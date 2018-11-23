#
# Copyright (c) 2013 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Miscellaneous HTTP related functions.
"""

import os
import re
import six
import base64
import pprint
import cherrypy
import pkg_resources

from six import string_types
from  six.moves.urllib.parse import parse_qs

import eduid_idp
from eduid_idp.util import b64encode
from eduid_idp.error import BadRequest
from eduid_common.api.sanitation import Sanitizer, SanitationProblem

from saml2 import BINDING_HTTP_REDIRECT


class Redirect(cherrypy.HTTPRedirect):
    """
    Class 'copy' just to avoid having references to CherryPy in other modules.
    """
    pass


def create_html_response(binding, http_args, start_response, logger):
    """
    Create a HTML response based on parameters compiled by pysaml2 functions
    like apply_binding().

    :param binding: SAML binding
    :param http_args: response data
    :param start_response: WSGI-like start_response function
    :param logger: logging logger

    :return: HTML response

    :type binding: string
    :type http_args: dict
    :type start_response: function
    :type logger: logging.Logger
    :rtype: bytes
    """
    if binding == BINDING_HTTP_REDIRECT:
        # XXX This URL extraction code is untested in practice, but it appears
        # the should be HTTP headers in http_args['headers']
        urls = [v for (k, v) in http_args['headers'] if k == 'Location']
        logger.debug('Binding {!r} redirecting to {!r}'.format(binding, urls))
        if 'url' in http_args:
            del http_args['headers']  # less debug log below
            logger.debug('XXX there is also a "url" in http_args :\n{!s}'.format(pprint.pformat(http_args)))
            if not urls:
                urls = [http_args.get('url')]
        raise cherrypy.HTTPRedirect(urls)

    # Parse the parts of http_args we know how to parse, and then warn about any remains.
    message = http_args.pop('data')
    status = http_args.pop('status', '200 Ok')
    headers = http_args.pop('headers', [])
    headers_lc = [x[0].lower() for x in headers]
    if 'content-type' not in headers_lc:
        _content_type = http_args.pop('content', 'text/html')
        headers.append(('Content-Type', _content_type))

    if http_args != {}:
        logger.debug('Unknown HTTP args when creating {!r} response :\n{!s}'.format(
            status, pprint.pformat(http_args)))

    start_response(status, headers)
    if not isinstance(message, six.binary_type):
        message = message.encode('utf-8')
    return message


def geturl(config, query = True, path = True):
    """Rebuilds a request URL (from PEP 333).

    :param config: IdP config
    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)

    :type config: eduid_idp.config.IdPConfig
    """
    url = [config.base_url]
    if not url[0]:
        # For some reason, cherrypy.request.base always have host 127.0.0.1 -
        # work around that with much more elaborate code, based on pysaml2.
        #return cherrypy.request.base + cherrypy.request.path_info
        url = [cherrypy.request.scheme, '://',
               cherrypy.request.headers['Host'], ':',
               str(cherrypy.request.local.port), '/']
    if path:
        url.append(cherrypy.request.path_info.lstrip('/'))
    if query:
        url.append('?' + cherrypy.request.query_string)
    return ''.join(url)


def get_post(logger):
    """
    Return the parsed query string equivalent from a HTML POST request.

    When the method is POST the query string will be sent in the HTTP request body.

    :param logger: A logger object

    :return: query string

    :type logger: logging.Logger
    :rtype: dict
    """
    body_params = cherrypy.request.body_params
    query = dict()
    san = Sanitizer()
    for k, v in body_params.items():
        try:
            safe_k = san.sanitize_input(k, logger=logger,
                                        content_type='text/plain')
            if safe_k != k:
                raise BadRequest()
            safe_v = san.sanitize_input(v, logger=logger,
                                        content_type='text/plain')
        except SanitationProblem as sp:
            logger.info("There was a problem sanitizing inputs: {!r}".format(sp))
            raise BadRequest()
        query[safe_k] = safe_v
    return query


def get_request_header():
    """
    Return the HTML request headers..

    :return: headers

    :rtype: dict
    """
    return cherrypy.request.headers


def get_request_body():
    """
    Return the request body from a HTML POST request.

    :return: raw body

    :rtype: string
    """
    length = cherrypy.request.headers.get('Content-Length', 0)
    if not length:
        # CherryPy 3.2.4 seems to not like length 0 in the read() below
        return ''
    raw_body = cherrypy.request.body.read(int(length))
    return raw_body


def static_filename(config, path, logger):
    """
    Check if there is a static file matching 'path'.

    :param config: IdP config
    :param path: URL part to check
    :param logger: Logging logger
    :return: False, None or filename as string

    :type config: eduid_idp.config.IdPConfig
    :type path: string
    :rtype: False | None | string
    """
    if not isinstance(path, string_types):
        return False
    if not config.static_dir:
        return False
    if '..' in str(path):
        logger.warning("Attempted directory traversal: \'{}\'".format(path))
        return False
    try:
        filename = os.path.join(config.static_dir, path)
        os.stat(filename)
        return filename
    except OSError:
        return None


def static_file(start_response, filename, logger, fp=None, status=None):
    """
    Serve a static file, 'known' to exist.

    :param start_response: WSGI-like start_response function
    :param filename: OS path to the files whose content should be served
    :param logger: Logging logger
    :param fp: optional file-like object implementing read()
    :param status: optional HTML result data ('404 Not Found' for example)
    :return: file content

    :type start_response: function
    :type filename: string
    :type logger: logging.Logger
    :type fp: File
    :type status: string
    :rtype: string
    """
    content_type = get_content_type(filename)
    if not content_type:
        logger.error("Could not determine content type for static file {!r}".format(filename))
        raise eduid_idp.error.NotFound()

    if not status:
        status = '200 Ok'

    try:
        if not fp:
            fp = open(filename)
        text = fp.read()
    except IOError:
        raise eduid_idp.error.NotFound()
    finally:
        fp.close()

    logger.debug("Serving {!s}, status={!r} content-type {!s}, length={!r}".format(
        filename, status, content_type, len(text)))

    start_response(status, [('Content-Type', content_type)])
    return text


def get_content_type(filename):
    """
    Figure out the content type to use from a filename.

    :param filename: string
    :return: string like 'text/html'

    :type filename: string
    :rtype: string
    """
    types = {'ico': 'image/x-icon',
             'png': 'image/png',
             'html': 'text/html',
             'css': 'text/css',
             'js': 'application/javascript',
             'txt': 'text/plain',
             'xml': 'text/xml',
             'svg': 'image/svg+xml',
             'woff': 'application/font-woff',
             'eot': 'application/vnd.ms-fontobject',
             'ttf': 'application/x-font-ttf',
             }
    ext = filename.rsplit('.', 1)[-1]
    if ext not in types:
        return None
    return types[ext]


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def read_cookie(logger):
    """
    Decode information stored in a browser cookie.

    The idpauthn cookie holds a value used to lookup `userdata' in IDP.cache.

    :param logger: logging logger
    :returns: string with cookie content, or None

    :type logger: logging.Logger
    :rtype: string | None
    """
    cookie = cherrypy.request.cookie
    logger.debug("Parsing cookie(s): {!s}".format(cookie))
    _authn = cookie.get("idpauthn")
    if _authn:
        import binascii
        try:
            cookie_val = base64.b64decode(_authn.value)
            logger.debug("idpauthn cookie value={!r}".format(cookie_val))
            return cookie_val
        except binascii.Error:
            logger.debug('Invalid idpauthn value: {!r}'.format(_authn.value))
            raise
        except KeyError:
            return None
    else:
        logger.debug("No idpauthn cookie")
    return None


def delete_cookie(name, logger, config):
    """
    Ask browser to delete a cookie.

    :param name: cookie name as string
    :param logger: logging instance
    :param config: IdPConfig instance
    :return: True on success

    :type name: string
    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    :rtype: bool
    """
    logger.debug("Delete cookie: {!s}".format(name))
    return set_cookie(name, '/', logger, config)


def set_cookie(name, path, logger, config, value=''):
    """
    Ask browser to store a cookie.

    Since eduID.se is HTTPS only, the cookie parameter `Secure' is set.

    :param name: Cookie identifier (string)
    :param path: The path specification for the cookie
    :param logger: logging instance
    :param config: IdPConfig instance
    :param value: The value to assign to the cookie

    :return: True on success

    :type name: string
    :type path: string
    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    :type value: string
    :rtype: bool
    """
    if six.PY3 and type(value) == bytes:
        value = value.decode('utf-8')
    cookie = cherrypy.response.cookie
    cookie[name] = b64encode(value)
    cookie[name]['path'] = path
    if not config.insecure_cookies:
        cookie[name]['secure'] = True  # ask browser to only send cookie using SSL/TLS
    cookie[name]['httponly'] = True # protect against common XSS vulnerabilities
    logger.debug("Set cookie : {!s}".format(cookie))
    return True


def parse_query_string(logger):
    """
    Parse HTML request query string into a dict like

    {'Accept': string,
     'Host': string,
    }

    NOTE: Only the first header value for each header is included in the result.

    :param logger: A logger object

    :return: parsed query string

    :type logger: logging.Logger
    :rtype: dict
    """
    query = None
    if cherrypy.request.query_string:
        _qs = cherrypy.request.query_string
        query = dict()
        san = Sanitizer()
        for k, v in parse_qs(_qs).items():
            try:
                safe_k = san.sanitize_input(k, logger=logger,
                                            content_type='text/plain')
                if safe_k != k:
                    raise BadRequest()
                safe_v = san.sanitize_input(v[0], logger=logger,
                                            content_type='text/plain')
            except SanitationProblem as sp:
                logger.info("There was a problem sanitizing inputs: {!r}".format(sp))
                raise BadRequest()
            query[safe_k] = safe_v
    return query


def parse_accept_lang_header(lang_string):
    """
    Parses the lang_string, which is the body of an HTTP Accept-Language
    header, and returns a list of (lang, q-value), ordered by 'q' values.

    Any format errors in lang_string results in an empty list being returned.

    :param lang_string: Accept-Language header

    :type lang_string: string
    :rtype: list[(string, string)]
    """
    return eduid_idp.thirdparty.parse_accept_lang_header(lang_string)


def get_default_template_arguments(config):
    """
    :param config: IdP config
    :type config: IdPConfig
    :return: header links
    :rtype: dict
    """
    return {
        'dashboard_link': config.dashboard_link,
        'signup_link': config.signup_link,
        'student_link': config.student_link,
        'technicians_link': config.technicians_link,
        'staff_link': config.staff_link,
        'faq_link': config.faq_link,
        'password_reset_link': config.password_reset_link,
        'static_link': config.static_link,
    }


def localized_resource(start_response, filename, config, logger=None, status=None):
    """
    Locate a static page in the users preferred language. Such pages are
    packaged in separate Python packages that allow access through
    pkg_resource.

    :param start_response: WSGI-like start_response function
    :param filename: string, name of resource
    :param config: IdP config instance
    :param logger: optional logging logger, for debug log messages
    :param status: string, optional HTML result data ('404 Not Found' for example)
    :return: HTML response data

    :type start_response: function
    :type filename: string
    :type config: eduid_idp.config.IdPConfig
    :type logger: logging.Logger
    :type status: string
    :rtype: string
    """
    _LANGUAGE_RE = re.compile(
            r'''
            ([A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*|)      # "en", "en-au", "x-y-z", "es-419", NOT the "*"
            ''', re.VERBOSE)

    # Look for some static page in user preferred language
    languages = eduid_idp.mischttp.parse_accept_lang_header(cherrypy.request.headers.get('Accept-Language', ''))
    if logger:
        logger.debug("Client language preferences: {!r}".format(languages))
    languages = [lang for (lang, q_val) in languages[:50]]  # cap somewhere to prevent DoS
    if not config.default_language in languages and config.default_language:
        languages.append(config.default_language)

    if languages:
        logger.debug("Languages list : {!r}".format(languages))
        for lang in languages:
            if _LANGUAGE_RE.match(lang):
                for (package, path) in config.content_packages:
                    langfile = path + '/' + lang.lower() + '/' + filename  # pkg_resources paths do not use os.path.join
                    if logger:
                        logger.debug('Looking for package {!r}, language {!r}, path: {!r}'.format(
                            package, lang, langfile))
                    try:
                        _res = pkg_resources.resource_stream(package, langfile)
                        res = eduid_idp.mischttp.static_file(start_response, langfile, logger, fp=_res, status=status)
                        if six.PY2:
                            return res
                        return res.decode('UTF-8')
                    except IOError:
                        pass

    # default language file
    static_fn = eduid_idp.mischttp.static_filename(config, filename, logger)
    logger.debug("Looking for {!r} at default location (static_dir {!r}): {!r}".format(
        filename, config.static_dir, static_fn))
    if not static_fn:
        logger.warning("Failed locating page {!r} in an accepted language or the default location".format(filename))
        return None
    logger.debug('Using default file for {!r}: {!r}'.format(filename, static_fn))
    res = eduid_idp.mischttp.static_file(start_response, static_fn, logger, status=status)
    if six.PY2:
        return res
    return res.decode('UTF-8')


def get_http_method():
    """
    Get the HTTP method verb for this request.

    This function keeps other modules from having to know that CherryPy is used.

    :return: 'GET', 'POST' or other
    :rtype: string
    """
    return cherrypy.request.method


def get_remote_ip():
    """
    Get the remote IP address for this request.

    This function keeps other modules from having to know that CherryPy is used.

    :return: Client IP address
    :rtype: string
    """
    return cherrypy.request.remote.ip
