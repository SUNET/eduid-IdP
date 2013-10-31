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
import base64
import pprint
import cherrypy
import pkg_resources

from urlparse import parse_qs

import eduid_idp

from saml2 import BINDING_HTTP_ARTIFACT
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
    :rtype: string
    """
    if binding == BINDING_HTTP_ARTIFACT or binding == BINDING_HTTP_REDIRECT:
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
    return message


def geturl(query = True, path = True):
    """Rebuilds a request URL (from PEP 333).

    :param query: Is QUERY_STRING included in URI (default: True)
    :param path: Is path included in URI (default: True)
    """
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


def get_post():
    """
    Return the parsed query string equivalent from a HTML POST request.

    When the method is POST the query string will be sent in the HTTP request body.

    :return: query string

    :rtype: dict
    """
    return cherrypy.request.body_params


def static_filename(config, path):
    """
    Check if there is a static file matching 'path'.

    :param config: IdP config
    :param path: URL part to check
    :return: False, None or filename as string

    :type config: config.IdPConfig
    :type path: string
    :rtype: False | None | string
    """
    if not isinstance(path, basestring):
        return False
    if not config.static_dir:
        return False
    try:
        filename = os.path.join(config.static_dir, path)
        os.stat(filename)
        return filename
    except OSError:
        return None


def static_file(start_response, filename, fp=None, status=None):
    """
    Serve a static file, 'known' to exist.

    :param start_response: WSGI-like start_response function
    :param filename: OS path to the files whose content should be served
    :param fp: optional file-like object implementing read()
    :param status: optional HTML result data ('404 Not Found' for example)
    :return: file content

    :type start_response: function
    :type filename: string
    :type fp: File
    :type status: string
    :rtype: string
    """
    content_type = get_content_type(filename)
    if not content_type:
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
        try:
            cookie_val = base64.b64decode(_authn.value)
            logger.debug("idpauthn cookie value={!r}".format(cookie_val))
            return cookie_val
        except KeyError:
            return None
    else:
        logger.debug("No idpauthn cookie")
    return None


def delete_cookie(name, logger):
    """
    Ask browser to delete a cookie.

    :param name: cookie name as string
    :param logger: logging logger
    :return: True on success

    :type name: string
    :type logger: logging.Logger
    :rtype: bool
    """
    logger.debug("Delete cookie: {!s}".format(name))
    return set_cookie(name, 0, '/', logger)


def set_cookie(name, expire, path, logger, value=''):
    """
    Ask browser to store a cookie.

    Since eduID.se is HTTPS only, the cookie parameter `Secure' is set.

    :param name: Cookie identifier (string)
    :param expire: Number of minutes before this cookie goes stale
    :param path: The path specification for the cookie
    :param logger: logging instance
    :param value: The value to assign to the cookie

    :return: True on success

    :type name: string
    :type expire: int
    :type path: string
    :type logger: logging.Logger
    :type value: string
    :rtype: bool
    """
    cookie = cherrypy.response.cookie
    cookie[name] = base64.b64encode(str(value))
    cookie[name]['path'] = path
    cookie[name]['max-age'] = expire * 60
    cookie[name]['secure'] = True  # ask browser to only send cookie using SSL/TLS

    logger.debug("Set cookie (expires {!r} minutes) : {!s}".format(expire, cookie))
    return True


def parse_query_string():
    """
    Parse HTML request query string into a dict like

    {'Accept': string,
     'Host': string,
    }

    NOTE: Only the first header value for each header is included in the result.

    :return: parsed query string

    :rtype: dict
    """
    query = None
    if cherrypy.request.query_string:
        _qs = cherrypy.request.query_string
        query = dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
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
    :type config: config.IdPConfig
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

    if languages:
        for (lang, q_val) in languages[:50]:  # cap somewhere to prevent DoS
            if _LANGUAGE_RE.match(lang):
                for (package, path) in config.content_packages:
                    langfile = path + '/' + lang.lower() + '/' + filename  # pkg_resources paths do not use os.path.join
                    if logger:
                        logger.debug('Looking for package {!r}, language {!r}, path: {!r}'.format(
                            package, lang, langfile))
                    try:
                        res = pkg_resources.resource_stream(package, langfile)
                        return eduid_idp.mischttp.static_file(start_response, langfile, fp=res, status=status)
                    except IOError:
                        pass

    # default language file
    static_fn = eduid_idp.mischttp.static_filename(config, filename)
    return eduid_idp.mischttp.static_file(start_response, static_fn, status=status)


def get_http_method():
    """
    Get the HTTP method verb for this request.

    This function keeps other modules from having to know that CherryPy is used.

    :return: 'GET', 'POST' or other
    :rtype: string
    """
    return cherrypy.request.method
