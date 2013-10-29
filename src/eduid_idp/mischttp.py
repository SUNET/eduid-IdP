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
import cherrypy

from urlparse import parse_qs
import pkg_resources

import eduid_idp


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'

    def __init__(self, message = None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)
        self.template = kwargs.get('template', self._template)

        self.message = message

        self.headers = kwargs.get('headers', [])
        _content_type = kwargs.get('content', self._content_type)
        headers_lc = [x[0].lower() for x in self.headers]
        if 'content-type' not in headers_lc:
            self.headers.append(('Content-Type', _content_type))

    def __call__(self, environ, start_response):
        start_response(self.status, self.headers)
        return self.response(self.message or geturl())

    def _response(self, message = ""):
        if self.template:
            return [self.template % message]
        elif isinstance(message, basestring):
            return [message]
        return message


class Redirect(cherrypy.HTTPRedirect):
    """
    Class 'copy' just to avoid having references to CherryPy in other modules.
    """
    pass


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
    # When the method is POST the query string will be sent
    # in the HTTP request body
    return cherrypy.request.body_params


def static_filename(config, path):
    """
    Check if there is a static file matching 'path'.

    :param config: IdP config instance
    :param path: string, URL part to check
    :return: False, None or filename as string
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
    :param status: string, optional HTML result data ('404 Not Found' for example)
    :return: string with file content
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
    """
    cookie = cherrypy.request.cookie
    logger.debug("Parsing cookie(s): {!s}".format(cookie))
    _authn = cookie.get("idpauthn")
    if _authn:
        try:
            cookie_val = base64.b64decode(_authn.value)
            logger.debug("idpauthn cookie value={!r}".format(cookie_val))
            return cookie_val  # XXX should maybe split on ':' to be consistent with set_cookie
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
    """
    logger.debug("Delete cookie: {!s}".format(name))
    return set_cookie(name, 0, '/', logger)


def set_cookie(name, expire, path, logger, *args):
    """
    Ask browser to store a cookie.

    Since eduID.se is HTTPS only, the cookie parameter `Secure' is set.

    :param name: Cookie identifier (string)
    :param expire: Number of minutes before this cookie goes stale
    :param path: The path specification for the cookie
    :param logger: logging instance
    :return: True on success
    """
    cookie = cherrypy.response.cookie
    cookie[name] = base64.b64encode(":".join(args))
    cookie[name]['path'] = path
    cookie[name]['max-age'] = expire * 60
    cookie[name]['secure'] = True  # ask browser to only send cookie using SSL/TLS

    logger.debug("Set cookie (expires {!r} minutes) : {!s}".format(expire, cookie))
    return True


def parse_query_string():
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
    :param lang_string: string
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
    """
    _LANGUAGE_RE = re.compile(
            r'''
            ([A-Za-z]{1,8}(?:-[A-Za-z0-9]{1,8})*|)      # "en", "en-au", "x-y-z", "es-419", NOT the "*"
            ''', re.VERBOSE)

    # Look for some static page in user preferred language
    languages = eduid_idp.mischttp.parse_accept_lang_header(cherrypy.request.headers['Accept-Language'])
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
    static_fn = eduid_idp.mischttp.static_filename(config, path)
    return eduid_idp.mischttp.static_file(start_response, static_fn, status=status)
