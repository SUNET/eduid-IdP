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
import base64
import cherrypy

from urlparse import parse_qs

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


def static_file(environ, start_response, filename):
    types = {'ico': 'image/x-icon',
             'png': 'image/png',
             'html': 'text/html',
             'css': 'text/css',
             'js': 'application/javascript',
             'txt': 'text/plain',
             'xml': 'text/xml',
    }
    ext = filename.rsplit('.', 1)[-1]

    if not ext in types:
        raise eduid_idp.error.NotFound()

    try:
        text = open(filename).read()
    except IOError:
        raise eduid_idp.error.NotFound()

    start_response('200 Ok', [('Content-Type', types[ext])])
    return [text]


# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def read_cookie(logger):
    """
    Decode information stored in a browser cookie.

    The idpauthn cookie holds a value used to lookup `userdata' in IDP.cache.

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
