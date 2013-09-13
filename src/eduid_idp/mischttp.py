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
import time
import base64
import cherrypy

from saml2 import time_util

from urlparse import parse_qs
from Cookie import SimpleCookie


class Response(object):
    _template = None
    _status = '200 OK'
    _content_type = 'text/html'

    def __init__(self, message=None, **kwargs):
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

    def _response(self, message=""):
        if self.template:
            return [self.template % message]
        elif isinstance(message, basestring):
            return [message]
        return message


class NotFound(Response):
    _status = '404 NOT FOUND'
    _template = "<html>The requested resource %s was not found on this server</html>"


class Redirect(Response):
    _template = '<html>\n<head><title>Redirecting to %s</title></head>\n' \
        '<body>\nYou are being redirected to <a href="%s">%s</a>\n' \
        '</body>\n</html>'
    _status = '302 Found'

    def __call__(self, environ, start_response, **kwargs):
        location = self.message
        self.headers.append(('location', location))
        start_response(self.status, self.headers)
        return self.response((location, location, location))


class Unauthorized(Response):
    _status = "401 Unauthorized"
    _template = "<html>%s</html>"


class BadRequest(Response):
    _status = "400 Bad Request"
    _template = "<html>%s</html>"


class ServiceError(Response):
    _status = '500 Internal Service Error'



def geturl(query=True, path=True):
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
        resp = NotFound()
        return resp(environ, start_response)

    try:
        text = open(filename).read()
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)

    start_response('200 Ok', [('Content-Type', types[ext])])
    return [text]


def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound()
    return resp(environ, start_response)



# ----------------------------------------------------------------------------
# Cookie handling
# ----------------------------------------------------------------------------
def info_from_cookie(kaka, IDP, logger):
    """
    Decode information stored in a browser cookie.

    The idpauthn cookie holds a value used to lookup `userdata' in IDP.cache.

    :returns: User data
    """
    logger.debug("Parsing cookie(s): %s" % kaka)
    _authn = kaka.get("idpauthn")
    if _authn:
        try:
            key = base64.b64decode(_authn.value)
            logger.debug("idpauthn cookie value={!r}".format(key))
            return IDP.cache.uid2user[key]
        except KeyError:
            return None
    else:
        logger.debug("No idpauthn cookie")
    return None


# XXX cherrypy offers some significantly simpler ways to set cookies using
# cherrypy.response.cookie - any reason to not use those? /Fredrik 2013-08

def _expiration(timeout, tformat="%a, %d-%b-%Y %H:%M:%S GMT"):
    """

    :param timeout:
    :param tformat:
    :return:
    """
    if timeout == "now":
        return time_util.instant(tformat)
    elif timeout == "dawn":
        return time.strftime(tformat, time.gmtime(0))
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=tformat)


def delete_cookie(name, logger):
    kaka = cherrypy.request.cookie
    logger.debug("delete KAKA: %s" % kaka)
    if kaka:
        cookie_obj = SimpleCookie(kaka)
        morsel = cookie_obj.get(name, None)
        cookie = SimpleCookie()
        cookie[name] = ""
        cookie[name]['path'] = "/"
        logger.debug("Expire: %s" % morsel)
        cookie[name]["expires"] = _expiration("dawn")
        return tuple(cookie.output().split(": ", 1))
    return None


def set_cookie(name, expire, path, logger, *args):
    """
    Create Cookies

    :param name: Cookie identifier (string)
    :param expire: Number of minutes before this cookie goes stale
    :param path: The path specification for the cookie
    :param logger: logging instance
    :return: A tuple to be added to headers
    """
    cookie = SimpleCookie()
    cookie[name] = base64.b64encode(":".join(args))
    if path:
        cookie[name]["path"] = path
    cookie[name]["expires"] = _expiration(expire)
    logger.debug("Cookie expires ({!r} minutes) : {!s}".format(expire, cookie[name]["expires"]))
    logger.debug("set KAKA: %s" % cookie)
    return tuple(cookie.output().split(": ", 1))


def parse_query_string():
    query = None
    if cherrypy.request.query_string:
        _qs = cherrypy.request.query_string
        query = dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
    return query
