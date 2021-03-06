#
# Copyright (c) 2013, 2014 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import inspect

import cherrypy


class HTTPError(cherrypy.HTTPError):
    def __init__(self, status=500, message=None, logger=None, extra=None):
        if logger:
            caller = None
            try:
                stack = inspect.stack()
                caller = stack[1][1:]
                if caller[2] == '__init__':
                    # Intermediate caller is one of the HTTPError subclasses __init__ method
                    caller = stack[2][1:]
            except ValueError:
                pass
            if extra is None:
                extra = {}
            if status not in [404, 429, 440]:
                logger.error("HTTP error {!s} {!s} (at {!r})".format(status, message, caller), extra=extra)
            else:
                logger.debug("HTTP error {!s} {!s} (at {!r})".format(status, message, caller), extra=extra)
        cherrypy.HTTPError.__init__(self, status, message)


class BadRequest(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=400, message=message, logger=logger, extra=extra)


class Unauthorized(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=401, message=message, logger=logger, extra=extra)


class Forbidden(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=403, message=message, logger=logger, extra=extra)


class NotFound(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=404, message=message, logger=logger, extra=extra)


class TooManyRequests(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=429, message=message, logger=logger, extra=extra)


class LoginTimeout(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=440, message=message, logger=logger, extra=extra)


class ServiceError(HTTPError):
    def __init__(self, message=None, logger=None, extra=None):
        HTTPError.__init__(self, status=500, message=message, logger=logger, extra=extra)
