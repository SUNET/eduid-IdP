#!/usr/bin/env python
#
# Copyright (c) 2013 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
eduID IdP application


General user<->IdP interaction flow :


  1) User visits protected page at SP, which redirects user to
     URL /sso/redirect?SAMLRequest=base64-AuthnRequest

  2) URL /sso/redirect is handled by SSO.redirect()

     SSO.redirect() creates SHA-1 of SAML AuthnRequest and uses this as key to store
     some info in a cache called IDP.ticket. The information stored includes all the
     URI parameters.

     The key is passed to the login form HTML template as {{key}}.

     A reference to the authn context is generated (by pysaml2 authn_context code)
     and passed to the template as {{authn_reference}}.

     The current URL is included in the HTML form as {{redirect_uri}}.

  3) User fills out login form an POSTs it to URL /verify

  4) URL /verify is handled by do_verify()

     do_verify() tries to authenticate user based on filled out HTML form contents.

     If successful, a random user identifier (UUID) is created and a mapping between
     the random uid and the real authenticated users username is stored in the
     IDP.cache.

     The random user identifier (UUID) is stored in a browser cookie called `idpauthn'.

     The user is HTTP redirected back to the URL of step 2 through the `redirect_uri'
     HTML parameter (included in the HTML form by step 2). The random user identifier
     is passed as URL parameter `id', and the `key' from step 2 is passed as URL
     parameter `key'.

  5) URL /sso/redirect (re-visited) is handled by SSO.redirect()

     Since the query string includes a `key' that can be used to look up info from
     IDP.ticket this time, processing is continued in SSO.do() (via SSO.operation()).
     The info in IDP.ticket is pruned first.

     SSO.do() gets the original URI parameters from step 2 that were stored in
     IDP.ticket, and rounds up identity information for the user.

     SSO.do() effectively uses IdPApplication.application() to determine which
     user is logged in. This will be either from the idpauthn cookie being set,
     and containing a random user identifier (UUID) that can be looked up in
     IDP.cache to get a real username, or from IDP.cache using the `id' URI
     parameter.

     An AuthnResponse is created using pysaml2 create_authn_response(), and this
     is where the `authn_reference' from step 2 seems to come into play. The authn
     reference is used to locate the correct authn instance (the same one used
     in step 2) with the AUTHN_BROKER.

"""

import os
import sys
import time
import pprint
import logging
import argparse
import threading

import cherrypy

import eduid_idp
from eduid_idp.login import SSO
from eduid_idp.logout import SLO

from saml2 import server

try:
    import raven
    raven_imported = True
except ImportError:
    raven = None

default_config_file = "/opt/eduid/IdP/conf/idp.ini"
default_debug = False


def parse_args():
    """
    Parse the command line arguments
    """
    parser = argparse.ArgumentParser(description = "eduID Identity Provider application",
                                     add_help = True,
                                     formatter_class = argparse.ArgumentDefaultsHelpFormatter,
                                     )
    parser.add_argument('-c', '--config-file',
                        dest = 'config_file',
                        default = default_config_file,
                        help = 'Config file',
                        metavar = 'PATH',
                        )

    parser.add_argument('--debug',
                        dest = 'debug',
                        action = 'store_true', default = default_debug,
                        help = 'Enable debug operation',
                        )

    return parser.parse_args()


# -----------------------------------------------------------------------------


class IdPApplication(object):
    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.response_status = None
        self.start_response = None

        old_path = sys.path
        cfgdir = os.path.dirname(config.pysaml2_config)
        cfgfile = config.pysaml2_config
        if cfgdir:
            # add directory part to sys.path, since pysaml2 'import's it's config
            sys.path = [cfgdir] + sys.path
            cfgfile = os.path.basename(config.pysaml2_config)
        _session_ttl = (self.config.sso_session_lifetime + 1) * 60
        if self.config.sso_session_mongo_uri:
            _SSOSessions = eduid_idp.cache.SSOSessionCacheMDB(self.config.sso_session_mongo_uri,
                                                              logger, _session_ttl)
        else:
            _SSOSessions = eduid_idp.cache.SSOSessionCacheMem(logger, _session_ttl, threading.Lock())
        self.IDP = server.Server(cfgfile, cache = _SSOSessions)
        # restore path
        sys.path = old_path
        self.IDP.ticket = eduid_idp.login.SSOLoginDataCache(self.IDP, 'TicketCache', logger, 5 * 60, threading.Lock())

        _my_id = self.IDP.config.entityid
        self.AUTHN_BROKER = eduid_idp.assurance.init_AuthnBroker(_my_id)
        self.userdb = eduid_idp.idp_user.IdPUserDb(logger, config)

        cherrypy.config.update({'request.error_response': self.handle_error,
                                'error_page.default': self.error_page_default,
                                })

    @cherrypy.expose
    def sso(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- SSO ---")
        path = cherrypy.request.path_info.lstrip('/').split('/')
        self.logger.info("<application> PATH: %s" % path)

        environ = self._request_environment()

        if path[1] == 'post':
            return SSO(environ, self._my_start_response, self).post()
        if path[1] == 'redirect':
            return SSO(environ, self._my_start_response, self).redirect()
        if path[1] == 'art':
            # seldomly used, but part of standard
            return SSO(environ, self._my_start_response, self).artifact()

        raise eduid_idp.error.NotFound(logger = self.logger)

    @cherrypy.expose
    def slo(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- SLO ---")
        path = cherrypy.request.path_info.lstrip('/').split('/')
        self.logger.info("<application> PATH: %s" % path)

        environ = self._request_environment()

        if path[1] == 'post':
            return SLO(environ, self._my_start_response, self).post()
        if path[1] == 'redirect':
            return SLO(environ, self._my_start_response, self).redirect()
        if path[1] == 'soap':
            # SOAP is commonly used for SLO
            return SLO(environ, self._my_start_response, self).soap()

        raise eduid_idp.error.NotFound(logger = self.logger)

    @cherrypy.expose
    def verify(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- Verify ---")
        assert not (self._lookup_userdata())  # just to verify when refactoring
        environ = {}
        return eduid_idp.login.do_verify(environ, self._my_start_response, self)

    @cherrypy.expose
    def static(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- Static file ---")
        path = cherrypy.request.path_info.lstrip('/')
        self.logger.info("<application> PATH: %s" % path)

        static_fn = eduid_idp.mischttp.static_filename(self.config, path)
        if static_fn:
            self.logger.debug("Serving static file {!r}".format(static_fn))
            return eduid_idp.mischttp.static_file(self._my_start_response, static_fn)

        raise eduid_idp.error.NotFound(logger = self.logger)

    def _my_start_response(self, status, headers):
        """
        The IdP used to be a WSGI application, and this function is a remaining trace of that.
        """
        self.logger.debug("Initiating HTTP response {!r}, headers {!s}".format(status, pprint.pformat(headers)))
        if hasattr(cherrypy.response, 'idp_response_status') and cherrypy.response.idp_response_status:
            self.logger.warning("start_response called twice (now {!r}, previous {!r})".format(
                status, cherrypy.response.idp_response_status))
        cherrypy.response.idp_response_status = status
        cherrypy.response.status = status
        for (k, v) in headers:
            cherrypy.response.headers[k] = v

    def _request_environment(self):
        """
        Initialize well-known environment for this request.

        :returns: environ dict()
        """
        environ = {'idp.user': None,
                   }
        userdata = self._lookup_userdata()
        if userdata:
            environ['idp.user'] = self.userdb.lookup_user(userdata['username'])
            environ['idp.authn'] = self.get_authn_by_ref(userdata['authn_ref'], userdata.get('authn_class_ref'))
            self.logger.info("SSO session for user {!r} found in IdP cache".format(userdata['username']))
            if environ['idp.authn'] is None:
                # This could happen with SSO sessions refering to old authns during
                # reconfiguration of authns in the AUTHN_BROKER.
                # XXX remove SSO session?
                raise eduid_idp.error.ServiceError(logger=self.logger)
        return environ

    def _lookup_userdata(self):
        userdata = None
        _session_id = eduid_idp.mischttp.read_cookie(self.logger)
        if _session_id:
            userdata = self.IDP.cache.get_session(_session_id)
            self.logger.debug("Looked up SSO session using idpauthn cookie :\n{!s}".format(
                pprint.pformat(userdata)))
        else:
            query = eduid_idp.mischttp.parse_query_string()
            if query:
                self.logger.debug("Parsed query string :\n{!s}".format(pprint.pformat(query)))
                try:
                    userdata = self.IDP.cache.get_session(query['id'])
                    self.logger.debug("Looked up SSO session using query 'id' parameter :\n{!s}".format(
                        pprint.pformat(userdata)))
                except KeyError:
                    # no 'id', or not found in cache
                    pass
        if userdata:
            _age = (int(time.time()) - userdata['authn_timestamp']) / 60
            if _age > self.config.sso_session_lifetime:
                self.logger.info("SSO session expired (age {!r} minutes > {!r})".format(
                    _age, self.config.sso_session_lifetime))
                return None
            self.logger.debug("SSO session is still valid (age {!r} minutes <= {!r})".format(
                _age, self.config.sso_session_lifetime))
        else:
            self.logger.debug("SSO session not found using 'id' parameter or 'idpauthn' cookie")
        return userdata

    def get_authn_by_ref(self, ref, class_ref=None):
        """
        Look up an authentication context by reference.
        :param ref: object
        :param class_ref: Authn class ref as string
        :return: authn context or None
        """
        try:
            _authn = self.AUTHN_BROKER[ref]
            if class_ref is not None:
                if _authn['class_ref'] != class_ref:
                    self.logger.warning("AuthN context returned for ref {!r} class_ref mismatch".format(ref))
                    self.logger.debug("Got AuthN context class_ref {!r}, expected {!r}".format(
                        _authn['class_ref'], class_ref))
            return _authn
        except KeyError:
            self.logger.warning("No AuthN context found using ref {!r}".format(ref))

    def handle_error(self):
        """
        Function called by CherryPy when there is an unhandled exception processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.
        """
        cherrypy.response.status = 500
        cherrypy.response.body = self._render_error_page(500, 'Server Internal Error')

    def error_page_default(self, status, message, traceback, version):
        """
        Function called by CherryPy when there is an unhandled exception processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.

        :param status: integer, HTML error code
        :param message: string, HTML error message
        :param traceback: traceback of error
        :param version: cherrypy version
        """
        path = cherrypy.request.path_info.lstrip('/')
        self.logger.debug("FAIL ({!r}) PATH : {!r}".format(status, path))
        return self._render_error_page(status, message, traceback)

    def _render_error_page(self, status, reason, traceback=None):
        # Look for error page in user preferred language
        res = eduid_idp.mischttp.localized_resource(
            self._my_start_response, 'error.html', self.config, logger=self.logger, status=status)
        if not res:
            # default error message
            res = "<html><body>Sorry, an error occured.<p>{status} {reason}</body></html>".format(
                status=status, reason=reason)

        status_code = 'unknown'
        try:
            status_code = int(status.split()[0])
        except (ValueError, AttributeError, IndexError):
            pass

        # apply simplistic HTML formatting to template in 'res'
        argv = {
            'error_status': status,
            'error_code': status_code,
            'error_reason': reason,
            'error_traceback': str(traceback),
        }
        res = res.format(**argv)

        if not status.startswith("404 "):
            self.logger.error("Error in IdP application",
                              exc_info = 1, extra={'stack': True,
                                                   'request': cherrypy.request,
                                                   'traceback': traceback,
                                                   'status': status,
                                                   'reason': reason,
                                                   })
        return res


# ----------------------------------------------------------------------------


def main(myname = 'eduid.saml2.idp', args = None, logger = None):
    """
    Initialize everything and start the IdP application.
    """
    if not args:
        args = parse_args()

    # initialize various components
    if not logger:
        logger = logging.getLogger(myname)
    config = eduid_idp.config.IdPConfig(args.config_file, args.debug)
    if config.debug:
        logger.setLevel(logging.DEBUG)
        # log to stderr when debugging
        formatter = logging.Formatter('%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
        stream_h = logging.StreamHandler(sys.stderr)
        stream_h.setFormatter(formatter)
        logger.addHandler(stream_h)
    if config.logfile:
        formatter = logging.Formatter('%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
        file_h = logging.FileHandler(config.logfile)
        file_h.setFormatter(formatter)
        logger.addHandler(file_h)
    if config.syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)
    if config.raven_dsn:
        if raven:
            from raven.handlers.logging import SentryHandler
            logger.debug("Setting up Raven exception logging")
            client = raven.Client(config.raven_dsn, timeout=10)
            handler = SentryHandler(client, level=logging.ERROR)
            logger.addHandler(handler)
        else:
            logger.warning("Config option raven_dsn set, but raven not available")

    cherry_conf = {'server.thread_pool': config.num_threads,
                   'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
                   'request.show_tracebacks': config.debug,
                   }
    if config.server_cert and config.server_key:
        _ssl_opts = {'server.ssl_module': config.ssl_adapter,
                     'server.ssl_certificate': config.server_cert,
                     'server.ssl_private_key': config.server_key,
                     #'server.ssl_certificate_chain':
                     }
        cherry_conf.update(_ssl_opts)

    if config.logdir:
        cherry_conf['log.access_file'] = os.path.join(config.logdir, 'access.log')
        cherry_conf['log.error_file'] = os.path.join(config.logdir, 'error.log')
    else:
        sys.stderr.write("NOTE: Config option 'logdir' not set.\n")
        cherry_conf['log.screen'] = True

    cherrypy.config.update(cherry_conf)

    cherrypy.quickstart(IdPApplication(logger, config))


if __name__ == '__main__':
    try:
        progname = os.path.basename(sys.argv[0])
        if main(progname):
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
