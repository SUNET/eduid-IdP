#!/usr/bin/env python
#
# Copyright (c) 2013, 2014, 2017 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
eduID IdP application

Stored state :

  1) State regarding the SAMLRequest currently being processed is stored in
     eduid_idp.login.SSOLoginData() objects. These are by tradition called
     'tickets', and are currently stored in memory of the IdP instance
     processing a request.

  2) Single Sign On sessions are stored in eduid_idp.sso_session.SSOSession
     objects. A unique reference to the SSOSession is sent to the user in a
     browser cookie. The user will generally not have to authenticate again
     as long as the cookie is sent from the users browser and the SSOSession
     hasn't expired. These objects should be stored in MongoDB, accessible
     to all IdP instances in a cluster.


General non-authenticated user<->IdP interaction flow :

  1) User visits protected page at SP, which redirects user to
     URL /sso/redirect?SAMLRequest=base64-AuthnRequest

  2) URL /sso/redirect is handled by SSO.redirect()

     SSO.redirect() creates an SSOLoginData() object and stores it in the
     IDP.ticket cache. The information stored includes the parsed SAMLRequest
     and the RelayState, if any.

     No existing SSOSession() is found, so the user is required to authenticate.

     A unique reference to the SSOLoginData() is passed to the login form
     HTML template as {{key}}.

     A reference to the requested authn context is generated (by pysaml2
     authn_context code) and passed to the template as {{authn_reference}}.
     This is to allow the login.html page to render an appropriate form to
     authenticate the user commensurately.

     The URL of the redirection service is included in the HTML form as
     {{redirect_uri}}. XXX this should maybe go into the SSOLoginData instead.

     The place that will verify the submitted credentials (/verify) is
     communicated to the login-page as {{action}}.

  3) User fills out login form and POSTs it to URL {{action}} (/verify).

  4) {{action}} URL /verify is handled by do_verify()

     do_verify() tries to authenticate user based on filled out HTML form contents.

     If successful, an SSOSession() is created and stored in context.sso_sessions. This
     SSO session object contains information about what type of authentication
     was performed, the authn_instant (time of authentication) etc. and will later
     be used to automatically log the user in, as long as the SSO session hasn't
     expired, the SP doesn't require re-authentication (using SAML ForceAuthn),
     the SP doesn't require an incompatible AuthnContext etcetera.

     The ID (an UUID) of the SSO session is stored in a browser cookie called `idpauthn'.

     The user is HTTP redirected back to the URL of step 2 through the {{redirect_uri}}
     HTML parameter (included in the HTML form by step 2). The unique reference to the
     SSOLoginData() object is passed using the URL parameter `key', instead of passing
     the SAMLRequest URL parameter. This avoids having to parse the SAMLRequest again,
     and also provides the IdP with the possibility to store information about the
     'login event' somewhere where a malicious user cannot manipulate it.

  5) URL /sso/redirect (re-visited) is handled by SSO.redirect()

     The users browser this time presents an `idpauthn' cookie refering to an
     existing (and valid) SSOSession.

     If the `key' URL parameter is present, it is used to locate the SSOLoginData()
     object.

     If the SAML request includes a ForceAuthn request from the relying party (SP),
     the SSO session is ignored and step 2 above (more or less) is invoked instead.

     SSO().perform_login() is called to figure out what attributes to release to
     this relying party (SP), as well as what AuthnContext should be used based
     on what the SP requested, and the level of the authentiocation performed when
     the effective SSOSession() was created..

     At the end of perform_login(), the actual SAML assertion is created and put
     in a SAMLResponse.

     SSO.do() gets the original URI parameters from step 2 that were stored in
     IDP.ticket, and rounds up identity information for the user.


When the user proceeds to log in to other relying partys (SPs), the IdP will find
the SSO session using the `idpauthn' cookie sent by the users browser and only step
5 from above will be executed.
"""

import os
import sys
import time
import pprint
import logging
import argparse
import threading

import six
import cherrypy
import simplejson

import logging.handlers
from logging import Logger
from typing import Optional, Any

import eduid_idp
import eduid_idp.authn
import eduid_idp.sso_session
from eduid_idp.login import SSO
from eduid_idp.logout import SLO
from eduid_idp.config import IdPConfig
from eduid_idp.context import IdPContext
from eduid_idp.loginstate import SSOLoginDataCache
from eduid_idp.cache import ExpiringCacheCommonSession, SSOSessionCache, RedisEncryptedSession

from eduid_userdb.actions import ActionDB

from saml2 import server

from bson import ObjectId

# Load Raven (exception logging to Sentry), if available.
try:
    #noinspection PyPackageRequirements
    import raven
    #noinspection PyPackageRequirements
    from raven.handlers.logging import SentryHandler
except ImportError:
    raven = None
    SentryHandler = None


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
    """
    Main CherryPy application for the eduid IdP.

    Userdb can be passed as an argument to make testing easier.

    :param logger: logging logger
    :param config: IdP configuration data

    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    """

    def __init__(self, logger: Logger, config: IdPConfig, userdb: Optional[Any] = None):
        self.logger = logger
        self.config = config
        self.response_status = None
        self.start_response = None

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        self._init_pysaml2()

        _session_ttl = self.config.sso_session_lifetime * 60
        _SSOSessions: SSOSessionCache
        if self.config.sso_session_mongo_uri:
            _SSOSessions = eduid_idp.cache.SSOSessionCacheMDB(self.config.sso_session_mongo_uri,
                                                              self.logger, _session_ttl)
        else:
            _SSOSessions = eduid_idp.cache.SSOSessionCacheMem(self.logger, _session_ttl, threading.Lock())

        _login_state_ttl = (self.config.login_state_ttl + 1) * 60
        _ticket_sessions = SSOLoginDataCache('TicketCache', self.logger, _login_state_ttl,
                                      self.config, threading.Lock())
        self.authn_info_db = None
        _actions_db = None

        if config.mongo_uri:
            self.authn_info_db = eduid_idp.authn.AuthnInfoStoreMDB(config.mongo_uri, logger)

        if config.mongo_uri and config.actions_auth_shared_secret and config.actions_app_uri:
            _actions_db = ActionDB(config.mongo_uri)
            self.logger.info("configured to redirect users with pending actions")
        else:
            self.logger.debug("NOT configured to redirect users with pending actions")

        if userdb is None:
            userdb = eduid_idp.idp_user.IdPUserDb(logger, config)
        self.userdb = userdb
        self.authn = eduid_idp.authn.IdPAuthn(logger, config, self.userdb)

        cherrypy.config.update({'request.error_response': self.handle_error,
                                'error_page.default': self.error_page_default,
                                })
        listen_str = 'http://'
        if self.config.server_key:
            listen_str = 'https://'
        if ':' in self.config.listen_addr:  # IPv6
            listen_str += '[' + self.config.listen_addr + ']:' + str(self.config.listen_port)
        else:  # IPv4
            listen_str += self.config.listen_addr + ':' + str(self.config.listen_port)
        self.logger.info("eduid-IdP server started, listening on {!s}".format(listen_str))

        _common_sessions: Optional[ExpiringCacheCommonSession]
        if (config.redis_sentinel_hosts or config.redis_host) and config.shared_session_cookie_name \
                and config.shared_session_secret_key:
            _common_sessions = ExpiringCacheCommonSession('CommonSessions', logger,
                                                          config.shared_session_ttl, config,
                                                          secret=config.shared_session_secret_key)
        else:
            logger.info('eduID shared sessions not configured')
            _common_sessions = None

        self.context = IdPContext(config=self.config,
                                  idp=self.IDP,
                                  logger=self.logger,
                                  sso_sessions=_SSOSessions,
                                  ticket_sessions=_ticket_sessions,
                                  common_sessions=_common_sessions,
                                  actions_db=_actions_db,
                                  authn=self.authn,
                                  )

    def _init_pysaml2(self):
        """
        Initialization of PySAML2. Part of __init__().

        :return:
        """
        old_path = sys.path
        cfgfile = self.config.pysaml2_config
        cfgdir = os.path.dirname(cfgfile)
        if cfgdir:
            # add directory part to sys.path, since pysaml2 'import's it's config
            sys.path = [cfgdir] + sys.path
            cfgfile = os.path.basename(self.config.pysaml2_config)

        _path = sys.path[0]
        self.logger.debug("Loading PySAML2 server using cfgfile {!r} and path {!r}".format(cfgfile, _path))
        try:
            self.IDP = server.Server(cfgfile)
        finally:
            # restore path
            sys.path = old_path

    @cherrypy.expose
    def sso(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- SSO ---")
        path = cherrypy.request.path_info.lstrip('/').split('/')
        self.logger.debug("<application> PATH: %s" % path)

        sso_session = self._lookup_sso_session()
        session = self._lookup_common_session()

        if path[1] == 'post':
            return SSO(sso_session, session, self._my_start_response, self.context).post()
        if path[1] == 'redirect':
            return SSO(sso_session, session, self._my_start_response, self.context).redirect()

        raise eduid_idp.error.NotFound(logger = self.logger)

    @cherrypy.expose
    def slo(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- SLO ---")
        path = cherrypy.request.path_info.lstrip('/').split('/')
        self.logger.debug("<application> PATH: %s" % path)

        sso_session = self._lookup_sso_session()
        session = self._lookup_common_session()

        if path[1] == 'post':
            return SLO(sso_session, session, self._my_start_response, self.context).post()
        if path[1] == 'redirect':
            return SLO(sso_session, session, self._my_start_response, self.context).redirect()
        if path[1] == 'soap':
            # SOAP is commonly used for SLO
            return SLO(sso_session, session, self._my_start_response, self.context).soap()

        raise eduid_idp.error.NotFound(logger = self.logger)

    @cherrypy.expose
    def verify(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- Verify ---")
        if self._lookup_sso_session():
            # If an already logged in user presses 'back' or similar, we can't really expect to
            # manage to log them in again (think OTPs) and just continue 'back' to the SP.
            # However, with forceAuthn, this is exactly what happens so maybe it isn't really
            # an error case.
            #raise eduid_idp.error.LoginTimeout("Already logged in - can't verify credentials again",
            #                                   logger = self.logger)
            self.logger.debug("User is already logged in - verifying credentials again might not work")
        return eduid_idp.login.do_verify(self.context)

    @cherrypy.expose
    def static(self, *_args, **_kwargs):
        self.logger.debug("\n\n")
        self.logger.debug("--- Static file ---")
        path = cherrypy.request.path_info.lstrip('/')
        self.logger.debug("<application> PATH: %s" % path)

        static_fn = eduid_idp.mischttp.static_filename(self.config, path, self.logger)
        if static_fn:
            return eduid_idp.mischttp.static_file(self._my_start_response, static_fn, self.logger)

        raise eduid_idp.error.NotFound(logger = self.logger)

    @cherrypy.expose
    def status(self, request=None):
        """
        Check that the userdb and authentication backends are operational.

        :param request: The HTTP POST parameter `request'
        :return: HTML response with JSON data

        :rtype: string
        """
        self.logger.debug('Status request')

        try:
            parsed = simplejson.loads(request)
        except simplejson.JSONDecodeError:
            raise eduid_idp.error.BadRequest(logger = self.logger)

        if 'username' not in parsed or 'password' not in parsed:
            raise eduid_idp.error.BadRequest(logger = self.logger)

        if parsed['username'] not in self.config.status_test_usernames \
                and self.config.status_test_usernames != ['*']:
            self.logger.debug("Username {!r} in status request is not on the list "
                              "of permitted usernames : {!r}".format(parsed['username'],
                                                                     self.config.status_test_usernames))
            raise eduid_idp.error.Forbidden(logger = self.logger)

        response = {'status': 'FAIL'}

        authn = self.authn.password_authn(parsed)
        if authn:
            user = authn.user
            health = self._is_healthy()
            if health['status'] != 'STATUS_OK':
                response['reason'] = 'Health check failed: {}'.format(health.get('reason'))
            else:
                response = {'status': 'OK',
                            'testuser_name': user.display_name,
                            }

        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def healthy(self, request=None):
        """
        Check that the backend components we can test cheaply are available.

        :param request: The HTTP POST parameter `request'
        :return: HTML response with JSON data

        :rtype: string
        """
        self.logger.debug("Health check request")

        response = self._is_healthy()

        return "{}\n".format(simplejson.dumps(response))

    @cherrypy.expose
    def test500(self):
        """
        Show the same error page that will be shown on most server errors.
        For testing the error message.

        :raise AssertionError: always
        """
        self.logger.debug("Testing 500 Server Internal Error")
        raise AssertionError('Testing 500 Server Internal Error')

    def _is_healthy(self):
        res = {'status': 'STATUS_FAIL'}

        # Test mongodb
        cred_id = ObjectId(b'0000000000ab')
        previous = self.authn.authn_store.get_credential_last_used(cred_id)
        self.authn.authn_store.credential_success([cred_id])
        new = self.authn.authn_store.get_credential_last_used(cred_id)
        if not previous:
            self.logger.info('This seems to be the first MongoDB health-check...')
        elif new <= previous:
            self.logger.info('MongoDB not healthy: previous = {!r}, new = {!r}'.format(previous, new))
            res['reason'] = 'Failed writing to authninfo database (MongoDB)'
            return res
        res['mongodb_ts'] = new.isoformat()

        # Test Redis
        now = time.time()
        _session_id = self.context.sso_sessions.add_session('health_test', {'ts': now})
        fetched = self.context.sso_sessions.get_session(_session_id)
        self.context.sso_sessions.remove_session(_session_id)
        if not fetched:
            self.logger.info('This seems to be the first Redis health-check...')
        elif fetched['ts'] != now:
            self.logger.info('Redis not healthy: now = {!r}, fetched = {!r}'.format(previous, fetched))
            res['reason'] = 'Failed writing to session store (Redis)'
            return res
        res['redis_ts'] = time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(fetched['ts']))

        res['status'] = 'STATUS_OK'
        res['reason'] = 'Databases tested OK'
        return res

    def _my_start_response(self, status, headers):
        """
        The IdP used to be a WSGI application, and this function is a remaining trace of that.

        Headers are expected to be a list of (Name, Value) tuples, e.g. [('Content-Type', 'text/html')].

        :param status: HTML status code of response
        :param headers: HTML headers to add to the response

        :type status: int
        :type headers: list[(string, string)]
        """
        self.logger.debug("Initiating HTTP response {!r}, headers {!s}".format(status, pprint.pformat(headers)))
        if hasattr(cherrypy.response, 'idp_response_status') and cherrypy.response.idp_response_status:
            self.logger.warning("start_response called twice (now {!r}, previous {!r})".format(
                status, cherrypy.response.idp_response_status))
        cherrypy.response.idp_response_status = status
        cherrypy.response.status = status
        for (k, v) in headers:
            cherrypy.response.headers[k] = v

    def _lookup_sso_session(self):
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        :rtype: SSOSession | None
        """
        session = self._lookup_sso_session2()
        if session:
            self.logger.debug("SSO session for user {!r} found in IdP cache".format(session.user_id))
            session.set_user(self.userdb.lookup_user(session.user_id))
            if not session.idp_user:
                return None
            _age = session.minutes_old
            if _age > self.config.sso_session_lifetime:
                self.logger.debug("SSO session expired (age {!r} minutes > {!r})".format(
                    _age, self.config.sso_session_lifetime))
                return None
            self.logger.debug("SSO session is still valid (age {!r} minutes <= {!r})".format(
                _age, self.config.sso_session_lifetime))
        return session

    def _lookup_sso_session2(self) -> Optional[eduid_idp.sso_session.SSOSession]:
        """
        See if a SSO session exists for this request, and return the data about
        the currently logged in user from the session store.

        :return: Data about currently logged in user
        """
        _data = None
        _session_id = eduid_idp.mischttp.get_idpauthn_cookie(self.logger)
        if _session_id:
            _data = self.context.sso_sessions.get_session(eduid_idp.cache.SSOSessionId(_session_id))
            self.logger.debug("Looked up SSO session using idpauthn cookie :\n{!s}".format(_data))
        else:
            query = eduid_idp.mischttp.parse_query_string(self.logger)
            if query:
                self.logger.debug("Parsed query string :\n{!s}".format(pprint.pformat(query)))
                try:
                    _data = self.context.sso_sessions.get_session(query['id'])
                    self.logger.debug("Looked up SSO session using query 'id' parameter :\n{!s}".format(
                        pprint.pformat(_data)))
                except KeyError:
                    # no 'id', or not found in cache
                    pass
        if not _data:
            self.logger.debug("SSO session not found using 'id' parameter or 'idpauthn' cookie")
            return None
        _sso = eduid_idp.sso_session.from_dict(_data)
        self.logger.debug("Re-created SSO session {!r}".format(_sso))
        return _sso

    def _lookup_common_session(self) -> Optional[RedisEncryptedSession]:
        if not self.context.common_sessions:
            return None
        cookie = eduid_idp.mischttp.read_cookie(self.config.shared_session_cookie_name, self.context.logger)
        if not cookie:
            return None
        session = self.context.common_sessions.get(cookie)
        self.context.logger.debug('Fetched common session: {}'.format(session))
        return session

    def handle_error(self):
        """
        Function called by CherryPy when there is an unhandled exception processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.
        """
        self.logger.debug("handle_error() invoked")
        cherrypy.response.status = 500
        cherrypy.response.body = self._render_error_page('500', 'Server Internal Error', filename='error.html')

    def error_page_default(self, status: str, message: str, traceback: str, version: str) -> bytes:
        """
        Function called by CherryPy when there is an exception
        (subclass of cherrypy.HTTPError) processing a request.

        Display a 'fail whale' page (error.html), and log the error in a way that makes
        post-mortem analysis in Sentry as easy as possible.

        :param status: HTML error code like '404 Not Found'
        :param message: HTML error message
        :param traceback: traceback of error
        :param version: cherrypy version
        """
        self.logger.debug("error_page_default() invoked, status={!r}, message={!r}".format(status, message))
        status_code = -1
        try:
            status_code = int(status.split()[0])
        except (ValueError, AttributeError, IndexError):
            pass

        pages = {401: 'unauthorized.html',
                 403: 'forbidden.html',
                 429: 'toomany.html',
                 440: 'session_timeout.html',
                 }
        fn = pages.get(status_code)
        if status_code == 403:
            if 'CREDENTIAL_EXPIRED' in message:
                fn = 'credential_expired.html'
            elif 'SWAMID_MFA_REQUIRED' in message:
                fn = 'swamid_mfa_required.html'
            elif 'MFA_REQUIRED' in message:
                fn = 'mfa_required.html'
        if fn is None:
            fn = 'error.html'

        return self._render_error_page(status, message, traceback = traceback, filename = fn)

    def _render_error_page(self, status: str, reason: str, filename: str, traceback: Optional[str]=None) -> bytes:
        # Look for error page in user preferred language
        """
        Render localized error page `error.html' or a default string based one if
        that page is not found in the configured content packages.

        :param status: HTML error code
        :param reason: HTML error message
        :param filename: HTML error page filename
        :param traceback: traceback of error
        :return: HTML
        """
        res = eduid_idp.mischttp.localized_resource(
            self._my_start_response, filename, self.config, logger=self.logger, status=status)
        if not res:
            # default error message
            res = "<html><body>Sorry, an error occured.<p>{status} {reason}</body></html>".format(
                status=status, reason=reason)

        status_code = -1
        try:
            status_code = int(status.split()[0])
        except (ValueError, AttributeError, IndexError):
            pass

        messages = {'SAML_UNKNOWN_SP': 'SAML error: Unknown Service Provider',
                    }
        error_details = ''
        if reason in messages:
            error_details = '<p>' + messages[reason] + '</p>'

        # apply simplistic HTML formatting to template in 'res'
        argv = eduid_idp.mischttp.get_default_template_arguments(self.config)
        argv.update({
            'error_status': str(status),
            'error_code': str(status_code),
            'error_reason': str(reason),
            'error_traceback': str(traceback),
            'error_details': str(error_details),
        })
        res = res.format(**argv).encode('utf-8')

        # Return before logging the error for errors that are not failures in the IdP
        # (avoids sentry reports)
        if status_code in [401, 403, 404, 440]:
            return res

        if status_code == 400:
            if str(reason) in [
                'Bad request, please re-initiate login',
                'No valid SAMLRequest found',
            ]:
                return res

        self.logger.exception("Error in IdP application",
                              extra={'data': {'request': cherrypy.request,
                                              'traceback': traceback,
                                              'status': status,
                                              'reason': reason,
                                              },
                                     })
        return res


# ----------------------------------------------------------------------------


def main(myname = 'eduid-IdP', args = None, logger = None):
    """
    Initialize everything and start the IdP application.

    :param myname: name of IdP application
    :param args: Object with attributes
    :param logger: logging root_logger
    :return: Does not return

    :type myname: string
    :type args: None | object
    :type logger: logging.Logger
    """
    if not args:
        args = parse_args()

    config = eduid_idp.config.IdPConfig(args.config_file, args.debug)

    # This is the root log level
    level = logging.INFO
    if config.debug:
        level = logging.DEBUG

    root_logger = logging.getLogger()

    # initialize various components
    if not logger:
        logging.basicConfig(level = level, stream = sys.stderr,
                            format='%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
        logger = logging.getLogger(myname)
        # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
        if not sys.stderr.isatty():
            for this_h in root_logger.handlers:
                this_h.setLevel(logging.WARNING)
    if config.logfile:
        formatter = logging.Formatter('%(asctime)s %(name)s %(threadName)s: %(levelname)s %(message)s')
        file_h = logging.handlers.RotatingFileHandler(config.logfile, maxBytes=10 * 1024 * 1024)
        file_h.setFormatter(formatter)
        file_h.setLevel(level)
        root_logger.addHandler(file_h)
    if config.syslog_socket:
        syslog_h = logging.handlers.SysLogHandler(config.syslog_socket)
        formatter = logging.Formatter('%(name)s: %(message)s')
        syslog_h.setFormatter(formatter)
        syslog_h.setLevel(level)
        root_logger.addHandler(syslog_h)
    if config.raven_dsn:
        if raven and SentryHandler:
            root_logger.debug("Setting up Raven exception logging")
            client = raven.Client(config.raven_dsn, timeout=10)
            handler = SentryHandler(client, level=logging.ERROR)
            if not raven.conf.setup_logging(handler):
                root_logger.warning("Failed setting up Raven/Sentry logging")
        else:
            root_logger.warning("Config option raven_dsn set, but raven not available")

    cherry_conf = {'server.thread_pool': config.num_threads,
                   'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles TLS
                   'tools.proxy.on': True,
                   'request.show_tracebacks': config.debug,
                   }
    if config.server_cert and config.server_key:
        _tls_opts = {'server.ssl_module': config.ssl_adapter,
                     'server.ssl_certificate': config.server_cert,
                     'server.ssl_private_key': config.server_key,
                     #'server.ssl_certificate_chain':
                     }
        cherry_conf.update(_tls_opts)

    if config.logdir:
        cherry_conf['log.access_file'] = os.path.join(config.logdir, 'access.log')
        cherry_conf['log.error_file'] = os.path.join(config.logdir, 'error.log')
    else:
        sys.stderr.write("NOTE: Config option 'logdir' not set.\n")

    cherrypy.log.access_log.propagate = False
    cherrypy.config.update(cherry_conf)

    cherrypy.quickstart(IdPApplication(logger, config))

if __name__ == '__main__':
    try:
        if main():
            sys.exit(0)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
