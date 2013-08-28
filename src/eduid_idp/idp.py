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

     Another hash, a reference to the authn context is generated (by pysaml2
     authn_context code) and passed to the template as {{authn_reference}}.

     The current URL is included in the HTML form as {{redirect_uri}}.

  3) User fills out login form an POSTs it to URL /verify

  4) URL /verify is handled by do_verify()

     do_verify() tries to authenticate user based on filled out HTML form contents.

     If successful, a random user identifier is created and a mapping between the
     random uid and the real authenticated users username is stored in the IDP.cache.

     The random user identifier and the authn_reference from step 2 is stored in a
     browser cookie called `idpauthn'.

     The user is HTTP redirected back to the URL of step 2 through the `redirect_uri'
     HTML parameter (included in the HTML form by step 2). The random user identifier
     is passed as URL parameter `id', and the `authn_reference' from step 2 is passed
     as URL parameter `key'.

  5) URL /sso/redirect (re-visited) is handled by SSO.redirect()

     Since the query string includes a `key' that can be used to look up info from
     IDP.ticket this time, processing is continued in SSO.do() (via SSO.operation()).
     The info in IDP.ticket is pruned first.

     SSO.do() gets the original URI parameters from step 2 that were stored in
     IDP.ticket, and rounds up identity information for the user.

     SSO.do() effectively uses IdPApplication.application() to determine which
     user is logged in. This will be either from the idpauthn cookie being set,
     and containing a random user identifier that can be looked up in IDP.cache
     to get a real username, or from IDP.cache using the `id' URI parameter.

     An AuthnResponse is created using pysaml2 create_authn_response(), and this
     is where the `authn_reference' from step 2 seems to come into play. The authn
     reference is used to locate the correct authn instance (the same one used
     in step 2) with the AUTHN_BROKER.

"""

import os
import re
import sys
import pprint
import logging
import argparse
from hashlib import sha1

import cherrypy

import eduid_idp
from eduid_idp.login import SSO, do_verify
from eduid_idp.logout import SLO

from saml2 import server

from saml2.authn_context import AuthnBroker
from saml2.authn_context import PASSWORD
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import authn_context_class_ref

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
                        dest='config_file',
                        default=default_config_file,
                        help='Config file',
                        metavar='PATH',
                        )

    parser.add_argument('--debug',
                        dest='debug',
                        action='store_true', default=default_debug,
                        help='Enable debug operation',
                        )

    return parser.parse_args()


class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}

class TicketCache():

    # XXX something needs to clean out old entries from TicketCache!

    def __init__(self, logger):
        self.logger = logger
        self._data = {}

    def key(self, SAMLRequest):
        return sha1(SAMLRequest).hexdigest()

    def add(self, key, info):
        assert("SAMLRequest" in info)
        self._data[key] = info

    def get(self, key):
        return self._data.get(key)

    def items(self):
        return self._data

    def delete(self, key):
        if key in self._data:
            del self._data[key]
        else:
            self.logger.debug("FREDRIK: FAILED DELETING {!r} FROM\n{!s}".format(
                    key, pprint.pformat(self._data)))


# -----------------------------------------------------------------------------






# map urls to functions
AUTHN_URLS = [
    # sso
    (r'sso/post$', (SSO, "post")),
    (r'sso/post/(.*)$', (SSO, "post")),
    (r'sso/redirect$', (SSO, "redirect")),
    (r'sso/redirect/(.*)$', (SSO, "redirect")),
    (r'sso/art$', (SSO, "artifact")),		# seldomly used, but part of standard
    (r'sso/art/(.*)$', (SSO, "artifact")),	# seldomly used, but part of standard
    # slo
    (r'slo/redirect$', (SLO, "redirect")),
    (r'slo/redirect/(.*)$', (SLO, "redirect")),
    (r'slo/post$', (SLO, "post")),
    (r'slo/post/(.*)$', (SLO, "post")),
    (r'slo/soap$', (SLO, "soap")),		# SOAP is commonly used for SLO
    (r'slo/soap/(.*)$', (SLO, "soap")),		# SOAP is commonly used for SLO
]

NON_AUTHN_URLS = [
    (r'verify?(.*)$', do_verify),
    #(r'sso/ecp$', (SSO, "ecp")),   # ECP is for eduID > 1
]

# ----------------------------------------------------------------------------



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
        self.IDP = server.Server(cfgfile, cache=Cache())
        # restore path
        sys.path = old_path
        self.IDP.ticket = TicketCache(logger)

        authn_authority = self.IDP.config.entityid

        self.AUTHN_BROKER = AuthnBroker()
        #self.AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), two_factor_authn, 20, authn_authority)
        self.AUTHN_BROKER.add(authn_context_class_ref(PASSWORD), eduid_idp.login.username_password_authn, 10, authn_authority)
        self.AUTHN_BROKER.add(authn_context_class_ref(UNSPECIFIED), "", 0, authn_authority)

        self.userdb = eduid_idp.idp_user.IdPUserDb(logger, config)

    @cherrypy.expose
    def default(self, *args, **kwargs):
        cherrypy.response.idp_response_status = None

        res = self.application(self.my_start_response)
        res2 = res
        if isinstance(res, list):
            res2 = ''.join(res)
        if isinstance(res2, basestring):
            if len(res2) < 200:
                self.logger.debug("FREDRIK: APP RESPONSE {!r} :\n{!r}".format(cherrypy.response.idp_response_status, res2))
            else:
                self.logger.debug("FREDRIK: APP RESPONSE {!r} : {!r} bytes ({!r})".format(cherrypy.response.idp_response_status, len(res2), res2[:20]))
            res = res2
        else:
            self.logger.debug("FREDRIK: NON-LIST APP RESPONSE {!r} : {!r}".format(cherrypy.response.idp_response_status, res))
        cherrypy.response.status = cherrypy.response.idp_response_status
        if cherrypy.response.idp_response_headers:
            for (k, v) in cherrypy.response.idp_response_headers:
                cherrypy.response.headers[k] = v
        return res

    def my_start_response(self, status, headers):
        self.logger.debug("FREDRIK: START RESPONSE {!r}, HEADERs {!r}".format(status, headers))
        if cherrypy.response.idp_response_status:
            self.logger.warning("start_response called twice (now {!r} / {!r}, previous {!r} / {!r})".format(
                    status, headers, cherrypy.response.idp_response_status, cherrypy.response.idp_response_headers))
        cherrypy.response.idp_response_status = status
        cherrypy.response.idp_response_headers = headers

    def application(self, start_response):
        """
        What used to be the main WSGI application. Dispatch the current
        request to the functions from above (AUTHN_URLS and NOT_AUTHN_URLS).

        If nothing matches call the `not_found` function.

        :param start_response: The function to run when the handling of the
        request is done
        :return: The response as a list of lines
        """

        path = cherrypy.request.path_info.lstrip('/')
        kaka = cherrypy.request.cookie
        self.logger.debug("\n\n-----\n\n")
        self.logger.info("<application> PATH: %s" % path)

        environ = {}

        static_fn = eduid_idp.mischttp.static_filename(self.config, path)
        if static_fn:
            self.logger.debug("SERVING STATIC FILE {!r}".format(static_fn))
            return eduid_idp.mischttp.static_file(environ, start_response, static_fn)
        if path.startswith("static/") or path == "favicon.ico":
            return eduid_idp.mischttp.not_found(environ, start_response)

        userdata = None
        if kaka:
            userdata = eduid_idp.mischttp.info_from_cookie(kaka, self.IDP, self.logger)
            self.logger.debug("Looked up userdata using idpauthn cookie : {!s}".format(pprint.pformat(userdata)))
        else:
            self.logger.debug("No cookie, looking for 'id' parameter in query string :\n{!s}".format(cherrypy.request.query_string))
            query = eduid_idp.mischttp.parse_query_string()
            self.logger.debug("FREDRIK: QUERY:\n{!s}".format(pprint.pformat(query)))
            if query:
                try:
                    userdata = self.IDP.cache.uid2user[query["id"]]
                    self.logger.debug("Looked up userdata using request id parameter : {!s}".format(pprint.pformat(userdata)))
                except KeyError:
                    # no 'id', or not found in cache
                    pass

        user = None
        if userdata:
            user = userdata['user']
            authn_ref = userdata['authn_reference']
            environ["idp.authn_ref"] = authn_ref

        url_patterns = AUTHN_URLS
        if not user:
            self.logger.info("-- No USER --")
            # insert NON_AUTHN_URLS first in case there is no user
            url_patterns = NON_AUTHN_URLS + url_patterns
        else:
            self.logger.info("FREDRIK: USER {!r}".format(user))

        for regex, callback in url_patterns:
            match = re.search(regex, path)
            self.logger.debug("match path {!r} to re {!r} -> {!r}".format(path, regex, match))
            if match is not None:
                self.logger.debug("Callback: %s" % (callback,))
                if isinstance(callback, tuple):
                    cls = callback[0](environ, start_response, self, user)
                    func = getattr(cls, callback[1])
                    return func()
                return callback(environ, start_response, self, user)

        return eduid_idp.mischttp.not_found(environ, start_response)

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

    cherry_conf = {'server.thread_pool': config.num_threads,
        	   'server.socket_host': config.listen_addr,
                   'server.socket_port': config.listen_port,
                   # enables X-Forwarded-For, since BCP is to run this server
                   # behind a webserver that handles SSL
                   'tools.proxy.on': True,
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
