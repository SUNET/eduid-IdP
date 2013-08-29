#
# Copyright (c) 2013 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

import time
import pprint
import cherrypy

from eduid_idp.service import Service
from eduid_idp.mischttp import Response, BadRequest, Unauthorized, ServiceError, Redirect
import eduid_idp.mischttp

from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import rndstr, exception_trace
from saml2.sigver import verify_redirect_signature

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST

"""
Code handling Single Sign On logins.
"""

# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):

    def __init__(self, environ, start_response, idp_app, user=None):
        Service.__init__(self, environ, start_response, idp_app, user)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None


    def verify_request(self, query, binding):
        """
        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over
        """
        resp_args = {}
        if not query:
            self.logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return resp_args, resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = self.IDP.parse_authn_request(query, binding)
            self.logger.info("SAML query parsed OK")
        else:
            self.logger.debug("verify_request acting on previously parsed self.req_info {!s}".format(
                    self.req_info))

        _authn_req = self.req_info.message
        self.logger.debug("AuthnRequest {!r} :\n{!s}".format(_authn_req, _authn_req))

        self.binding_out, self.destination = self.IDP.pick_binding(
            "assertion_consumer_service",
            bindings=self.response_bindings,
            entity_id=_authn_req.issuer.text)

        self.logger.debug("Binding: %s, destination: %s" % (self.binding_out,
                                                            self.destination))

        try:
            resp_args = self.IDP.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal, excp:
            _resp = self.IDP.create_error_response(_authn_req.id,
                                                   self.destination, excp)
        except UnsupportedBinding, excp:
            _resp = self.IDP.create_error_response(_authn_req.id,
                                                   self.destination, excp)

        return resp_args, _resp


    def do(self, query, binding_in, relay_state=""):
        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.do() ---")
        try:
            resp_args, _resp = self.verify_request(query, binding_in)
        except UnknownPrincipal, excp:
            self.logger.error("Could not verify request: UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            self.logger.error("Could not verify request: UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        if not _resp:
            self.logger.info("Identity of user {!s}:\n{!s}".format(self.user, pprint.pformat(self.user.identity)))

            try:
                #_authn = self.AUTHN_BROKER[self.environ["idp.authn_ref"]]
                _authn = self.environ["idp.authn"]
                self.logger.debug("User authenticated using Authn {!r}".format(_authn))
                self.logger.debug("Creating an AuthnResponse, user {!r}".format(self.user))
                _resp = self.IDP.create_authn_response(self.user.identity, userid=self.user.username,
                                                       authn=_authn, sign_assertion=True, **resp_args)
            except Exception, excp:
                self.logger.error("Failed creating AuthnResponse:\n {!s}".format(exception_trace(excp)))
                resp = ServiceError("Exception: %s" % (excp,))
                return resp(self.environ, self.start_response)

        self.logger.info("AuthNResponse {!r} :\n{!s}".format(_resp, _resp))
        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        http_args = self.IDP.apply_binding(self.binding_out,
                                           "%s" % _resp, self.destination,
                                           relay_state, response=True)
        #self.logger.debug("HTTPargs :\n{!s}".format(pprint.pformat(http_args)))
        return self.response(self.binding_out, http_args)


    def redirect(self):
        """ This is the HTTP-redirect endpoint """
        self.logger.info("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("FREDRIK: Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        _res, _ticket = self._get_ticket(_info)
        if not _res or isinstance(_ticket, Response):
            # result is False and/or _ticket is an instance of Response (or BadRequest etc.)
            return _ticket(self.environ, self.start_response)

        self.req_info = _ticket['req_info']

        _fc = _ticket.get("FailCount", 0)
        try:
            _fc = int(_fc)
        except ValueError:
            self.logger.debug("Bad (non-integer) FailCount : {!r}".format(_fc))
            _fc = 0

        self.environ['idp.FailCount'] = _fc

        if self.user and not self.req_info.message.force_authn:
            self.logger.debug("Continuing with Authn request {!r}".format(self.req_info))
            return self.operation(_ticket, BINDING_HTTP_REDIRECT)

        if not self.user:
            self.logger.info("Not authenticated")
        if self.req_info.message.force_authn:
            self.logger.info("Forcing authentication for user {!r}".format(self.user))

        # re-insert in IDP.ticket cache
        _ticket["FailCount"] = _fc + 1
        key = self._store_ticket(_ticket)

        return self.not_authn(key, self.req_info.message.requested_authn_context)


    def post(self):
        """
        The HTTP-Post endpoint
        """
        self.logger.info("--- In SSO POST ---")
        _info = self.unpack_either()
        self.req_info = self.IDP.parse_authn_request(
            _info["SAMLRequest"], BINDING_HTTP_POST)
        _req = self.req_info.message
        if self.user and not _req.force_authn:
            return self.operation(_info, BINDING_HTTP_POST)
        # Request authentication, either because there was no self.user
        # or because it was requested using SAML2 ForceAuthn
        _info["req_info"] = self.req_info
        key = self._store_ticket(_info)
        return self.not_authn(key, _req.requested_authn_context)


    def _store_ticket(self, _ticket):
        """
        Add an entry to the IDP.ticket cache.

        Ticket must contain SAMLRequest and is typically

        {'RelayState': '/path',
         'SAMLRequest': 'nVLB...==',
         'req_info': <saml2.request.AuthnRequest object>,
         ...
        }

        :returns: Key as string
        """
        key = self.IDP.ticket.key(_ticket["SAMLRequest"])
        self.logger.debug("_store_ticket in IDP.ticket (key {!r}):\n{!s}".format(key, pprint.pformat(_ticket)))
        # store the AuthnRequest
        self.IDP.ticket.add(key, _ticket)
        return key


    def _get_ticket(self, _info):
        """
        _info is redirect HTTP query parameters.

        Will include a 'key' parameter, or a 'SAMLRequest'.

        Ticket is typically

        {'RelayState': '/path',
         'SAMLRequest': 'nVLB...==',
         'req_info': <saml2.request.AuthnRequest object>,
         ...
        }

        :returns: ResultBool, Ticket as dict
        """
        # Try ticket-cache lookup based on key, or key derived from SAMLRequest
        _key = None
        if "key" in _info:
            _key = _info["key"]
        elif "SAMLRequest" in _info:
            _key = self.IDP.ticket.key(_info["SAMLRequest"])
        else:
            return False, BadRequest("Missing SAMLRequest, please re-initiate login")
        # lookup
        _data = self.IDP.ticket.get(_key)

        if _data is None:
            self.logger.debug("FREDRIK: Key {!r} not found in IDP.ticket :\n{!s}".format(
                     _key, pprint.pformat(self.IDP.ticket.items())))
            if "key" in _info:
                return False, BadRequest("Missing IdP ticket, please re-initiate login")
             # cache miss, parse SAMLRequest
            _data = _info
            _data["req_info"] = self._parse_SAMLRequest(_info)
        else:
            self.logger.debug("FREDRIK: Retreived IDP.ticket(key={!r}) :\n{!s}".format(
                    _key, pprint.pformat(_data)))

        return True, _data


    def _parse_SAMLRequest(self, _info):
        """
        Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
        instance.

        If the SAMLRequest is signed, the signature is validated and a BadRequest()
        returned on failure.

        :returns: AuthnRequest or BadRequest() instance
        """
        self.logger.debug("SAML request : {!r}".format(_info["SAMLRequest"]))
        _req_info = self.IDP.parse_authn_request(_info["SAMLRequest"], BINDING_HTTP_REDIRECT)

        self.logger.debug("Decoded SAMLRequest into AuthnRequest {!r} :\n{!s}".format(
                _req_info.message, _req_info.message))

        if "SigAlg" in _info and "Signature" in _info:  # Signed request
            issuer = _req_info.message.issuer.text
            _certs = self.IDP.metadata.certs(issuer, "any", "signing")
            verified_ok = False
            for cert in _certs:
                if verify_redirect_signature(_info, cert):
                    verified_ok = True
                    break
            if not verified_ok:
                resp = BadRequest("Message signature verification failure")
                return resp(self.environ, self.start_response)
        else:
            self.logger.debug("No signature in SAMLRequest")
        return _req_info



# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def username_password_authn(environ, start_response, reference, key,
                            redirect_uri, logger, config):
    """
    Display the login form for standard username-password authentication.

    Service.not_authn() chooses what authentication method to use based on
    requested AuthnContext and local configuration, and then calls this method
    to render the login page for this method.
    """
    argv = {
        "action": "/verify",
        "username": "",
        "password": "",
        "key": key,
        "authn_reference": reference,
        "redirect_uri": redirect_uri,
        "alert_msg": "",
    }

    # if idp.FailCount is present, it is always an integer
    _fc = environ.get("idp.FailCount", 0)
    if _fc > 0:
        argv["alert_msg"] = "Incorrect username or password (%i attempts)" % (_fc)

    logger.debug("Login page HTML substitution arguments :\n{!s}".format(pprint.pformat(argv)))

    static_fn = eduid_idp.mischttp.static_filename(config, 'login.html')

    if static_fn:
        res = eduid_idp.mischttp.static_file(environ, start_response, static_fn)
        if len(res) == 1:
            res = res[0]
        # apply simplistic HTML formatting to template in 'res'
        return res.format(**argv)

    return eduid_idp.mischttp.not_found(environ, start_response)


def verify_username_and_password(dic, idp_app):
    """
    :params dic: dict() with POST parameters
    :params idp_app: IdPApplication instance
    :returns: (verdict, res,) where verdict is bool()
    """
    username = dic["username"]
    password = dic["password"]

    res = idp_app.userdb.verify_username_and_password(username, password)
    if res:
        return True, res
    return False, ""


def do_verify(environ, start_response, idp_app, _user):
    query = eduid_idp.mischttp.get_post()

    _loggable = query.copy()
    if 'password' in _loggable:
        _loggable['password'] = '<redacted>'
    idp_app.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(_loggable)))

    idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))

    # What kind of authentication to perform was chosen by Service.not_authn() when
    # the login web page was to be rendered. It is passed to us here through an HTTP POST
    # parameter (authn_reference) so it can't be trusted. XXX is this a problem? Not sure.

    authn_ref = query["authn_reference"]
    try:
        _authn = idp_app.AUTHN_BROKER[authn_ref]
    except KeyError:
        resp = Unauthorized("Bad authentication reference")
        return resp(environ, start_response)

    idp_app.logger.debug("Authenticating with {!r} (from authn_reference={!r})".format(_authn['class_ref'], authn_ref))

    try:
        if _authn['class_ref'] == 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password':
            _ok, user = verify_username_and_password(query, idp_app)
        else:
            idp_app.logger.info("Authentication for class {!r} not implemented".format(_authn['class_ref']))
            raise NotImplementedError()
    except Exception as excp:
        idp_app.logger.error("Failed authenticating user:\n {!s}".format(exception_trace(excp)))
        _ok = False
        user = None

    if not _ok:
        idp_app.logger.info("Unknown user or wrong password")
        _referer = cherrypy.request.headers.get('Referer')
        if _referer:
            lox = str(_referer)
            resp = Redirect(lox, content="text/html")
        else:
            resp = Unauthorized("Unknown user or wrong password")
    else:
        idp_app.logger.debug("User {!r} authenticated OK using {!r}".format(user, _authn['class_ref']))
        uid = rndstr(24)
        idp_app.IDP.cache.uid2user[uid] = {'user': user,
                                           'authn': _authn,
                                           'authn_timestamp': int(time.time()),
                                           }
        idp_app.IDP.cache.user2uid[user] = uid
        idp_app.logger.debug("Registered %s under '%s' in IdP SSO sessions" % (user, uid))

        kaka = eduid_idp.mischttp.set_cookie("idpauthn", "/", idp_app.logger, uid)
        lox = "%s?id=%s&key=%s" % (query["redirect_uri"], uid,
                                   query["key"])
        idp_app.logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers=[kaka], content="text/html")

    return resp(environ, start_response)


# ----------------------------------------------------------------------------
