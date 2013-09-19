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
Code handling Single Sign On logins.
"""

import uuid
import time
import pprint
import cherrypy

from eduid_idp.service import Service
from eduid_idp.mischttp import Response, BadRequest, Unauthorized, ServiceError, Redirect
import eduid_idp.mischttp

from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import exception_trace
from saml2.sigver import verify_redirect_signature

from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):
    def __init__(self, environ, start_response, idp_app):
        Service.__init__(self, environ, start_response, idp_app)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None

    def perform_login(self, _dict, binding_in, relay_state=None):
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param _dict: Login request as dict
        :param binding_in: SAML2 binding as string
        :param relay_state: SAML2 relay state
        :return: Response as string
        """
        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.perform_login() ---")

        self.logger.debug("perform_login :\n{!s}".format(pprint.pformat(_dict)))
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        try:
            _ok, _resp = self._verify_request(_dict, binding_in)
            if not _ok:
                return _resp(self.environ, self.start_response)
            resp_args = self.IDP.response_args(self.req_info.message)
        except UnknownPrincipal as excp:
            self.logger.error("Could not verify request: UnknownPrincipal: {!s}".format(excp))
            _resp = self.IDP.create_error_response(self.req_info.message.id,
                                                   self.destination, excp)
            #_resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return _resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            self.logger.error("Could not verify request: UnsupportedBinding: {!s}".format(excp))
            _resp = self.IDP.create_error_response(self.req_info.message.id,
                                                   self.destination, excp)
            #_resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return _resp(self.environ, self.start_response)

        self.logger.info("Identity of user {!s}:\n{!s}".format(self.user, pprint.pformat(self.user.identity)))

        try:
            #_authn = self.AUTHN_BROKER[self.environ["idp.authn_ref"]]
            _authn = self.environ["idp.authn"]
            self.logger.debug("User authenticated using Authn {!r}".format(_authn))
            self.logger.debug("Creating an AuthnResponse, user {!r}, response args {!r}".format(self.user, resp_args))
            _resp = self.IDP.create_authn_response(self.user.identity, userid = self.user.username,
                                                   authn = _authn, sign_assertion = True, **resp_args)
        except Exception, excp:
            self.logger.error("Failed creating AuthnResponse:\n {!s}".format(exception_trace(excp)))
            resp = ServiceError("Exception: %s" % (excp,))
            return resp(self.environ, self.start_response)

        self.logger.info("AuthNResponse {!r}".format(_resp))
        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        if relay_state is None:
            relay_state = _dict["RelayState"]
        self.logger.debug("Applying binding_out {!r}, destination {!r}, relay_state {!r}".format(
            self.binding_out, self.destination, relay_state))
        http_args = self.IDP.apply_binding(self.binding_out, str(_resp), self.destination,
                                           relay_state, response = True)
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
            return self.perform_login(_ticket, BINDING_HTTP_REDIRECT)

        if not self.user:
            self.logger.info("Not authenticated")
        if self.req_info.message.force_authn:
            self.logger.info("Forcing authentication for user {!r}".format(self.user))

        # Re-insert in IDP.ticket cache.
        # XXX this should ideally be done in do_verify(), on actual authentication failures,
        # since when it is done here it will show page reloads (Ctrl+R) as failed login
        # attempts to the user.
        _ticket["FailCount"] = _fc + 1
        key = self._store_ticket(_ticket)

        return self._not_authn(key, self.req_info.message.requested_authn_context)

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
            self.logger.debug("Continuing with posted Authn request {!r}".format(_info))
            return self.perform_login(_info, BINDING_HTTP_POST)
        # Request authentication, either because there was no self.user
        # or because it was requested using SAML2 ForceAuthn
        _info["req_info"] = self.req_info
        key = self._store_ticket(_info)
        return self._not_authn(key, _req.requested_authn_context)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _dict = self.unpack_either()
        if not _dict:
            resp = BadRequest("Missing query")
            return resp(self.environ, self.start_response)
            # exchange artifact for request
        request = self.IDP.artifact2message(_dict["SAMLart"], "spsso")
        return self.perform_login(request, BINDING_HTTP_ARTIFACT, _dict["RelayState"])

    def _verify_request(self, query, binding):
        """
        Verify that a login request looks OK to this IdP, and figure out
        the outgoing binding and destination to use later.

        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over as string
        :return: Status, Response where Status is a bool()
        Status is True if query is OK, and Response is either a Response() or None
        if Status is True.
        """
        if not query:
            self.logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return False, resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = self.IDP.parse_authn_request(query, binding)
            self.logger.info("SAML query parsed OK")
        else:
            self.logger.debug("verify_request acting on previously parsed self.req_info {!s}".format(
                self.req_info))

        self.logger.debug("AuthnRequest {!r}".format(self.req_info.message))

        self.binding_out, self.destination = self.IDP.pick_binding(
            "assertion_consumer_service",
            bindings = self.response_bindings,
            entity_id = self.req_info.message.issuer.text)

        self.logger.debug("Binding: %s, destination: %s" % (self.binding_out,
                                                            self.destination))
        return True, None

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
        if "key" in _info:
            _key = _info["key"]
        elif "SAMLRequest" in _info:
            _key = self.IDP.ticket.key(_info["SAMLRequest"])
        else:
            return False, BadRequest("Missing SAMLRequest, please re-initiate login")
            # lookup
        _data = self.IDP.ticket.get(_key)

        if _data is None:
            self.logger.debug("Key {!r} not found in IDP.ticket".format(_key))
            if "key" in _info:
                return False, BadRequest("Missing IdP ticket, please re-initiate login")
                # cache miss, parse SAMLRequest
            _data = _info
            _data["req_info"] = self._parse_SAMLRequest(_info)
        else:
            self.logger.debug("Retreived IDP.ticket(key={!r}) :\n{!s}".format(
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

    def _not_authn(self, key, requested_authn_context):
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        """
        redirect_uri = eduid_idp.mischttp.geturl(query = False)

        self.logger.debug("Do authentication, requested auth context : {!r}".format(requested_authn_context))

        auth_info = self.AUTHN_BROKER.pick(requested_authn_context)

        if len(auth_info):
            method, reference = auth_info[0]
            self.logger.debug("Authn chosen: %s (ref=%s)" % (method, reference))
            # `method' is, for example, the function username_password_authn
            return method(self.environ, self.start_response, reference, key,
                          redirect_uri, self.logger, self.config)
        else:
            resp = Unauthorized("No usable authentication method")
            return resp(self.environ, self.start_response)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def username_password_authn(environ, start_response, reference, key,
                            redirect_uri, logger, config):
    """
    Display the login form for standard username-password authentication.

    SSO._not_authn() chooses what authentication method to use based on
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
        argv["alert_msg"] = "Incorrect username or password ({!s} attempts)".format(_fc)

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


def do_verify(environ, start_response, idp_app):
    query = eduid_idp.mischttp.get_post()

    _loggable = query.copy()
    if 'password' in _loggable:
        _loggable['password'] = '<redacted>'
    idp_app.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(_loggable)))

    idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))

    # What kind of authentication to perform was chosen by SSO._not_authn() when
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
            resp = Redirect(lox, content = "text/html")
        else:
            resp = Unauthorized("Unknown user or wrong password")
    else:
        idp_app.logger.debug("User {!r} authenticated OK using {!r}".format(user, _authn['class_ref']))
        # NOTE: It is important than noone can guess one of these uids, as that would allow impersonation.
        uid = str(uuid.uuid4())
        _session = {'user': user,
                    'authn': _authn,
                    'authn_timestamp': int(time.time()),
                    }
        idp_app.IDP.cache.add_session(uid, user.username, _session)
        idp_app.logger.debug("Registered %s under '%s' in IdP SSO sessions" % (user, uid))

        kaka = eduid_idp.mischttp.set_cookie("idpauthn", idp_app.config.sso_session_lifetime,
                                             "/", idp_app.logger, uid)
        lox = "%s?id=%s&key=%s" % (query["redirect_uri"], uid,
                                   query["key"])
        idp_app.logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers = [kaka], content = "text/html")

    return resp(environ, start_response)


# ----------------------------------------------------------------------------
