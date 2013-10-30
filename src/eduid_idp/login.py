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

import time
import pprint
import cherrypy

from eduid_idp.service import Service
import eduid_idp.mischttp

from saml2.request import AuthnRequest

from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.sigver import verify_redirect_signature

from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST


class SSOLoginData(object):
    """
    Class to hold data about an ongoing login process - i.e. data relating to a
    particular IdP visitor in the process of logging in, but not yet fully logged in.

    :param key: unique reference for this instance
    :param req_info: pysaml2 AuthnRequest data
    :param data: dict

    :type key: basestring
    :type req_info: AuthnRequest
    """
    def __init__(self, key, req_info, data):
        self._key = key
        self._req_info = req_info
        self._data = data
        self._FailCount = 0

    def __str__(self):
        return pprint.pformat({'key': self._key,
                               'req_info': self._req_info,
                               'data': self._data,
                               'FailCount': self._FailCount,
                               })

    @property
    def key(self):
        """
        Unique reference for this instance. Used for storing SSOLoginData instances
        in SSOLoginDataCache.
        :rtype: basestring
        """
        return self._key

    @property
    def SAMLRequest(self):
        """
        The SAML request in transport encoding (base 64).

        :rtype : basestring
        """
        return self._data['SAMLRequest']

    @property
    def req_info(self):
        """
        req_info is SAMLRequest, but parsed

        :rtype: AuthnRequest
        """
        return self._req_info

    @property
    def RelayState(self):
        """
        This is an opaque string generated by a SAML SP that must be sent to the
        SP when the authentication is finished and the user redirected to the SP.

        :rtype: basestring
        """
        return self._data['RelayState']

    @property
    def FailCount(self):
        """
        The number of failed login attempts. Used to show an alert message to the
        user to make them aware of the reason they got back to the IdP login page.

        :rtype: int
        """
        return self._FailCount

    @FailCount.setter
    def FailCount(self, value):
        """
        Set the FailCount.

        :param value: new value
        :type value: int
        """
        assert isinstance(value, int)
        self._FailCount = value


class SSOLoginDataCache(eduid_idp.cache.ExpiringCache):
    """
    Login data is state kept between rendering the login screen, to when the user is
    completely logged in and redirected from the IdP to the original resource the
    user is accessing.

    :param idp_app: saml2.server.Server() instance
    :param name: string describing this cache
    :param logger: logging logger
    :param ttl: expire time of data in seconds
    :param lock: threading.Lock() instance

    :type idp_app: saml2.server.Server
    :type name: basestring
    :type logger: logging.Logger
    :type ttl: int
    :type lock: threading.Lock
    """

    def __init__(self, idp_app, name, logger, ttl, lock = None):
        self.IDP = idp_app
        eduid_idp.cache.ExpiringCache.__init__(self, name, logger, ttl, lock)

    def store_ticket(self, ticket):
        """
        Add an entry to the IDP.ticket cache.

        :param ticket: SSOLoginData instance
        :returns: True on success
        """
        self.logger.debug("Storing login state (IdP ticket) :\n{!s}".format(ticket))
        self.add(ticket.key, ticket)
        return True

    def create_ticket(self, data, binding, key=None):
        """
        Create an SSOLoginData instance from a dict.

        The dict must contain SAMLRequest and is typically

        {'RelayState': '/path',
         'SAMLRequest': 'nVLB...==',
         ...
        }

        :param data: dict containing at least `SAMLRequest'.
        :param binding: SAML2 binding as string (typically a URN)
        :param key: unique key to use. If not specified, one will be computed.
        :returns: SSOLoginData instance

        :type data: dict
        :type binding: basestring
        :type key: basestring | None
        :rtype: SSOLoginData
        """
        if not binding:
            raise eduid_idp.error.ServiceError("Can't create IdP ticket with unknown binding", logger = self.logger)
        req_info = self._parse_SAMLRequest(data, binding)
        if not key:
            key = self.key(data["SAMLRequest"])
        ticket = SSOLoginData(key, req_info, data)
        self.logger.debug("Created login state (IdP ticket) :\n{!s}".format(ticket))
        return ticket

    def get_ticket(self, info, binding=None):
        """
        _info is redirect HTTP query parameters.

        Will include a 'key' parameter, or a 'SAMLRequest'.

        :param info: dict containing `key' or `SAMLRequest'.
        :param binding: SAML2 binding (typically a URN)
        :returns: SSOLoginData instance

        :type info: dict
        :type binding: basestring
        :rtype: SSOLoginData
        """
        if not info:
            raise eduid_idp.error.BadRequest("Bad request, please re-initiate login", logger = self.logger)

        # Try ticket-cache lookup based on key, or key derived from SAMLRequest
        if "key" in info:
            _key = info["key"]
        elif "SAMLRequest" in info:
            _key = self.key(info["SAMLRequest"])
        else:
            raise eduid_idp.error.BadRequest("Missing SAMLRequest, please re-initiate login", logger = self.logger)

        # lookup
        _ticket = self.get(_key)

        if _ticket is None:
            self.logger.debug("Key {!r} not found in IDP.ticket".format(_key))
            if "key" in info:
                raise eduid_idp.error.BadRequest("Missing IdP ticket, please re-initiate login", logger = self.logger)

            # cache miss, parse SAMLRequest
            _ticket = self.create_ticket(info, binding, key=_key)
            self.store_ticket(_ticket)
        else:
            self.logger.debug("Retreived login state (IdP.ticket) :\n{!s}".format(_ticket))

        return _ticket

    def _parse_SAMLRequest(self, info, binding):
        """
        Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
        instance.

        If the SAMLRequest is signed, the signature is validated and a BadRequest()
        returned on failure.

        :param info: dict with keys 'SAMLRequest' and possibly 'SigAlg' and 'Signature'
        :param binding: SAML binding
        :returns: pysaml2 AuthnRequest information
        :raise: BadRequest if request signature validation fails

        :type info: dict
        :type binding: basestring
        :rtype: AuthnRequest
        """
        self.logger.debug("Parsing SAML request : {!r}".format(info["SAMLRequest"]))
        _req_info = self.IDP.parse_authn_request(info["SAMLRequest"], binding)
        assert isinstance(_req_info, AuthnRequest)

        self.logger.debug("Decoded SAMLRequest into AuthnRequest {!r} :\n{!s}".format(
            _req_info.message, _req_info.message))

        if "SigAlg" in info and "Signature" in info:  # Signed request
            issuer = _req_info.message.issuer.text
            _certs = self.IDP.metadata.certs(issuer, "any", "signing")
            verified_ok = False
            for cert in _certs:
                if verify_redirect_signature(info, cert):
                    verified_ok = True
                    break
            if not verified_ok:
                self.logger.info("Message signature verification failure")
                raise eduid_idp.error.BadRequest("Message signature verification failure", logger = self.logger)
        else:
            # XXX check if metadata says request should be signed ???
            self.logger.debug("No signature in SAMLRequest")
        return _req_info


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):
    """
    Single Sign On service.

    :param environ: environment (see eduid_idp.idp._request_environment())
    :param start_response: WSGI-like start_response function pointer
    :param idp_app: IdPApplication instance

    :type environ: dict
    :type start_response: function
    :type idp_app: idp.IdPApplication
    """

    def __init__(self, environ, start_response, idp_app):
        Service.__init__(self, environ, start_response, idp_app)
        self.binding = ""
        self.binding_out = None
        self.destination = None

    def perform_login(self, ticket):
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param ticket: SSOLoginData instance
        :return: Response

        :type ticket: SSOLoginData
        :rtype: basestring
        """
        assert isinstance(ticket, SSOLoginData)

        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.perform_login() ---")

        self.logger.debug("perform_login :\n{!s}".format(str(ticket)))
        try:
            if not self._verify_request(ticket):
                raise eduid_idp.error.ServiceError(logger = self.logger)  # not reached
            resp_args = self.IDP.response_args(ticket.req_info.message)
        except UnknownPrincipal as excp:
            self.logger.error("Could not verify request: UnknownPrincipal: {!s}".format(excp))
            raise eduid_idp.error.BadRequest("Don't know the SP that referred you here", logger = self.logger)
        except UnsupportedBinding as excp:
            self.logger.error("Could not verify request: UnsupportedBinding: {!s}".format(excp))
            raise eduid_idp.error.BadRequest("Don't know how to reply to the SP that referred you here",
                                             logger = self.logger)

        self.logger.info("Identity of user {!s}:\n{!s}".format(self.user, pprint.pformat(self.user.identity)))

        #_authn = self.AUTHN_BROKER[self.environ["idp.authn_ref"]]
        _authn = self.environ["idp.authn"]
        self.logger.debug("User authenticated using Authn {!r}".format(_authn))

        # Decide what AuthnContext to assert based on the one requested in the request
        # and the authentication performed
        req_authn_context = ticket.req_info.message.requested_authn_context

        authn_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_context, self.logger)
        auth_info = self.AUTHN_BROKER.pick(authn_ctx)

        auth_levels = []
        if authn_ctx and len(auth_info):
            # `method' is just a no-op (true) value in the way eduid_idp uses the AuthnBroker -
            # filter out the `reference' values (canonical class_ref strings)
            auth_levels = [reference for (method, reference) in auth_info]
            self.logger.debug("Acceptable Authn levels (picked by AuthnBroker) : {!r}".format(auth_levels))

        response_authn = eduid_idp.assurance.response_authn(req_authn_context, _authn, auth_levels, self.logger)

        try:
            self.logger.debug("Asserting AuthnContext {!r} (requested: {!r})".format(
                response_authn['class_ref'], req_authn_context.authn_context_class_ref[0].text))
        except AttributeError:
            self.logger.debug("Asserting AuthnContext {!r} (none requested)".format(response_authn['class_ref']))

        self.logger.debug("Creating an AuthnResponse, user {!r}, response args {!r}".format(self.user, resp_args))

        _resp = self.IDP.create_authn_response(self.user.identity, userid = self.user.username,
                                               authn = response_authn, sign_assertion = True, **resp_args)

        self.logger.info("AuthNResponse\n\n{!r}\n\n".format(_resp))

        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        self.logger.debug("Applying binding_out {!r}, destination {!r}, relay_state {!r}".format(
            self.binding_out, self.destination, ticket.RelayState))
        http_args = self.IDP.apply_binding(self.binding_out, str(_resp), self.destination,
                                           ticket.RelayState, response = True)
        #self.logger.debug("HTTPargs :\n{!s}".format(pprint.pformat(http_args)))
        return eduid_idp.mischttp.create_html_response(self.binding_out, http_args, self.start_response, self.logger)

    def redirect(self):
        """ This is the HTTP-redirect endpoint.

        :return: HTTP response
        :rtype: basestring
        """
        self.logger.info("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        _ticket = self.IDP.ticket.get_ticket(_info, binding=BINDING_HTTP_REDIRECT)

        if self.user and not _ticket.req_info.message.force_authn:
            self.logger.debug("Continuing with Authn request {!r}".format(_ticket.req_info))
            return self.perform_login(_ticket)

        if not self.user:
            self.logger.info("Not authenticated")
        if _ticket.req_info.message.force_authn:
            self.logger.info("Forcing authentication for user {!r}".format(self.user))

        return self._not_authn(_ticket, _ticket.req_info.message.requested_authn_context)

    def post(self):
        """
        The HTTP-Post endpoint

        :return: HTTP response
        :rtype: basestring
        """
        self.logger.info("--- In SSO POST ---")
        _info = self.unpack_either()

        _ticket = self.IDP.ticket.get_ticket(_info, binding=BINDING_HTTP_POST)

        if self.user and not _ticket.req_info.message.force_authn:
            self.logger.debug("Continuing with posted Authn request {!r}".format(_ticket.req_info))
            return self.perform_login(_ticket)

        if not self.user:
            self.logger.info("Not authenticated")
        if _ticket.req_info.message.force_authn:
            self.logger.info("Forcing authentication for user {!r}".format(self.user))

        return self._not_authn(_ticket, _ticket.req_info.message.requested_authn_context)

    def artifact(self):
        """
        The HTTP-Artifact endpoint

        :return: HTTP response
        :raise eduid_idp.error.BadRequest:

        :rtype: basestring
        """
        # Can be either by HTTP_Redirect or HTTP_POST
        info = self.unpack_either()
        if not info:
            raise eduid_idp.error.BadRequest('Missing query', logger = self.logger)
        # exchange artifact for request
        request = self.IDP.artifact2message(info["SAMLart"], "spsso")
        _ticket = self.IDP.ticket.create_ticket(request, BINDING_HTTP_ARTIFACT)
        # XXX is there a point in using create_login_data and thereby not saving the
        # ticket in self.IDP.ticket for artifact requests?
        return self.perform_login(_ticket)

    def _verify_request(self, ticket):
        """
        Verify that a login request looks OK to this IdP, and figure out
        the outgoing binding and destination to use later.

        :param ticket: SSOLoginData instance
        :return: True on success
        Status is True if query is OK, and Response is either a Response() or None
        if Status is True.

        :type ticket: SSOLoginData
        :rtype: bool
        """
        assert isinstance(ticket, SSOLoginData)
        self.logger.debug("verify_request acting on previously parsed ticket.req_info {!s}".format(ticket.req_info))

        self.logger.debug("AuthnRequest {!r}".format(ticket.req_info.message))

        self.binding_out, self.destination = self.IDP.pick_binding("assertion_consumer_service",
                                                                   entity_id = ticket.req_info.message.issuer.text)

        self.logger.debug("Binding: %s, destination: %s" % (self.binding_out, self.destination))
        return True

    def _not_authn(self, ticket, requested_authn_context):
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        :param ticket: SSOLoginData instance
        :param requested_authn_context: saml2.samlp.RequestedAuthnContext instance
        :returns: HTTP response

        :type ticket: SSOLoginData
        :type requested_authn_context: saml2.samlp.RequestedAuthnContext
        :rtype: basestring
        """
        assert isinstance(ticket, SSOLoginData)
        redirect_uri = eduid_idp.mischttp.geturl(query = False)

        self.logger.debug("Do authentication, requested auth context : {!r}".format(requested_authn_context))

        authn_ctx = eduid_idp.assurance.canonical_req_authn_context(requested_authn_context, self.logger)
        auth_info = self.AUTHN_BROKER.pick(authn_ctx)

        if authn_ctx and len(auth_info):
            # `method' is just a no-op (true) value in the way eduid_idp uses the AuthnBroker -
            # filter out the `reference' values (canonical class_ref strings)
            auth_levels = [reference for (method, reference) in auth_info]
            self.logger.debug("Acceptable Authn levels (picked by AuthnBroker) : {!r}".format(auth_levels))

            return self.show_login_page(ticket, auth_levels, redirect_uri)

        raise eduid_idp.error.Unauthorized("No usable authentication method", logger = self.logger)

    def show_login_page(self, ticket, auth_levels, redirect_uri):
        """
        Display the login form for all authentication methods.

        SSO._not_authn() chooses what authentication method to use based on
        requested AuthnContext and local configuration, and then calls this method
        to render the login page for this method.

        :param ticket: SSOLoginData instance
        :param auth_levels: list of strings with auth level names that would be valid for this request
        :param redirect_uri: string with URL to proceed to after authentication
        :returns: HTTP response

        :rtype: basestring
        """
        assert isinstance(ticket, SSOLoginData)

        argv = {
            "action": "/verify",
            "username": "",
            "password": "",
            "key": ticket.key,
            "authn_reference": auth_levels[0],
            "redirect_uri": redirect_uri,
            "alert_msg": "",
            "sp_entity_id": "",
            "failcount": ticket.FailCount,
        }

        # Set alert msg if FailCount is greater than zero
        if ticket.FailCount:
            argv["alert_msg"] = "INCORRECT"  # "Incorrect username or password ({!s} attempts)".format(ticket.FailCount)

        try:
            argv["sp_entity_id"] = ticket.req_info.message.issuer.text
        except KeyError:
            pass

        self.logger.debug("Login page HTML substitution arguments :\n{!s}".format(pprint.pformat(argv)))

        # Look for login page in user preferred language
        content = eduid_idp.mischttp.localized_resource(self.start_response, 'login.html', self.config, self.logger)

        # apply simplistic HTML formatting to template in 'res'
        return content.format(**argv)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def verify_username_and_password(dic, idp_app, min_length=0):
    """
    :param dic: dict() with POST parameters
    :param idp_app: IdPApplication instance
    :param min_length: Minimum required length of password

    :returns: IdPUser instance or False

    :type dic: dict
    :type idp_app: idp.IdPApplication
    :rtype: IdPUser | False
    """
    username = dic["username"]
    password = dic["password"]

    user = idp_app.userdb.verify_username_and_password(username, password)
    if user:
        if len(password) >= min_length:
            return user
        idp_app.logger("User {!r} authenticated, but denied by password length constraints".format(user))
    return False


def do_verify(environ, idp_app):
    """
    Perform authentication of user based on user provided credentials.

    What kind of authentication to perform was chosen by SSO._not_authn() when
    the login web page was to be rendered. It is passed to this function through
    an HTTP POST parameter (authn_reference).

    This function should not be thought of as a "was login successful" or not.
    It will figure out what authentication level to assert based on the authncontext
    requested, and the actual authentication that succeeded.

    :param environ: environ dict() (see eduid_idp.idp._request_environment())
    :param idp_app: IdPApplication instance
    :returns: Does not return
    :raise eduid_idp.mischttp.Redirect: On successful authentication, redirect to redirect_uri.
    """
    query = eduid_idp.mischttp.get_post()

    _loggable = query.copy()
    if 'password' in _loggable:
        _loggable['password'] = '<redacted>'
    idp_app.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(_loggable)))

    idp_app.logger.debug("ENVIRON:\n{!s}".format(pprint.pformat(environ)))

    _ticket = idp_app.IDP.ticket.get_ticket(query)

    user_authn = None
    authn_ref = query.get('authn_reference')
    if authn_ref:
        user_authn = idp_app.get_authn_by_ref(authn_ref)
    if not user_authn:
        raise eduid_idp.error.Unauthorized("Bad authentication reference", logger = idp_app.logger)

    idp_app.logger.debug("Authenticating with {!r} (from authn_reference={!r})".format(
        user_authn['class_ref'], authn_ref))

    try:
        if user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_1_NAME:
            user = verify_username_and_password(query, idp_app)
        elif user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_2_NAME:
            user = verify_username_and_password(query, idp_app, min_length=20)
        else:
            idp_app.logger.info("Authentication for class {!r} not implemented".format(user_authn['class_ref']))
            raise eduid_idp.error.ServiceError("Authentication for class {!r} not implemented".format(
                user_authn['class_ref'], logger=idp_app.logger))
    except Exception:
        idp_app.logger.error("Failed authenticating user", exc_info=1, extra={'stack': True,
                                                                              'request': cherrypy.request,
                                                                              })
        user = None

    if not user:
        _ticket.FailCount += 1
        idp_app.IDP.ticket.store_ticket(_ticket)
        idp_app.logger.info("Unknown user or wrong password")
        _referer = cherrypy.request.headers.get('Referer')
        if _referer:
            raise eduid_idp.mischttp.Redirect(str(_referer))
        raise eduid_idp.error.Unauthorized("Login incorrect", logger = idp_app.logger)

    idp_app.logger.debug("User {!r} authenticated OK using {!r}".format(user, user_authn['class_ref']))
    _data = {'username': user.username,
             'authn_ref': authn_ref,
             'authn_class_ref': user_authn['class_ref'],
             'authn_timestamp': int(time.time()),
             }
    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    _session_id = idp_app.IDP.cache.add_session(user.username, _data)
    idp_app.logger.debug("Registered {!r} under {!r} in IdP SSO sessions".format(user, _session_id))
    eduid_idp.mischttp.set_cookie("idpauthn", idp_app.config.sso_session_lifetime, "/", idp_app.logger, _session_id)

    lox = "%s?id=%s&key=%s" % (query["redirect_uri"], _session_id, query["key"])
    idp_app.logger.debug("Redirect => %s" % lox)
    raise eduid_idp.mischttp.Redirect(lox)


# ----------------------------------------------------------------------------
