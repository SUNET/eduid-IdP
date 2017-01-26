#
# Copyright (c) 2013, 2014, 2016 NORDUnet A/S. All rights reserved.
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

import hmac
import pprint
import time
from hashlib import sha256

import eduid_idp
from eduid_idp.idp_actions import check_for_pending_actions
from eduid_idp.service import Service
from eduid_idp.sso_session import SSOSession
from eduid_idp.loginstate import SSOLoginData
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_HTTP_REDIRECT
from saml2.authn_context import requested_authn_context
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
import lxml.etree as etree


class MustAuthenticate(Exception):
    """
    This exception is raised in special circumstances when the IdP decides
    that a user really must authenticate again, even though there exist an
    SSO session.
    """


# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------


class SSO(Service):
    """
    Single Sign On service.

    :param session: SSO session
    :param start_response: WSGI-like start_response function pointer
    :param idp_app: IdPApplication instance

    :type session: SSOSession | None
    :type start_response: function
    :type idp_app: idp.IdPApplication
    """

    def __init__(self, session, start_response, idp_app):
        Service.__init__(self, session, start_response, idp_app)
        self.binding = ""
        self.binding_out = None
        self.destination = None
        self._idp_app = idp_app

    def perform_login(self, ticket):
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param ticket: Login process state
        :return: Response

        :type ticket: SSOLoginData
        :rtype: string
        """
        assert isinstance(ticket, SSOLoginData)
        assert isinstance(self.sso_session, eduid_idp.sso_session.SSOSession)

        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.perform_login() ---")

        resp_args = self._validate_login_request(ticket)

        user = self.sso_session.idp_user

        check_for_pending_actions(self._idp_app, user, ticket)

        response_authn = self._get_login_response_authn(ticket, user)

        saml_response = self._make_saml_response(resp_args, response_authn, user, ticket)

        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        self.logger.debug("Applying binding_out {!r}, destination {!r}, relay_state {!r}".format(
            self.binding_out, self.destination, ticket.RelayState))
        http_args = self.IDP.apply_binding(self.binding_out, str(saml_response), self.destination,
                                           ticket.RelayState, response = True)

        # INFO-Log the SSO session id and the AL and destination
        self.logger.info("{!s}: response authn={!s}, dst={!s}".format(ticket.key,
                                                                      response_authn['class_ref'],
                                                                      self.destination))
        self._fticks_log(relying_party = resp_args.get('sp_entity_id', self.destination),
                         authn_method = response_authn['class_ref'],
                         user_id = str(user.user_id),
                         )

        return eduid_idp.mischttp.create_html_response(self.binding_out, http_args, self.start_response, self.logger)

    def _make_saml_response(self, resp_args, response_authn, user, ticket):
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param response_authn: pysaml2 response authn info
        :param user: IdP user
        :param ticket: Login process state

        :type resp_args: dict
        :type response_authn: dict
        :type user: eduid_idp.idp_user.IdPUser
        :type ticket: SSOLoginData

        :return: SAML response in lxml format
        """
        attributes = user.to_saml_attributes(self.config, self.logger)
        # Only perform expensive parse/pretty-print if debugging
        if self.config.debug:
            self.logger.debug("Creating an AuthnResponse: user {!r}\n\nAttributes:\n{!s},\n\n"
                              "Response args:\n{!s},\n\nAuthn:\n{!s}\n".format(
                user,
                pprint.pformat(attributes),
                pprint.pformat(resp_args),
                pprint.pformat(response_authn)))
        saml_response = self.IDP.create_authn_response(attributes, userid = user.eppn,
                                                       authn = response_authn, sign_assertion = True,
                                                       **resp_args)
        self._kantara_log_assertion_id(saml_response, ticket)

        return saml_response

    def _kantara_log_assertion_id(self, saml_response, ticket):
        """
        Log the assertion id, which _might_ be required by Kantara.

        :param saml_response: authn response as a compact XML string
        :param ticket: Login process state

        :type saml_response: str | unicode
        :type ticket: SSOLoginData

        :return: None
        """
        # saml_response is a
        printed = False
        try:
            parser = etree.XMLParser(remove_blank_text = True)
            xml = etree.XML(str(saml_response), parser)

            # For debugging, it is very useful to get the full SAML response pretty-printed in the logfile directly
            self.logger.debug("Created AuthNResponse :\n\n{!s}\n\n".format(etree.tostring(xml, pretty_print=True)))
            printed = True

            attrs = xml.attrib
            assertion = xml.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            self.logger.info('{!s}: id={!s}, in_response_to={!s}, assertion_id={!s}'.format(
                ticket.key, attrs['ID'], attrs['InResponseTo'], assertion.get('ID')))

            return etree.tostring(xml, pretty_print = True)
        except Exception as exc:
            self.logger.debug("Could not parse message as XML: {!r}".format(exc))
            if not printed:
                # Fall back to logging the whole response
                self.logger.info("{!s}: authn response: {!s}".format(ticket.key, saml_response))

    def _fticks_log(self, relying_party, authn_method, user_id):
        """
        Perform SAML F-TICKS logging, for statistics in the SWAMID federation.

        :param relying_party: The entity id of the relying party (SP).
        :param authn_method: The URN of the authentication method used.
        :param user_id: Unique user id.

        :type relying_party: string
        :type authn_method: string
        :type user_id: string
        :return: None
        """
        if not self.config.fticks_secret_key:
            return
        # Default format string:
        #   'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#',
        _timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        _anon_userid = hmac.new(self.config.fticks_secret_key, msg=user_id, digestmod=sha256).digest().encode('hex')
        msg = self.config.fticks_format_string.format(ts=_timestamp,
                                                      rp=relying_party,
                                                      ap=self.IDP.config.entityid,
                                                      pn=_anon_userid,
                                                      am=authn_method,
                                                      )
        self.logger.info(msg)

    def _validate_login_request(self, ticket):
        """
        Validate the validity of the SAML request we are going to answer with
        an assertion.

        Checks that the SP is known through metadata.

        Figures out how to respond to this request. Return a dictionary like

          {'destination': 'https://sp.example.org/saml2/acs/',
           'name_id_policy': <saml2.samlp.NameIDPolicy object>,
           'sp_entity_id': 'https://sp.example.org/saml2/metadata/',
           'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
           'in_response_to': 'id-4c45b079f571c57aef34aaaaac4295c9'
           }

        :param ticket: State for this request
        :return: pysaml2 response creation data

        :type ticket: SSOLoginData
        :rtype: dict
        """
        self.logger.debug("Validate login request :\n{!s}".format(str(ticket)))
        try:
            if not self._verify_request(ticket):
                raise eduid_idp.error.ServiceError(logger = self.logger)  # not reached
            resp_args = self.IDP.response_args(ticket.req_info.message)
        except UnknownPrincipal as excp:
            self.logger.info("{!s}: Unknown service provider: {!s}".format(ticket.key, excp))
            raise eduid_idp.error.BadRequest("Don't know the SP that referred you here", logger = self.logger)
        except UnsupportedBinding as excp:
            self.logger.info("{!s}: Unsupported SAML binding: {!s}".format(ticket.key, excp))
            raise eduid_idp.error.BadRequest("Don't know how to reply to the SP that referred you here",
                                             logger = self.logger)
        return resp_args

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

    def _get_login_response_authn(self, ticket, user):
        """
        Figure out what AuthnContext to assert in the SAML response.

        The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

        What AuthnContext is asserted is also heavily influenced by what the SP requested.

        Returns a pysaml2-style dictionary like

            {'authn_auth': u'https://idp.example.org/idp.xml',
             'authn_instant': 1391678156,
             'class_ref': 'http://www.swamid.se/policy/assurance/al1'
             }

        :param ticket: State for this request
        :param user: The user for whom the assertion will be made
        :return: Authn information (pysaml2 style)

        :type ticket: SSOLoginData
        :type user: IdPUser
        :rtype: dict
        """
        session_authn = self.sso_session.get_authn_context(self.AUTHN_BROKER, logger=self.logger)
        self.logger.debug("User authenticated using Authn {!r}".format(session_authn))
        if not session_authn:
            # This could happen with SSO sessions refering to old authns during
            # reconfiguration of authns in the AUTHN_BROKER.
            raise eduid_idp.error.ServiceError('Unknown stored AuthnContext')

        # Decide what AuthnContext to assert based on the one requested in the request
        # and the authentication performed
        req_authn_context = self._get_requested_authn_context(ticket)

        # XXX loop though the list of all authn_context_class_ref!
        auth_levels = self._get_acceptable_auth_levels(req_authn_context)
        try:
            response_authn = eduid_idp.assurance.response_authn(req_authn_context, session_authn, auth_levels,
                                                                self.logger)
        except eduid_idp.error.Forbidden:
            # The level of authentication was not sufficient for the requested AuthnContext.
            raise MustAuthenticate()

        self.logger.debug("Response Authn: {!r}".format(response_authn))

        # Apply application logic to determine if this IdP is willing to assert the response_authn
        # AuthnContext for this particular user.
        if not eduid_idp.assurance.permitted_authn(user, response_authn, self.logger):
            # XXX should return a login failure SAML response instead of an error in the IdP here.
            # The SP could potentially help the user much better than the IdP here.
            raise eduid_idp.error.Forbidden("Authn not permitted".format())

        try:
            self.logger.debug("Asserting AuthnContext {!r} (requested: {!r})".format(
                response_authn['class_ref'], req_authn_context.authn_context_class_ref[0].text))
        except AttributeError:
            self.logger.debug("Asserting AuthnContext {!r} (none requested)".format(response_authn['class_ref']))

        response_authn['authn_instant'] = self.sso_session.authn_timestamp

        return response_authn

    def _get_acceptable_auth_levels(self, req_authn_context):
        """
        Use the AUTHN_BROKER to decide what authentication levels are acceptable given a
        RequestedAuthnContext.

        The return value is a list of our `internal' levels, e.g.

            ['eduid.se:level:1', 'eduid.se:level:2', 'eduid.se:level:3']
               if 'http://www.swamid.se/policy/assurance/al1' is requested

            ['eduid.se:level:2', 'eduid.se:level:3']
               if 'http://www.swamid.se/policy/assurance/al2' is requested

        :param req_authn_context: Requested Authn Context
        :return: List with names of acceptable authn levels

        :type req_authn_context: saml2.samlp.RequestedAuthnContext
        :rtype: [string]
        """
        authn_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_context, self.logger)
        auth_info = self.AUTHN_BROKER.pick(authn_ctx)
        auth_levels = []
        if authn_ctx and len(auth_info):
            # `method' is just a no-op (true) value in the way eduid_idp uses the AuthnBroker -
            # filter out the `reference' values (canonical class_ref strings)
            levels_dict = {}
            # Turn references (e.g. 'eduid:level:1:100') into base levels (e.g. 'eduid:level:1')
            for (method, reference) in auth_info:
                this = self.AUTHN_BROKER[reference]
                levels_dict[this['class_ref']] = 1
            auth_levels = sorted(levels_dict.keys())
        self.logger.debug("Acceptable Authn levels considering requested AuthnContext "
                          "(picked by AuthnBroker): {!r}".format(auth_levels))
        return auth_levels

    def _get_requested_authn_context(self, ticket):
        """
        Check if this SP has explicit Authn preferences in the metadata (some SPs are not
        capable of conveying this preference in the RequestedAuthnContext)

        :param ticket: State for this request
        :return: Requested Authn Context

        :type ticket: SSOLoginData
        :rtype: RequestedAuthnContext
        """
        req_authn_context = ticket.req_info.message.requested_authn_context
        try:
            attributes = self.IDP.metadata.entity_attributes(ticket.req_info.message.issuer.text)
        except KeyError:
            attributes = {}
        if 'http://www.swamid.se/assurance-requirement' in attributes:
            # XXX don't just pick the first one from the list - choose the most applicable one somehow.
            new_authn = attributes['http://www.swamid.se/assurance-requirement'][0]
            requested = None
            if req_authn_context and req_authn_context.authn_context_class_ref:
                requested = req_authn_context.authn_context_class_ref[0].text
            self.logger.debug("Entity {!r} has AuthnCtx preferences in metadata. Overriding {!r} -> {!r}".format(
                ticket.req_info.message.issuer.text,
                requested,
                new_authn))
            req_authn_context = requested_authn_context(new_authn)
        return req_authn_context

    def redirect(self):
        """ This is the HTTP-redirect endpoint.

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        ticket = self.IDP.ticket.get_ticket(_info, binding=BINDING_HTTP_REDIRECT)
        return self._redirect_or_post(ticket)

    def post(self):
        """
        The HTTP-Post endpoint

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        ticket = self.IDP.ticket.get_ticket(_info, binding=BINDING_HTTP_POST)
        return self._redirect_or_post(ticket)

    def _redirect_or_post(self, ticket):
        """
        Common code for redirect() and post() endpoints.

        :type ticket: SSOLoginData

        :rtype: string
        """
        _force_authn = self._should_force_authn(ticket)
        if self.sso_session and not _force_authn:
            _ttl = self.config.sso_session_lifetime - self.sso_session.minutes_old
            self.logger.info("{!s}: proceeding sso_session={!s}, ttl={:}m".format(
                ticket.key, self.sso_session.public_id, _ttl))
            self.logger.debug("Continuing with Authn request {!r}".format(ticket.req_info))
            try:
                return self.perform_login(ticket)
            except MustAuthenticate:
                _force_authn = True

        if not self.sso_session:
            self.logger.info("{!s}: authenticate ip={!s}".format(ticket.key, eduid_idp.mischttp.get_remote_ip()))
        elif _force_authn:
            self.logger.info("{!s}: force_authn sso_session={!s}".format(
                ticket.key, self.sso_session.public_id))

        req_authn_context = self._get_requested_authn_context(ticket)
        return self._not_authn(ticket, req_authn_context)

    def _should_force_authn(self, ticket):
        """
        Check if the IdP should force authentication of this request.

        Will check SAML ForceAuthn but avoid endless loops of forced authentications
        by looking if the SSO session says authentication was actually performed
        based on this SAML request.

        :type ticket: SSOLoginData
        :rtype: bool
        """
        if ticket.req_info.message.force_authn:
            if not self.sso_session:
                self.logger.debug("Force authn without session - ignoring")
                return True
            if ticket.req_info.message.id != self.sso_session.user_authn_request_id:
                self.logger.debug("Forcing authentication because of ForceAuthn with "
                                  "SSO session id {!r} != {!r}".format(
                                  self.sso_session.user_authn_request_id, ticket.req_info.message.id))
                return True
            self.logger.debug("Ignoring ForceAuthn, authn already performed for SAML request {!r}".format(
                ticket.req_info.message.id))
        return False

    def _not_authn(self, ticket, requested_authn_context):
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        :param ticket: SSOLoginData instance
        :param requested_authn_context: saml2.samlp.RequestedAuthnContext instance
        :returns: HTTP response

        :type ticket: SSOLoginData
        :type requested_authn_context: saml2.samlp.RequestedAuthnContext
        :rtype: string
        """
        assert isinstance(ticket, SSOLoginData)
        redirect_uri = eduid_idp.mischttp.geturl(self.config, query = False)

        self.logger.debug("Do authentication, requested auth context : {!r}".format(requested_authn_context))

        authn_ctx = eduid_idp.assurance.canonical_req_authn_context(requested_authn_context, self.logger)
        auth_info = self.AUTHN_BROKER.pick(authn_ctx)

        if authn_ctx and len(auth_info):
            # `method' is just a no-op (true) value in the way eduid_idp uses the AuthnBroker -
            # filter out the `reference' values (canonical class_ref strings)
            auth_levels = [reference for (method, reference) in auth_info]
            self.logger.debug("Acceptable Authn levels (picked by AuthnBroker) : {!r}".format(auth_levels))

            return self._show_login_page(ticket, auth_levels, redirect_uri)

        raise eduid_idp.error.Unauthorized("No usable authentication method", logger = self.logger)

    def _show_login_page(self, ticket, auth_levels, redirect_uri):
        """
        Display the login form for all authentication methods.

        SSO._not_authn() chooses what authentication method to use based on
        requested AuthnContext and local configuration, and then calls this method
        to render the login page for this method.

        :param ticket: Login session state (not SSO session state)
        :param auth_levels: list of strings with auth level names that would be valid for this request
        :param redirect_uri: string with URL to proceed to after authentication
        :return: HTTP response

        :type ticket: SSOLoginData

        :rtype: string
        """
        assert isinstance(ticket, SSOLoginData)

        argv = eduid_idp.mischttp.get_default_template_arguments(self.config)
        argv.update({
            "action": "/verify",
            "username": "",
            "password": "",
            "key": ticket.key,
            "authn_reference": auth_levels[0],
            "redirect_uri": redirect_uri,
            "alert_msg": "",
            "sp_entity_id": "",
            "failcount": ticket.FailCount,
            "password_reset_link": self.config.password_reset_link,
            # SAMLRequest, RelayState and binding are used to re-create the ticket state if not found using `key'
            "SAMLRequest": ticket.SAMLRequest,
            "RelayState": ticket.RelayState,
            "binding": ticket.binding,
        })

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
        if not content:
            raise eduid_idp.error.NotFound()

        # apply simplistic HTML formatting to template in 'res'
        return content.format(**argv)


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def do_verify(idp_app):
    """
    Perform authentication of user based on user provided credentials.

    What kind of authentication to perform was chosen by SSO._not_authn() when
    the login web page was to be rendered. It is passed to this function through
    an HTTP POST parameter (authn_reference).

    This function should not be thought of as a "was login successful" or not.
    It will figure out what authentication level to assert based on the authncontext
    requested, and the actual authentication that succeeded.

    :param idp_app: IdPApplication instance
    :return: Does not return
    :raise eduid_idp.mischttp.Redirect: On successful authentication, redirect to redirect_uri.

    :type idp_app: idp.IdPApplication
    """
    query = eduid_idp.mischttp.get_post()
    # extract password to keep it away from as much code as possible
    password = query.get('password')
    _loggable = query.copy()
    if password:
        del query['password']
        _loggable['password'] = '<redacted>'
    idp_app.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(_loggable)))

    _ticket = idp_app.IDP.ticket.get_ticket(query)

    user_authn = None
    authn_ref = query.get('authn_reference')
    if authn_ref:
        user_authn = eduid_idp.assurance.get_authn_context(idp_app.AUTHN_BROKER, authn_ref)
    if not user_authn:
        raise eduid_idp.error.Unauthorized("Bad authentication reference", logger = idp_app.logger)

    idp_app.logger.debug("Authenticating with {!r} (from authn_reference={!r})".format(
        user_authn['class_ref'], authn_ref))

    if not password or 'username' not in query:
        raise eduid_idp.error.Unauthorized("Credentials not supplied", logger = idp_app.logger)

    login_data = {'username': query['username'].strip(),
                  'password': password,
                  }
    del password  # keep out of any exception logs
    user = idp_app.authn.get_authn_user(login_data, user_authn)

    if not user:
        _ticket.FailCount += 1
        idp_app.IDP.ticket.store_ticket(_ticket)
        idp_app.logger.debug("Unknown user or wrong password")
        _referer = eduid_idp.mischttp.get_request_header().get('Referer')
        if _referer:
            raise eduid_idp.mischttp.Redirect(str(_referer))
        raise eduid_idp.error.Unauthorized("Login incorrect", logger = idp_app.logger)

    # Create SSO session
    idp_app.logger.debug("User {!r} authenticated OK using {!r}".format(user, user_authn['class_ref']))
    _sso_session = SSOSession(user_id = user.user_id,
                              authn_ref = authn_ref,
                              authn_class_ref = user_authn['class_ref'],
                              authn_request_id = _ticket.req_info.message.id,
                              )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    _session_id = idp_app.IDP.cache.add_session(user.user_id, _sso_session.to_dict())
    eduid_idp.mischttp.set_cookie("idpauthn", "/", idp_app.logger, idp_app.config, _session_id)
    # knowledge of the _session_id enables impersonation, so get rid of it as soon as possible
    del _session_id

    # INFO-Log the request id (sha1 of SAMLrequest) and the sso_session
    idp_app.logger.info("{!s}: login sso_session={!s}, authn={!s}, user={!s}".format(
        query['key'], _sso_session.public_id,
        _sso_session.user_authn_class_ref,
        user))

    # Now that an SSO session has been created, redirect the users browser back to
    # the main entry point of the IdP (the 'redirect_uri'). The ticket reference `key'
    # is passed as an URL parameter instead of the SAMLRequest.
    lox = query["redirect_uri"] + '?key=' + query['key']
    idp_app.logger.debug("Redirect => %s" % lox)
    raise eduid_idp.mischttp.Redirect(lox)


# ----------------------------------------------------------------------------
