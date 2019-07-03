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
from dataclasses import replace
from hashlib import sha256
from typing import Callable, Mapping, Optional

import cherrypy
from defusedxml import ElementTree as DefusedElementTree

import eduid_idp
from eduid_idp.assurance import AssuranceException, MissingMultiFactor, WrongMultiFactor
from eduid_common.session.idp_cache import ExpiringCache
from eduid_idp.context import IdPContext
from eduid_idp.idp_actions import check_for_pending_actions
from eduid_common.authn.idp_saml import AuthnInfo, IdP_SAMLRequest, ResponseArgs, parse_SAMLRequest
from eduid_idp.idp_user import IdPUser
from eduid_common.session.loginstate import SSOLoginData
from eduid_idp.service import Service
from eduid_idp.sso_session import SSOSession
from eduid_idp.util import get_requested_authn_context
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT


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

    :param sso_session: SSO session
    :param start_response: WSGI-like start_response function pointer
    :param context: IdP context
    """

    def __init__(self, sso_session: SSOSession, start_response: Callable, context: IdPContext):
        super().__init__(sso_session, start_response, context)

    def perform_login(self, ticket: SSOLoginData) -> bytes:
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param ticket: Login process state
        :return: Response
        """
        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.perform_login() ---")

        assert isinstance(self.sso_session, eduid_idp.sso_session.SSOSession)

        user = self.sso_session.idp_user

        resp_args = self._validate_login_request(ticket)

        if self.context.common_sessions is not None:
            cherrypy.session['user_eppn'] = user.eppn

        check_for_pending_actions(self.context, user, ticket, self.sso_session)
        # We won't get here until the user has completed all login actions

        #  if self.context.common_sessions is not None:
        #      cherrypy.request.session['is_logged_in'] = True
        #      cherrypy.request.session.commit()

        response_authn = self._get_login_response_authn(ticket, user)

        saml_response = self._make_saml_response(response_authn, resp_args, user, ticket, self.sso_session)

        binding_out = resp_args['binding_out']
        destination = resp_args['destination']
        http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, str(saml_response))

        # INFO-Log the SSO session id and the AL and destination
        self.logger.info('{!s}: response authn={!s}, dst={!s}'.format(ticket.key,
                                                                      response_authn,
                                                                      destination))
        self._fticks_log(relying_party = resp_args.get('sp_entity_id', destination),
                         authn_method = response_authn.class_ref,
                         user_id = str(user.user_id),
                         )

        return eduid_idp.mischttp.create_html_response(binding_out, http_args, self.start_response, self.logger)

    def _make_saml_response(self, response_authn: AuthnInfo, resp_args: ResponseArgs,
                            user: IdPUser, ticket: SSOLoginData, sso_session):
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param user: IdP user
        :param ticket: Login process state

        :return: SAML response in lxml format
        """
        attributes = user.to_saml_attributes(self.config, self.logger)
        # Add a list of credentials used in a private attribute that will only be
        # released to the eduID authn component
        attributes['eduidIdPCredentialsUsed'] = [x['cred_id'] for x in sso_session.authn_credentials]
        for k, v in response_authn.authn_attributes.items():
            if k in attributes:
                self.logger.debug('Overwriting user attribute {} ({!r}) with authn attribute value {!r}'.format(
                    k, attributes[k], v
                ))
            else:
                self.logger.debug('Adding attribute {} with value from authn process: {}'.format(k, v))
            attributes[k] = v
        # Only perform expensive parse/pretty-print if debugging
        if self.config.debug:
            self.logger.debug("Creating an AuthnResponse: user {!r}\n\nAttributes:\n{!s},\n\n"
                              "Response args:\n{!s},\n\nAuthn:\n{!s}\n".format(
                user,
                pprint.pformat(attributes),
                pprint.pformat(resp_args),
                pprint.pformat(response_authn)))

#        saml_response = self.context.idp.create_authn_response(attributes, userid = user.eppn,
#                                                               authn = response_authn, sign_response = True,
#                                                               **resp_args)
        saml_response = ticket.saml_req.make_saml_response(attributes, user.eppn, response_authn, resp_args)
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
        printed = False
        try:
            parser = DefusedElementTree.DefusedXMLParser()
            xml = DefusedElementTree.XML(str(saml_response), parser)

            # For debugging, it is very useful to get the full SAML response pretty-printed in the logfile directly
            self.logger.debug("Created AuthNResponse :\n\n{!s}\n\n".format(DefusedElementTree.tostring(xml)))
            printed = True

            attrs = xml.attrib
            assertion = xml.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
            self.logger.info('{!s}: id={!s}, in_response_to={!s}, assertion_id={!s}'.format(
                ticket.key, attrs['ID'], attrs['InResponseTo'], assertion.get('ID')))

            return DefusedElementTree.tostring(xml)
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
        _anon_userid = hmac.new(self.config.fticks_secret_key.encode('ascii'),
                                msg=user_id.encode('ascii'), digestmod=sha256).hexdigest()
        msg = self.config.fticks_format_string.format(ts=_timestamp,
                                                      rp=relying_party,
                                                      ap=self.context.idp.config.entityid,
                                                      pn=_anon_userid,
                                                      am=authn_method,
                                                      )
        self.logger.info(msg)

    def _validate_login_request(self, ticket: SSOLoginData) -> ResponseArgs:
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

        but we dress it up as a ResponseArgs to allow type checking to ensure
        it is used with the right functions later.

        :param ticket: State for this request
        :return: pysaml2 response creation data
        """
        assert isinstance(ticket, SSOLoginData)
        self.logger.debug("Validate login request :\n{!s}".format(ticket))
        self.logger.debug("AuthnRequest from ticket: {!r}".format(ticket.saml_req))
        return ticket.saml_req.get_response_args(eduid_idp.error.BadRequest, ticket.key)

    def _get_login_response_authn(self, ticket: SSOLoginData, user: IdPUser) -> AuthnInfo:
        """
        Figure out what AuthnContext to assert in the SAML response.

        The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

        What AuthnContext is asserted is also heavily influenced by what the SP requested.

        :param ticket: State for this request
        :param user: The user for whom the assertion will be made
        :return: Authn information
        """
        self.logger.debug('MFA credentials logged in the ticket: {}'.format(ticket.mfa_action_creds))
        self.logger.debug('External MFA credential logged in the ticket: {}'.format(ticket.mfa_action_external))
        self.logger.debug('Credentials used in this SSO session:\n{}'.format(self.sso_session.authn_credentials))
        self.logger.debug('User credentials:\n{}'.format(user.credentials.to_list()))

        # Decide what AuthnContext to assert based on the one requested in the request
        # and the authentication performed

        req_authn_context = get_requested_authn_context(self.context.idp, ticket.saml_req, self.logger)

        try:
            resp_authn = eduid_idp.assurance.response_authn(req_authn_context, user, self.sso_session, self.logger)
        except WrongMultiFactor as exc:
            self.logger.info('Assurance not possible: {!r}'.format(exc))
            raise eduid_idp.error.Forbidden('SWAMID_MFA_REQUIRED')
        except MissingMultiFactor as exc:
            self.logger.info('Assurance not possible: {!r}'.format(exc))
            raise eduid_idp.error.Forbidden('MFA_REQUIRED')
        except AssuranceException as exc:
            self.logger.info('Assurance not possible: {!r}'.format(exc))
            raise MustAuthenticate()

        self.logger.debug("Response Authn context class: {!r}".format(resp_authn))

        try:
            self.logger.debug("Asserting AuthnContext {!r} (requested: {!r})".format(
                resp_authn, req_authn_context))
        except AttributeError:
            self.logger.debug("Asserting AuthnContext {!r} (none requested)".format(resp_authn))

        # Augment the AuthnInfo with the authn_timestamp before returning it
        return replace(resp_authn, instant=self.sso_session.authn_timestamp)


    def redirect(self) -> bytes:
        """ This is the HTTP-redirect endpoint.

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        ticket = _get_ticket(self.context, _info, BINDING_HTTP_REDIRECT)
        return self._redirect_or_post(ticket)

    def post(self) -> bytes:
        """
        The HTTP-Post endpoint

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        ticket = _get_ticket(self.context, _info, BINDING_HTTP_POST)
        return self._redirect_or_post(ticket)

    def _redirect_or_post(self, ticket: SSOLoginData) -> bytes:
        """ Common code for redirect() and post() endpoints. """
        _force_authn = self._should_force_authn(ticket)
        if self.sso_session and not _force_authn:
            _ttl = self.context.config.sso_session_lifetime - self.sso_session.minutes_old
            self.logger.info("{!s}: proceeding sso_session={!s}, ttl={:}m".format(
                ticket.key, self.sso_session.public_id, _ttl))
            self.logger.debug(f'Continuing with Authn request {repr(ticket.saml_req.request_id)}')
            try:
                return self.perform_login(ticket)
            except MustAuthenticate:
                _force_authn = True

        if not self.sso_session:
            self.logger.info("{!s}: authenticate ip={!s}".format(ticket.key, eduid_idp.mischttp.get_remote_ip()))
        elif _force_authn:
            self.logger.info("{!s}: force_authn sso_session={!s}".format(
                ticket.key, self.sso_session.public_id))

        return self._not_authn(ticket)

    def _should_force_authn(self, ticket: SSOLoginData) -> bool:
        """
        Check if the IdP should force authentication of this request.

        Will check SAML ForceAuthn but avoid endless loops of forced authentications
        by looking if the SSO session says authentication was actually performed
        based on this SAML request.
        """
        if ticket.saml_req.force_authn:
            if not self.sso_session:
                self.logger.debug("Force authn without session - ignoring")
                return True
            if ticket.saml_req.request_id != self.sso_session.user_authn_request_id:
                self.logger.debug("Forcing authentication because of ForceAuthn with "
                                  "SSO session id {!r} != {!r}".format(
                    self.sso_session.user_authn_request_id, ticket.saml_req.request_id))
                return True
            self.logger.debug("Ignoring ForceAuthn, authn already performed for SAML request {!r}".format(
                ticket.saml_req.request_id))
        return False

    def _not_authn(self, ticket: SSOLoginData) -> bytes:
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        :param ticket: SSOLoginData instance
        :returns: HTTP response
        """
        assert isinstance(ticket, SSOLoginData)
        redirect_uri = eduid_idp.mischttp.geturl(self.config, query = False)

        req_authn_context = get_requested_authn_context(self.context.idp, ticket.saml_req, self.logger)
        self.logger.debug("Do authentication, requested auth context : {!r}".format(req_authn_context))

        return self._show_login_page(ticket, req_authn_context, redirect_uri)

    def _show_login_page(self, ticket: SSOLoginData, requested_authn_context: Optional[str], redirect_uri) -> bytes:
        """
        Display the login form for all authentication methods.

        SSO._not_authn() chooses what authentication method to use based on
        requested AuthnContext and local configuration, and then calls this method
        to render the login page for this method.

        :param ticket: Login session state (not SSO session state)
        :param requested_authn_context: Requested authentication context class
        :param redirect_uri: string with URL to proceed to after authentication

        :return: HTTP response
        """
        argv = eduid_idp.mischttp.get_default_template_arguments(self.context.config)
        argv.update({
            "action": "/verify",
            "username": "",
            "password": "",
            "key": ticket.key,
            "authn_reference": requested_authn_context,
            "redirect_uri": redirect_uri,
            "alert_msg": "",
            "sp_entity_id": "",
            "failcount": ticket.FailCount,
            # SAMLRequest, RelayState and binding are used to re-create the ticket state if not found using `key'
            "SAMLRequest": ticket.SAMLRequest,
            "RelayState": ticket.RelayState,
            "binding": ticket.binding,
        })

        # Set alert msg if FailCount is greater than zero
        if ticket.FailCount:
            argv["alert_msg"] = "INCORRECT"  # "Incorrect username or password ({!s} attempts)".format(ticket.FailCount)

        try:
            argv["sp_entity_id"] = ticket.saml_req.sp_entity_id
        except KeyError:
            pass

        self.logger.debug("Login page HTML substitution arguments :\n{!s}".format(pprint.pformat(argv)))

        # Look for login page in user preferred language
        content = eduid_idp.mischttp.localized_resource(self.start_response, 'login.html', self.config, self.logger)
        if not content:
            raise eduid_idp.error.NotFound()

        # apply simplistic HTML formatting to template in 'res'
        return content.format(**argv).encode('utf-8')


# -----------------------------------------------------------------------------
# === Authentication ====
# -----------------------------------------------------------------------------


def do_verify(context: IdPContext):
    """
    Perform authentication of user based on user provided credentials.

    What kind of authentication to perform was chosen by SSO._not_authn() when
    the login web page was to be rendered. It is passed to this function through
    an HTTP POST parameter (authn_reference).

    This function should not be thought of as a "was login successful" or not.
    It will figure out what authentication level to assert based on the authncontext
    requested, and the actual authentication that succeeded.

    :return: Does not return
    :raise eduid_idp.mischttp.Redirect: On successful authentication, redirect to redirect_uri.
    """
    query = eduid_idp.mischttp.get_post(context.logger)
    # extract password to keep it away from as much code as possible
    password = query.pop('password', None)
    if password:
        query['password'] = '<redacted>'
    context.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(query)))

    _ticket = _get_ticket(context, query, None)

    authn_ref = _ticket.saml_req.get_requested_authn_context()
    context.logger.debug("Authenticating with {!r}".format(authn_ref))

    if not password or 'username' not in query:
        lox = f'{query["redirect_uri"]}?{_ticket.query_string}'
        context.logger.debug(f'Credentials not supplied. Redirect => {lox}')
        raise eduid_idp.mischttp.Redirect(lox)

    login_data = {'username': query['username'].strip(),
                  'password': password,
                  }
    del password  # keep out of any exception logs
    authninfo = context.authn.password_authn(login_data)

    if not authninfo:
        _ticket.FailCount += 1
        cherrypy.session.sso_ticket = _ticket
        lox = f'{query["redirect_uri"]}?{_ticket.query_string}'
        context.logger.debug(f'Unknown user or wrong password. Redirect => {lox}')
        raise eduid_idp.mischttp.Redirect(lox)

    # Create SSO session
    user = authninfo.user
    context.logger.debug("User {} authenticated OK".format(user))
    _sso_session = SSOSession(user_id = user.user_id,
                              authn_request_id = _ticket.saml_req.request_id,
                              authn_credentials = [authninfo],
                              )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    _session_id = context.sso_sessions.add_session(user.user_id, _sso_session.to_dict())
    eduid_idp.mischttp.set_cookie('idpauthn', '/', context.logger, context.config, _session_id.decode('utf-8'))
    # knowledge of the _session_id enables impersonation, so get rid of it as soon as possible
    del _session_id

    # INFO-Log the request id (sha1 of SAMLrequest) and the sso_session
    context.logger.info("{!s}: login sso_session={!s}, authn={!s}, user={!s}".format(
        _ticket.key, _sso_session.public_id, authn_ref, user))

    # Now that an SSO session has been created, redirect the users browser back to
    # the main entry point of the IdP (the 'redirect_uri'). The ticket reference `key'
    # is passed as an URL parameter instead of the SAMLRequest.
    lox = query["redirect_uri"] + '?key=' + _ticket.key
    context.logger.debug("Redirect => %s" % lox)
    raise eduid_idp.mischttp.Redirect(lox)


# ----------------------------------------------------------------------------
def _get_ticket(context: IdPContext, info: Mapping, binding: Optional[str]) -> SSOLoginData:
    logger = context.logger

    ticket = cherrypy.session.sso_ticket

    if not info:
        raise eduid_idp.error.BadRequest('Bad request, please re-initiate login', logger=logger)
    _key = info.get('key')
    if not _key:
        if 'SAMLRequest' not in info:
            raise eduid_idp.error.BadRequest('Missing SAMLRequest, please re-initiate login',
                                             logger = logger, extra = {'info': info, 'binding': binding})
        _key = ExpiringCache.key(info['SAMLRequest'])
        logger.debug(f"No 'key' in info, hashed SAMLRequest into key {_key}")

        if ticket and _key != ticket.key:
            raise eduid_idp.error.BadRequest('Corrupted SAMLRequest, please re-initiate login',
                                             logger = logger, extra = {'info': info, 'binding': binding})

    if not ticket:
        # cache miss, parse SAMLRequest
        if binding is None:
            binding = info['binding']
        if binding is None:
            raise eduid_idp.error.BadRequest('Bad request, no binding')
        ticket = _create_ticket(context, info, binding, _key)
        cherrypy.session.sso_ticket = ticket

    return ticket


def _create_ticket(context: IdPContext, info: Mapping, binding: str, key: str) -> SSOLoginData:
    """
    Create an SSOLoginData instance from a dict.

    The dict must contain SAMLRequest and is typically

    {'RelayState': '/path',
     'SAMLRequest': 'nVLB...==',
     ...
    }

    :param info: dict containing at least `SAMLRequest' and `key'.
    :param binding: SAML2 binding as string (typically a URN)
    :returns: SSOLoginData instance
    """
    if not binding:
        raise eduid_idp.error.ServiceError("Can't create IdP ticket with unknown binding", logger = context.logger)
    saml_req = _parse_SAMLRequest(context, info, binding)
    ticket = SSOLoginData(key, saml_req,
                          info.get('RelayState', ''),
                          int(info.get('FailCount', 0)),
                          )
    context.logger.debug("Created new login state (IdP ticket) for request {!s}".format(key))
    return ticket


def _parse_SAMLRequest(context: IdPContext, info: Mapping, binding: str) -> IdP_SAMLRequest:
    return parse_SAMLRequest(info, binding, context.logger, context.idp, eduid_idp.error.BadRequest,
                             context.config.debug, context.config.verify_request_signatures)
