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
from typing import Optional, Callable

import eduid_idp
from eduid_idp.authn import IdPAuthn
from eduid_idp.cache import ExpiringCache
from eduid_idp.context import IdPContext
from eduid_idp.idp_actions import check_for_pending_actions
from eduid_idp.idp_user import IdPUser
from eduid_idp.idp_session import IdPSession, IdPSessionData
from eduid_idp.service import Service
from eduid_idp.sso_state import SSOState
from eduid_idp.loginstate import SSOLoginData
from eduid_idp.assurance import AssuranceException, WrongMultiFactor, MissingMultiFactor
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.s_utils import UnknownPrincipal, UnsupportedBinding, UnknownSystemEntity, UnravelError
from saml2.sigver import verify_redirect_signature
from saml2.request import AuthnRequest
from defusedxml import ElementTree as DefusedElementTree


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

    :param start_response: WSGI-like start_response function pointer
    """

    def __init__(self, session: IdPSession, state: SSOState, start_response: Callable, context: IdPContext):
        super().__init__(session, state, start_response, context)

    def perform_login(self, idp_data: IdPSessionData) -> str:
        """
        Validate request, and then proceed with creating an AuthnResponse and
        invoking the 'outgoing' SAML2 binding.

        :param idp_data: Login process state
        :return: Response
        """
        self.logger.debug("\n\n---\n\n")
        self.logger.debug("--- In SSO.perform_login() ---")

        user = self.sso_state.idp_user

        resp_args = self._validate_login_request(idp_data)
        binding_out = resp_args.get('binding_out')
        destination = resp_args.get('destination')

        check_for_pending_actions(self.context, user, idp_data, self.sso_state)
        # We won't get here until the user has completed all login actions

        response_authn = self._get_login_response_authn(idp_data, user)

        saml_response = self._make_saml_response(resp_args, response_authn, user, idp_data, self.session)

        # Create the Javascript self-posting form that will take the user back to the SP
        # with a SAMLResponse
        self.logger.debug('Applying binding_out {!r}, destination {!r}, relay_state {!r}'.format(
            binding_out, destination, idp_data.RelayState))
        http_args = self.context.idp.apply_binding(binding_out, str(saml_response), destination,
                                                   idp_data.RelayState, response = True)

        # INFO-Log the SSO session id and the AL and destination
        self.logger.info('{!s}: response authn={!s}, dst={!s}'.format(idp_data.sso_db_key,
                                                                      response_authn,
                                                                      destination))
        self._fticks_log(relying_party = resp_args.get('sp_entity_id', destination),
                         authn_method = response_authn['class_ref'],
                         user_id = str(user.user_id),
                         )

        return eduid_idp.mischttp.create_html_response(binding_out, http_args, self.start_response, self.logger)

    def _make_saml_response(self, resp_args: dict, response_authn: dict, user: IdPUser,
                            idp_data: IdPSessionData, sso_session):
        """
        Create the SAML response using pysaml2 create_authn_response().

        :param resp_args: pysaml2 response arguments
        :param response_authn: Response authn context class information
        :param user: IdP user
        :param idp_data: Login process state

        :type resp_args: dict
        :type response_authn: dict

        :return: SAML response in lxml format
        """
        attributes = user.to_saml_attributes(self.config, self.logger)
        # Add a list of credentials used in a private attribute that will only be
        # released to the eduID authn component
        attributes['eduidIdPCredentialsUsed'] = [x['cred_id'] for x in sso_session.authn_credentials]
        for k,v in response_authn.pop('authn_attributes', {}).items():
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
        saml_response = self.context.idp.create_authn_response(attributes, userid = user.eppn,
                                                               authn = response_authn, sign_response = True,
                                                               **resp_args)
        self._kantara_log_assertion_id(saml_response, idp_data)

        return saml_response

    def _kantara_log_assertion_id(self, saml_response: str, idp_data: IdPSessionData) -> None:
        """
        Log the assertion id, which _might_ be required by Kantara.

        :param saml_response: authn response as a compact XML string
        :param idp_data: Login process state

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
                idp_data.sso_db_key, attrs['ID'], attrs['InResponseTo'], assertion.get('ID')))

            return DefusedElementTree.tostring(xml)
        except Exception as exc:
            self.logger.debug("Could not parse message as XML: {!r}".format(exc))
            if not printed:
                # Fall back to logging the whole response
                self.logger.info("{!s}: authn response: {!s}".format(idp_data.sso_db_key, saml_response))

    def _fticks_log(self, relying_party: str, authn_method: str, user_id: str) -> None:
        """
        Perform SAML F-TICKS logging, for statistics in the SWAMID federation.

        :param relying_party: The entity id of the relying party (SP).
        :param authn_method: The URN of the authentication method used.
        :param user_id: Unique user id.
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

    def _validate_login_request(self, idp_data: IdPSessionData):
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

        :param idp_data: State for this request
        :return: pysaml2 response creation data

        :type idp_data: SSOLoginData
        :rtype: dict
        """
        self.logger.debug("Validate login request :\n{!s}".format(idp_data))
        self.logger.debug("AuthnRequest from ticket: {!r}".format(idp_data.req_info.message))
        try:
            resp_args = self.context.idp.response_args(idp_data.req_info.message)

            # not sure if we need to call pick_binding again (already done in response_args()),
            # but it is what we've always done
            binding_out, destination = self.context.idp.pick_binding('assertion_consumer_service',
                                                                     entity_id=idp_data.req_info.message.issuer.text)
            self.logger.debug('Binding: {}, destination: {}'.format(binding_out, destination))

            resp_args['binding_out'] = binding_out
            resp_args['destination'] = destination
            return resp_args
        except UnknownPrincipal as excp:
            self.logger.info("{!s}: Unknown service provider: {!s}".format(idp_data.sso_db_key, excp))
            raise eduid_idp.error.BadRequest("Don't know the SP that referred you here", logger = self.logger)
        except UnsupportedBinding as excp:
            self.logger.info("{!s}: Unsupported SAML binding: {!s}".format(idp_data.sso_db_key, excp))
            raise eduid_idp.error.BadRequest("Don't know how to reply to the SP that referred you here",
                                             logger = self.logger)

    def _get_login_response_authn(self, idp_data: IdPSessionData, user):
        """
        Figure out what AuthnContext to assert in the SAML response.

        The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

        What AuthnContext is asserted is also heavily influenced by what the SP requested.

        Returns a pysaml2-style dictionary like

            {'authn_auth': u'https://idp.example.org/idp.xml',
             'authn_instant': 1391678156,
             'class_ref': 'http://www.swamid.se/policy/assurance/al1'
             }

        :param idp_data: State for this request
        :param user: The user for whom the assertion will be made
        :return: Authn information (pysaml2 style)

        :type idp_data: SSOLoginData
        :type user: IdPUser
        :rtype: dict
        """
        self.logger.debug('MFA credentials logged in the ticket: {}'.format(idp_data.mfa_action_creds))
        self.logger.debug('Credentials used in this SSO session:\n{}'.format(self.session.authn_credentials))
        self.logger.debug('User credentials:\n{}'.format(user.credentials.to_list()))

        # Decide what AuthnContext to assert based on the one requested in the request
        # and the authentication performed

        req_authn_context = self._get_requested_authn_context(idp_data)

        try:
            resp_authn, extra_attributes = eduid_idp.assurance.response_authn(
                req_authn_context, user, self.session, self.logger)
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

        return dict(class_ref = resp_authn,
                    authn_instant = self.session.authn_timestamp,
                    authn_attributes = extra_attributes,
                    )

    def _get_requested_authn_context(self, idp_data: IdPSessionData) -> Optional[str]:
        """
        Check if this SP has explicit Authn preferences in the metadata (some SPs are not
        capable of conveying this preference in the RequestedAuthnContext)

        :param idp_data: State for this request
        :return: Requested Authn Context
        """
        res = None
        req_authn_context = idp_data.req_info.message.requested_authn_context
        if req_authn_context and req_authn_context.authn_context_class_ref:
            res = req_authn_context.authn_context_class_ref[0].text

        try:
            attributes = self.context.idp.metadata.entity_attributes(idp_data.req_info.message.issuer.text)
        except KeyError:
            attributes = {}
        if 'http://www.swamid.se/assurance-requirement' in attributes:
            # XXX don't just pick the first one from the list - choose the most applicable one somehow.
            new_authn = attributes['http://www.swamid.se/assurance-requirement'][0]
            self.logger.debug("Entity {!r} has AuthnCtx preferences in metadata. Overriding {!r} -> {!r}".format(
                idp_data.req_info.message.issuer.text,
                res,
                new_authn))
            res = new_authn

        return res

    def redirect(self):
        """ This is the HTTP-redirect endpoint.

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        self.logger.debug("Unpacked redirect :\n{!s}".format(pprint.pformat(_info)))

        self._update_session(_info, BINDING_HTTP_REDIRECT)
        self._update_state()
        return self._redirect_or_post(self.session.idp)

    def post(self):
        """
        The HTTP-Post endpoint

        :return: HTTP response
        :rtype: string
        """
        self.logger.debug("--- In SSO POST ---")
        _info = self.unpack_either()

        self._update_session(_info, BINDING_HTTP_POST)
        self._update_state()
        return self._redirect_or_post(self.session.idp)

    def _update_session(self, info: dict, binding: Optional[str]) -> None:
        if not info or 'SAMLRequest' not in info:
            raise eduid_idp.error.BadRequest('Bad request, please re-initiate login',
                                             logger=self.context.logger)
        key = ExpiringCache.key(info['SAMLRequest'])

        assert isinstance(self.session, IdPSession)
        if key != self.session.idp.sso_db_key:
            self.context.logger.debug('Different SAML request, updating session')
            self.session.idp = _create_session(self.context, key, info, binding)
            self.context.logger.debug('SAML request {}:\n{}'.format(key, self.session.idp))

        if binding is None:
            binding = info['binding']
        if binding is None:
            raise eduid_idp.error.BadRequest('Bad request, no binding')
        if binding != self.session.idp.binding:
            self.context.logger.debug('Different SAML binding, updating session')
            self.session.idp.binding = binding

        # TODO: save the session somewhere
        #self.context.sessions.store_session(session)

    def _update_state(self) -> None:
        if self.sso_state is None:
            _data = self.context.idp.cache.get_session(self.session.idp.sso_db_key)
            if _data:
                self.sso_state = eduid_idp.sso_state.from_dict(_data)
                self.context.debug('Updated SSO state: {}'.format(self.sso_state))

    def _redirect_or_post(self, idp_data: IdPSessionData) -> str:
        """ Common code for redirect() and post() endpoints. """
        _force_authn = self._should_force_authn(idp_data)
        if self.session and not _force_authn:
            _ttl = self.context.config.sso_session_lifetime - self.sso_state.minutes_old
            self.logger.info("{!s}: proceeding sso_session={!s}, ttl={:}m".format(
                idp_data.sso_db_key, self.sso_state.public_id, _ttl))
            self.logger.debug("Continuing with Authn request {!r}".format(idp_data.req_info))
            try:
                return self.perform_login(idp_data)
            except MustAuthenticate:
                _force_authn = True
            except UnknownSystemEntity as exc:
                self.logger.info('{!s}: Service provider not known: {!s}'.format(idp_data.sso_db_key, exc))
                raise eduid_idp.error.BadRequest('SAML_UNKNOWN_SP')

        if not self.session:
            self.logger.info("{!s}: authenticate ip={!s}".format(idp_data.sso_db_key, eduid_idp.mischttp.get_remote_ip()))
        elif _force_authn:
            self.logger.info("{!s}: force_authn sso_session={!s}".format(
                idp_data.sso_db_key, self.sso_state.public_id))

        return self._not_authn(idp_data)

    def _should_force_authn(self, data: IdPSessionData) -> bool:
        """
        Check if the IdP should force authentication of this request.

        Will check SAML ForceAuthn but avoid endless loops of forced authentications
        by looking if the SSO session says authentication was actually performed
        based on this SAML request.
        """
        if data.req_info.message.force_authn:
            if not self.session:
                self.logger.debug("Force authn without session - ignoring")
                return True
            if data.req_info.message.id != self.sso_state.user_authn_request_id:
                self.logger.debug("Forcing authentication because of ForceAuthn with "
                                  "SSO session id {!r} != {!r}".format(
                                  self.sso_state.user_authn_request_id, data.req_info.message.id))
                return True
            self.logger.debug("Ignoring ForceAuthn, authn already performed for SAML request {!r}".format(
                data.req_info.message.id))
        return False

    def _not_authn(self, idp_data: IdPSessionData) -> str:
        """
        Authenticate user. Either, the user hasn't logged in yet,
        or the service provider forces re-authentication.
        :param idp_data: SSOLoginData instance
        :returns: HTTP response
        """
        redirect_uri = eduid_idp.mischttp.geturl(self.config, query = False)

        req_authn_context = self._get_requested_authn_context(idp_data)
        self.logger.debug("Do authentication, requested auth context : {!r}".format(req_authn_context))

        return self._show_login_page(idp_data, req_authn_context, redirect_uri)

    def _show_login_page(self, idp_data: IdPSessionData, requested_authn_context: str, redirect_uri) -> str:
        """
        Display the login form for all authentication methods.

        SSO._not_authn() chooses what authentication method to use based on
        requested AuthnContext and local configuration, and then calls this method
        to render the login page for this method.

        :param idp_data: Login session state (not SSO session state)
        :param requested_authn_context: Requested authentication context class
        :param redirect_uri: string with URL to proceed to after authentication

        :return: HTTP response
        """
        argv = eduid_idp.mischttp.get_default_template_arguments(self.context.config)
        argv.update({
            "action": "/verify",
            "username": "",
            "password": "",
            "key": idp_data.sso_db_key,
            "authn_reference": requested_authn_context,
            "redirect_uri": redirect_uri,
            "alert_msg": "",
            "sp_entity_id": "",
            "failcount": idp_data.FailCount,
            # SAMLRequest, RelayState and binding are used to re-create the ticket state if not found using `key'
            "SAMLRequest": idp_data.SAMLRequest,
            "RelayState": idp_data.RelayState,
            "binding": idp_data.binding,
        })

        # Set alert msg if FailCount is greater than zero
        if idp_data.FailCount:
            argv["alert_msg"] = "INCORRECT"  # "Incorrect username or password ({!s} attempts)".format(ticket.FailCount)

        try:
            argv["sp_entity_id"] = idp_data.req_info.message.issuer.text
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


def do_verify(context: IdPContext, authn: IdPAuthn):
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
    query = eduid_idp.mischttp.get_post(context.logger)
    # extract password to keep it away from as much code as possible
    password = query.get('password')
    _loggable = query.copy()
    if password:
        del query['password']
        _loggable['password'] = '<redacted>'
    context.logger.debug("do_verify parsed query :\n{!s}".format(pprint.pformat(_loggable)))

    _ticket = _get_ticket(context, query, None)

    authn_ref = None
    if _ticket.req_info.message.requested_authn_context:
        authn_ref = _ticket.req_info.message.requested_authn_context.authn_context_class_ref[0].text
    context.logger.debug("Authenticating with {!r}".format(authn_ref))

    if not password or 'username' not in query:
        raise eduid_idp.error.Unauthorized("Credentials not supplied", logger=context.logger)

    login_data = {'username': query['username'].strip(),
                  'password': password,
                  }
    del password  # keep out of any exception logs
    authninfo = authn.password_authn(login_data)

    if not authninfo:
        _ticket.FailCount += 1
        context.idp.ticket.store_session(_ticket)
        context.logger.debug("Unknown user or wrong password")
        _referer = eduid_idp.mischttp.get_request_header().get('Referer')
        if _referer:
            raise eduid_idp.mischttp.Redirect(str(_referer))
        raise eduid_idp.error.Unauthorized("Login incorrect", logger=context.logger)

    # Create SSO session
    user = authninfo.user
    context.logger.debug("User {} authenticated OK".format(user))
    _sso_session = SSOState(user_id = user.user_id,
                            authn_request_id = _ticket.req_info.message.id,
                            authn_credentials = [authninfo],
                            )

    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    _session_id = context.idp.cache.add_session(user.user_id, _sso_session.to_dict())
    eduid_idp.mischttp.set_cookie('idpauthn', '/', context.logger, context.config, _session_id)
    # knowledge of the _session_id enables impersonation, so get rid of it as soon as possible
    del _session_id

    # INFO-Log the request id (sha1 of SAMLrequest) and the sso_session
    context.logger.info("{!s}: login sso_session={!s}, authn={!s}, user={!s}".format(
        query['key'], _sso_session.public_id,
        authn_ref,
        user))

    # Now that an SSO session has been created, redirect the users browser back to
    # the main entry point of the IdP (the 'redirect_uri'). The ticket reference `key'
    # is passed as an URL parameter instead of the SAMLRequest.
    lox = query["redirect_uri"] + '?key=' + query['key']
    context.logger.debug("Redirect => %s" % lox)
    raise eduid_idp.mischttp.Redirect(lox)


# ----------------------------------------------------------------------------



def _create_session(context: IdPContext, key: str, info: dict, binding: str) -> IdPSessionData:
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
    req_info = _parse_SAMLRequest(context, info, binding)
    return IdPSessionData(sso_db_key=key,
                          SAMLRequest=info['SAMLRequest'],
                          req_info = req_info,
                          RelayState=info['RelayState'],
                          binding=binding,
                          )


def _parse_SAMLRequest(context: IdPContext, info: dict, binding: str) -> AuthnRequest:
    """
    Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
    instance.

    If the SAMLRequest is signed, the signature is validated and a BadRequest()
    returned on failure.

    :param info: dict with keys 'SAMLRequest' and possibly 'SigAlg' and 'Signature'
    :param binding: SAML binding
    :returns: pysaml2 AuthnRequest information
    :raise: BadRequest if request signature validation fails
    """
    logger = context.logger
    try:
        _req_info = context.idp.parse_authn_request(info['SAMLRequest'], binding)
    except UnravelError as exc:
        logger.info('Failed parsing SAML request ({!s} bytes)'.format(len(info['SAMLRequest'])))
        logger.debug('Failed parsing SAML request:\n{!s}\nException {!s}'.format(info['SAMLRequest'], exc))
        raise eduid_idp.error.BadRequest('No valid SAMLRequest found', logger = logger)
    if not _req_info:
        # Either there was no request, or pysaml2 found it to be unacceptable.
        # For example, the IssueInstant might have been out of bounds.
        logger.debug('No valid SAMLRequest returned by pysaml2')
        raise eduid_idp.error.BadRequest('No valid SAMLRequest found', logger = logger)
    assert isinstance(_req_info, AuthnRequest)

    # Only perform expensive parse/pretty-print if debugging
    if context.config.debug:
        xmlstr = eduid_idp.util.maybe_xml_to_string(_req_info.message)
        logger.debug('Decoded SAMLRequest into AuthnRequest {!r} :\n\n{!s}\n\n'.format(
            _req_info.message, xmlstr))

    if 'SigAlg' in info and 'Signature' in info:  # Signed request
        issuer = _req_info.message.issuer.text
        _certs = context.idp.metadata.certs(issuer, 'any', 'signing')
        if context.config.verify_request_signatures:
            verified_ok = False
            for cert in _certs:
                if verify_redirect_signature(info, cert):
                    verified_ok = True
                    break
            if not verified_ok:
                _key = ExpiringCache.key(info['SAMLRequest'])
                logger.info('{!s}: SAML request signature verification failure'.format(_key))
                raise eduid_idp.error.BadRequest('SAML request signature verification failure',
                                                 logger = logger)
        else:
            logger.debug('Ignoring existing request signature, verify_request_signature is False')
    else:
        # XXX check if metadata says request should be signed ???
        # Leif says requests are typically not signed, and that verifying signatures
        # on SAML requests is considered a possible DoS attack vector, so it is typically
        # not done.
        # XXX implement configuration flag to disable signature verification
        logger.debug('No signature in SAMLRequest')
    return _req_info
