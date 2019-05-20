import logging
from dataclasses import dataclass
from typing import Mapping, NewType, Optional

import eduid_idp.util
import saml2.server
from eduid_idp.cache import ExpiringCache
from saml2.s_utils import UnknownPrincipal, UnknownSystemEntity, UnravelError, UnsupportedBinding
from saml2.saml import Issuer
from saml2.samlp import RequestedAuthnContext
from saml2.sigver import verify_redirect_signature

ResponseArgs = NewType('ResponseArgs', dict)


@dataclass
class AuthnInfo(object):
    """ Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: str
    authn_attributes: dict  # these are added to the user attributes
    instant: Optional[int] = None


class IdP_SAMLRequest(object):

    def __init__(self, request: str, binding: str, idp: saml2.server.Server, logger: logging.Logger,
                 debug: bool):
        self._request = request
        self._binding = binding
        self._idp = idp
        self._logger = logger
        self._debug = debug

        try:
            self._req_info = idp.parse_authn_request(request, binding)
        except UnravelError as exc:
            logger.info(f'Failed parsing SAML request ({len(request)} bytes)')
            logger.debug(f'Failed parsing SAML request:\n{request}\nException {exc}')
            raise

        if not self._req_info:
            # Either there was no request, or pysaml2 found it to be unacceptable.
            # For example, the IssueInstant might have been out of bounds.
            logger.debug('No valid SAMLRequest returned by pysaml2')
            raise ValueError('No valid SAMLRequest returned by pysaml2')

        # Only perform expensive parse/pretty-print if debugging
        if debug:
            xmlstr = eduid_idp.util.maybe_xml_to_string(self._req_info.message)
            logger.debug(f'Decoded SAMLRequest into AuthnRequest {repr(self._req_info.message)}:\n\n{xmlstr}\n\n')

    @property
    def binding(self):
         return self._binding

    def verify_signature(self, sig_alg: str, signature: str) -> bool:
        info = {'SigAlg': sig_alg,
                'Signature': signature,
                'SAMLRequest': self.request,
                }
        _certs = self._idp.metadata.certs(self.sp_entity_id, 'any', 'signing')
        verified_ok = False
        # Make sure at least one certificate verifies the signature
        for cert in _certs:
            if verify_redirect_signature(info, cert):
                verified_ok = True
                break
        if not verified_ok:
            _key = ExpiringCache.key(info['SAMLRequest'])
            self._logger.info('{!s}: SAML request signature verification failure'.format(_key))
        return verified_ok

    @property
    def request(self) -> str:
        """The original SAMLRequest XML string."""
        return self._request

    @property
    def raw_requested_authn_context(self) -> Optional[RequestedAuthnContext]:
        return self._req_info.message.requested_authn_context

    def get_requested_authn_context(self) -> Optional[str]:
        """
        SAML requested authn context.

        TODO: Don't just return the first one, but the most relevant somehow.
        """
        if self.raw_requested_authn_context:
            return self.raw_requested_authn_context.authn_context_class_ref[0].text
        return None

    @property
    def raw_sp_entity_id(self) -> Issuer:
        return self._req_info.message.issuer

    @property
    def sp_entity_id(self) -> str:
        """The entity ID of the service provider as a string."""
        return self.raw_sp_entity_id.text

    @property
    def force_authn(self) -> Optional[bool]:
        return self._req_info.message.force_authn

    @property
    def request_id(self) -> str:
        return self._req_info.message.id

    @property
    def sp_entity_attributes(self) -> Mapping:
        """Return the entity attributes for the SP that made the request from the metadata."""
        try:
            return self._idp.metadata.entity_attributes(self.sp_entity_id)
        except KeyError:
            return {}

    def get_response_args(self, bad_request, key: str) -> ResponseArgs:
        try:
            resp_args = self._idp.response_args(self._req_info.message)

            # not sure if we need to call pick_binding again (already done in response_args()),
            # but it is what we've always done
            binding_out, destination = self._idp.pick_binding('assertion_consumer_service', entity_id=self.sp_entity_id)
            self._logger.debug(f'Binding: {binding_out}, destination: {destination}')

            resp_args['binding_out'] = binding_out
            resp_args['destination'] = destination
        except UnknownPrincipal as excp:
            self._logger.info(f'{key}: Unknown service provider: {excp}')
            raise bad_request("Don't know the SP that referred you here", logger = self._logger)
        except UnsupportedBinding as excp:
            self._logger.info(f'{key}: Unsupported SAML binding: {excp}')
            raise bad_request("Don't know how to reply to the SP that referred you here",
                              logger = self._logger)
        except UnknownSystemEntity as exc:
            # TODO: Validate refactoring didn't move this exception handling to the wrong place.
            #       Used to be in an exception handler in _redirect_or_post around perform_login().
            self._logger.info(f'{key}: Service provider not known: {exc}')
            raise bad_request('SAML_UNKNOWN_SP')

        return ResponseArgs(resp_args)

    def make_saml_response(self, attributes: Mapping, userid: str, response_authn: AuthnInfo, resp_args: ResponseArgs):
        # Create pysaml2 dict with the authn information
        authn = dict(class_ref = response_authn.class_ref,
                     authn_instant = response_authn.instant,
                     )
        saml_response = self._idp.create_authn_response(attributes, userid = userid,
                                                        authn = authn, sign_response = True,
                                                        **resp_args)
        return saml_response

    def apply_binding(self, resp_args: ResponseArgs, relay_state: str, saml_response: str):
        """ Create the Javascript self-posting form that will take the user back to the SP
        with a SAMLResponse.
        """
        binding_out = resp_args.get('binding_out')
        destination = resp_args.get('destination')
        self._logger.debug('Applying binding_out {!r}, destination {!r}, relay_state {!r}'.format(
            binding_out, destination, relay_state))
        http_args = self._idp.apply_binding(binding_out, str(saml_response), destination,
                                            relay_state, response = True)
        return http_args



def parse_SAMLRequest(info: Mapping, binding: str, logger: logging.Logger, idp: saml2.server.Server,
                      bad_request,
                      debug: bool = False, verify_request_signatures=True) -> IdP_SAMLRequest:

    """
    Parse a SAMLRequest query parameter (base64 encoded) into an AuthnRequest
    instance.

    If the SAMLRequest is signed, the signature is validated and a BadRequest()
    returned on failure.

    :param info: dict with keys 'SAMLRequest' and possibly 'SigAlg' and 'Signature'
    :param binding: SAML binding
    :returns: pysaml2 interface class IdP_SAMLRequest
    :raise: BadRequest if request signature validation fails
    """
    try:
        saml_req = IdP_SAMLRequest(info['SAMLRequest'], binding, idp, logger, debug=debug)
    except UnravelError:
        raise bad_request('No valid SAMLRequest found', logger=logger)
    except ValueError:
        raise bad_request('No valid SAMLRequest found', logger=logger)

    if 'SigAlg' in info and 'Signature' in info:  # Signed request
        if verify_request_signatures:
            if not saml_req.verify_signature(info['SigAlg'], info['Signature']):
                raise bad_request('SAML request signature verification failure',
                                  logger=logger)
        else:
            logger.debug('Ignoring existing request signature, verify_request_signature is False')
    else:
        # XXX check if metadata says request should be signed ???
        # Leif says requests are typically not signed, and that verifying signatures
        # on SAML requests is considered a possible DoS attack vector, so it is typically
        # not done.
        # XXX implement configuration flag to disable signature verification
        logger.debug('No signature in SAMLRequest')

    return saml_req
