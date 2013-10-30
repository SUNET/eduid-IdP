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
Code handling Single Log Out requests.
"""
import pprint

from eduid_idp.service import Service
from eduid_idp.error import BadRequest
import eduid_idp.mischttp

from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.s_utils import exception_trace, error_status_factory
import saml2.samlp
import saml2.request

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------


class SLO(Service):
    """
    Single Log Out service.
    """

    def redirect(self):
        """ Expects a HTTP-redirect request """

        _dict = self.unpack_redirect()
        return self.perform_logout(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST request """

        _dict = self.unpack_post()
        return self.perform_logout(_dict, BINDING_HTTP_POST)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        self.logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        self.logger.debug("_dict: %s" % _dict)
        return self.perform_logout(_dict, BINDING_SOAP)

    def unpack_soap(self):
        """
        Turn a SOAP request into the common format of a dict.

        :return: dict with 'SAMLRequest' and 'RelayState' items
        """
        # XXX suspect this is broken - get_post() returns a dict() now
        # and it looks like the old get_post returned the body as string
        query = eduid_idp.mischttp.get_post()
        return {'SAMLRequest': query,
                'RelayState': '',
                }

    def perform_logout(self, info, binding):
        """
        Perform logout. Means remove SSO session from IdP list, and a best
        effort to contact all SPs that have received assertions using this
        SSO session and letting them know the user has been logged out.

        :param info: Dict with SAMLRequest and possibly RelayState
        :param binding: SAML2 binding as string
        :return: Response as string
        """
        self.logger.info("--- Single Log Out Service ---")

        self.logger.debug("_perform_logout {!s}:\n{!s}".format(binding, pprint.pformat(info)))
        if not info:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        request = info["SAMLRequest"]

        try:
            req_info = self.IDP.parse_logout_request(request, binding)
            assert isinstance(req_info, saml2.request.LogoutRequest)
            self.logger.debug("Parsed Logout request: {!s}".format(req_info.message))
        except Exception as exc:
            self.logger.error("Bad request parsing logout request : {!r}".format(exc))
            self.logger.debug("Exception parsing logout request :\n{!s}".format(exception_trace(exc)))
            raise eduid_idp.error.BadRequest("Failed parsing logout request", logger = self.logger)

        req_info.binding = binding
        if 'RelayState' in info:
            req_info.relay_state = info['RelayState']

        # look for the subject
        subject = req_info.subject_id()
        self.logger.debug("Logout subject: {!s}".format(subject.text.strip()))
        # XXX should verify issuer (a.k.a. sender()) somehow perhaps
        self.logger.debug("Logout request sender : {!s}".format(req_info.sender()))

        _name_id = req_info.message.name_id
        _lid = eduid_idp.mischttp.read_cookie(self.logger)
        if not _lid:
            _lid = self.IDP.ident.find_local_id(_name_id)
            self.logger.debug("Logout message name_id: {!r} found local-id {!r}".format(
                _name_id, _lid))

        status_code = self._logout_using_name_id(_lid, _name_id)
        self.logger.debug("Logout of local-id {!r} result : {!r}".format(_lid, status_code))
        return self._logout_response(req_info, status_code)

    def _logout_using_name_id(self, local_id, name_id):
        """
        :param local_id: Local ID (db key in SSO session database)
        :param name_id: NameID from LogoutRequest
        :return: SAML StatusCode (string)
        """
        if not local_id or not name_id:
            self.logger.error("Could not find local identifier (SSO session key) using provided name-id")
            return saml2.samlp.STATUS_UNKNOWN_PRINCIPAL
        self.logger.info("Logging out session with local identifier: {!s}".format(local_id))
        if not self.IDP.cache.remove_session(local_id):
            return saml2.samlp.STATUS_UNKNOWN_PRINCIPAL
        try:
            # remove the authentication
            # XXX would be useful if remove_authn_statements() returned how many statements it actually removed
            self.IDP.session_db.remove_authn_statements(name_id)
        except KeyError as exc:
            self.logger.error("ServiceError removing authn : %s" % exc)
            raise eduid_idp.error.ServiceError(logger = self.logger)
        return saml2.samlp.STATUS_SUCCESS

    def _logout_response(self, req_info, status_code, sign_response=True):
        """
        Create logout response.

        :param req_info: Logout request
        :param status_code: logout result (e.g. 'urn:oasis:names:tc:SAML:2.0:status:Success')
        :param sign_response: cryptographically sign response or not
        :return: HTML response

        :type req_info: saml2.request.LogoutRequest
        :type status_code: basestring
        :type sign_response: bool
        :rtype: basestring
        """
        self.logger.info("LOGOUT of '{!s}' by '{!s}', success={!r}".format(req_info.subject_id(), req_info.sender(),
                                                                           status_code))
        if req_info.binding != BINDING_SOAP:
            bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
            binding, destination = self.IDP.pick_binding("single_logout_service", bindings,
                                                         entity_id = req_info.sender())
            bindings = [binding]
        else:
            bindings = [BINDING_SOAP]
            destination = ""

        status = None  # None == success in create_logout_response()
        if status_code != saml2.samlp.STATUS_SUCCESS:
            status = error_status_factory((status_code, "Logout failed"))
            self.logger.debug("Created 'logout failed' status based on {!r} : {!r}".format(status_code, status))

        issuer = self.IDP._issuer(self.IDP.config.entityid)
        response = self.IDP.create_logout_response(req_info.message, bindings, status, sign = sign_response,
                                                   issuer = issuer)
        self.logger.debug("Logout SAMLResponse :\n{!s}".format(response))

        ht_args = self.IDP.apply_binding(bindings[0], str(response), destination, req_info.relay_state,
                                         response = True)

        self.logger.debug("Apply bindings result :\n{!s}\n\n".format(pprint.pformat(ht_args)))

        # Delete the SSO session cookie in the browser
        eduid_idp.mischttp.delete_cookie("idpauthn", self.logger)

        # XXX old code checked 'if req_info.binding == BINDING_HTTP_REDIRECT:', but it looks like
        # it would be more correct to look at bindings[0] here, since `bindings' is what was used
        # with create_logout_response() and apply_binding().
        if req_info.binding != bindings[0]:
            self.logger.debug("Creating response with binding {!r] instead of {!r} used before".format(
                bindings[0], req_info.binding))
        return eduid_idp.mischttp.create_html_response(bindings[0], ht_args, self.start_response, self.logger)
