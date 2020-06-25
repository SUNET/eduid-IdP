#!/usr/bin/python
#
# Copyright (c) 2014, 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import datetime

from typing import Mapping, NewType, Optional, AnyStr
import logging
import eduid_idp
import saml2.server
import saml2.time_util
from saml2.s_utils import UnravelError
from eduid_common.authn.idp_authn import AuthnData
from eduid_common.session.sso_session import SSOSession
from eduid_common.session.logindata import ExternalMfaData
from eduid_common.session.logindata import SSOLoginData
from eduid_common.authn.idp_saml import IdP_SAMLRequest
from eduid_idp.error import Forbidden
from eduid_idp.testing import IdPSimpleTestCase
from eduid_idp.util import b64encode
from eduid_userdb.credentials import METHOD_SWAMID_AL2_MFA, METHOD_SWAMID_AL2_MFA_HI, Password, U2F, u2f_from_dict
from eduid_userdb.nin import Nin
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT

SWAMID_AL1 = 'http://www.swamid.se/policy/assurance/al1'
SWAMID_AL2 = 'http://www.swamid.se/policy/assurance/al2'
SWAMID_AL2_MFA_HI = 'http://www.swamid.se/policy/authentication/swamid-al2-mfa-hi'

cc = {'REFEDS_MFA': 'https://refeds.org/profile/mfa',
      'REFEDS_SFA': 'https://refeds.org/profile/sfa',
      'EDUID_MFA':   'https://eduid.se/specs/mfa',
      'FIDO_U2F': 'https://www.swamid.se/specs/id-fido-u2f-ce-transports',
      'PASSWORD_PT': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      }

_U2F = u2f_from_dict({
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'firstU2FElement',
    'public_key': 'foo',
})

_U2F_SWAMID_AL2 = u2f_from_dict({
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'U2F SWAMID AL2',
    'public_key': 'foo',
    'verified': True,
    'proofing_method': METHOD_SWAMID_AL2_MFA,
    'proofing_version': 'testing',
})

_U2F_SWAMID_AL2_HI = u2f_from_dict({
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'U2F SWAMID AL2 HI',
    'public_key': 'foo',
    'verified': True,
    'proofing_method': METHOD_SWAMID_AL2_MFA_HI,
    'proofing_version': 'testing',
})


def make_SAML_request(class_ref):
    return _transport_encode('''
<?xml version="1.0" encoding="UTF-8"?>
<ns0:AuthnRequest xmlns:ns0="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:ns1="urn:oasis:names:tc:SAML:2.0:assertion"
        AssertionConsumerServiceURL="https://sp.example.edu/saml2/acs/"
        Destination="https://unittest-idp.example.edu/sso/post"
        ID="id-57beb2b2f788ec50b10541dbe48e9626"
        IssueInstant="{now!s}"
        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Version="2.0">
  <ns1:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">https://sp.example.edu/saml2/metadata/</ns1:Issuer>
  <ns0:NameIDPolicy AllowCreate="false" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"/>
  <ns0:RequestedAuthnContext>
    <ns1:AuthnContextClassRef>{class_ref!s}</ns1:AuthnContextClassRef>
  </ns0:RequestedAuthnContext>
</ns0:AuthnRequest>
'''.format(class_ref = class_ref,
           now = saml2.time_util.instant()))


def _transport_encode(data):
    # encode('base64') only works for POST bindings, redirect uses zlib compression too.
    return b64encode(''.join(data.split('\n')))


def make_login_ticket(req_class_ref, context, key=None) -> SSOLoginData:
    xmlstr = make_SAML_request(class_ref = req_class_ref)
    info = {'SAMLRequest': xmlstr}
    binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    if key is None:
        key = 'unique-key-for-request-1'
    saml_req = parse_SAMLRequest(info, binding, context.logger, context.idp, eduid_idp.error.BadRequest,
                                 context.config.debug, context.config.verify_request_signatures)
    #context.idp.parse_authn_request(xmlstr, binding)
    ticket = SSOLoginData(key, xmlstr, binding)
    ticket.saml_req = saml_req
    return ticket


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


# noinspection PyProtectedMember
class TestSSO(IdPSimpleTestCase):

    def setUp(self):
        super(TestSSO, self).setUp()

        self.start_response = lambda: False

    # ------------------------------------------------------------------------
    def get_user_set_nins(self, eppn, ninlist):
        """
        Fetch a user from the FakeUserDb and set it's NINs to those in ninlist.
        :param eppn: eduPersonPrincipalName or email address
        :param ninlist: List of NINs to configure user with (all verified)

        :type eppn: str or unicode
        :type ninlist: [str or unicode]

        :return: IdPUser instance
        :rtype: IdPUser
        """
        user = self.idp_userdb.lookup_user(eppn)
        [user.nins.remove(x) for x in user.nins.to_list()]
        for number in ninlist:
            this_nin = Nin.from_dict(dict(number=number,
                                         created_by='unittest',
                                         created_ts=True,
                                         verified=True,
                                         primary=user.nins.primary is None))
            user.nins.add(this_nin)
        return user

    # ------------------------------------------------------------------------

    def _get_login_response_authn(self, req_class_ref, credentials=[], user=None):
        if user is None:
            user = self.get_user_set_nins('test1@eduid.se', [])
        ticket = make_login_ticket(req_class_ref, self.context)

        sso_session_1 = SSOSession(user_id=user.eppn, authn_request_id='some-unique-id-1')
        if 'u2f' in credentials and not user.credentials.filter(U2F).to_list():
            # add a U2F credential to the user
            user.credentials.add(_U2F)
        for this in credentials:
            if this == 'pw':
                this = user.credentials.filter(Password).to_list()[0]
            elif this == 'u2f':
                this = user.credentials.filter(U2F).to_list()[0]

            if isinstance(this, AuthnData):
                sso_session_1.add_authn_credential(this)
            elif isinstance(this, ExternalMfaData):
                sso_session_1.external_mfa = this
            else:
                data = AuthnData(user, this, datetime.datetime.now())
                sso_session_1.add_authn_credential(data)
        _SSO = eduid_idp.login.SSO(sso_session_1, self.start_response, self.context)
        return _SSO._get_login_response_authn(ticket, user)

    # ------------------------------------------------------------------------

    def test__get_login_response_1(self):
        """
        Test login with password and SWAMID AL2-HI U2F, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA, and assurance attribute to include SWAMID MFA HI.
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        user.credentials.add(_U2F_SWAMID_AL2_HI)
        out = self._get_login_response_authn(user = user,
                                             req_class_ref = cc['REFEDS_MFA'],
                                             credentials = ['pw', _U2F_SWAMID_AL2_HI],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2, SWAMID_AL2_MFA_HI])

    def test__get_login_response_2(self):
        """
        Test login with password and SWAMID AL2 U2F, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA.
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        user.credentials.add(_U2F_SWAMID_AL2)
        out = self._get_login_response_authn(user = user,
                                             req_class_ref = cc['REFEDS_MFA'],
                                             credentials = ['pw', _U2F_SWAMID_AL2],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_response_wrong_multifactor(self):
        """
        Test login with password and non-SWAMID-AL2 U2F, request REFEDS MFA.

        Expect a failure because a self-registered U2F token is not acceptable as REFEDS MFA.
        """
        with self.assertRaises(Forbidden):
            self._get_login_response_authn(req_class_ref=cc['REFEDS_MFA'],
                                           credentials=['pw', 'u2f'],
                                           )

    def test__get_login_response_external_multifactor(self):
        """
        Test login with password and and external MFA, request REFEDS MFA.

        Expect the response Authn to be REFEDS MFA and assurance attribute to include SWAMID MFA HI.
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        external_mfa = ExternalMfaData(issuer='issuer.example.com',
                                       authn_context='http://id.elegnamnden.se/loa/1.0/loa3',
                                       timestamp=datetime.datetime.utcnow())
        out = self._get_login_response_authn(user=user, req_class_ref=cc['REFEDS_MFA'],
                                             credentials=['pw', external_mfa],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2, SWAMID_AL2_MFA_HI])

    def test__get_login_response_3(self):
        """
        Test login with password and U2F, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(req_class_ref = cc['REFEDS_SFA'],
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_SFA'])

    def test__get_login_response_4(self):
        """
        Test login with password, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(req_class_ref = cc['REFEDS_SFA'],
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_SFA'])

    def test__get_login_response_UNSPECIFIED2(self):
        """
        Test login with U2F, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """
        out = self._get_login_response_authn(req_class_ref = cc['REFEDS_SFA'],
                                             credentials = ['u2f'],
                                             )
        self.assertEqual(out.class_ref, cc['REFEDS_SFA'])

    def test__get_login_response_5(self):
        """
        Test login with password and U2F, request FIDO U2F.

        Expect the response Authn to be FIDO U2F.
        """
        out = self._get_login_response_authn(req_class_ref = cc['FIDO_U2F'],
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out.class_ref, cc['FIDO_U2F'])

    def test__get_login_response_6(self):
        """
        Test login with password and U2F, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(req_class_ref = PASSWORDPROTECTEDTRANSPORT,
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out.class_ref, PASSWORDPROTECTEDTRANSPORT)

    def test__get_login_response_7(self):
        """
        Test login with password, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(req_class_ref = PASSWORDPROTECTEDTRANSPORT,
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out.class_ref, PASSWORDPROTECTEDTRANSPORT)

    def test__get_login_response_8(self):
        """
        Test login with password, request unknown context class.

        Expect the response Authn to be FIDO U2F.
        """
        out = self._get_login_response_authn(req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out.class_ref, cc['FIDO_U2F'])

    def test__get_login_response_9(self):
        """
        Test login with password, request unknown context class.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out.class_ref, PASSWORDPROTECTEDTRANSPORT)

    def test__get_login_response_assurance_AL1(self):
        """
        Make sure eduPersonAssurace is SWAMID AL1 with no verified nin.
        """
        out = self._get_login_response_authn(req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1])

    def test__get_login_response_assurance_AL2(self):
        """
        Make sure eduPersonAssurace is SWAMID AL2 with a verified nin.
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        out = self._get_login_response_authn(user = user,
                                             req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_eduid_mfa_fido_al1(self):
        """
        Test login with password and fido for not verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1
        """
        out = self._get_login_response_authn(req_class_ref=cc['EDUID_MFA'],
                                             credentials=['pw', 'u2f'],
                                             )
        self.assertEqual(out.class_ref, cc['EDUID_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1])

    def test__get_login_eduid_mfa_fido_al2(self):
        """
        Test login with password and fido for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1,Al2
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        user.credentials.add(_U2F)
        out = self._get_login_response_authn(user=user,
                                             req_class_ref=cc['EDUID_MFA'],
                                             credentials=['pw', _U2F],
                                             )
        self.assertEqual(out.class_ref, cc['EDUID_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_eduid_mfa_fido_swamid_al2(self):
        """
        Test login with password and fido_swamid_al2 for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1,Al2
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        user.credentials.add(_U2F_SWAMID_AL2)
        out = self._get_login_response_authn(user=user,
                                             req_class_ref=cc['EDUID_MFA'],
                                             credentials=['pw', _U2F_SWAMID_AL2],
                                             )
        self.assertEqual(out.class_ref, cc['EDUID_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_eduid_mfa_fido_swamid_al2_hi(self):
        """
        Test login with password and fido_swamid_al2_hi for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA, eduPersonAssurance AL1,Al2
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        user.credentials.add(_U2F_SWAMID_AL2_HI)
        out = self._get_login_response_authn(user=user,
                                             req_class_ref=cc['EDUID_MFA'],
                                             credentials=['pw', _U2F_SWAMID_AL2_HI],
                                             )
        self.assertEqual(out.class_ref, cc['EDUID_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_eduid_mfa_external_mfa_al2(self):
        """
        Test login with password and external mfa for verified user, request EDUID_MFA.

        Expect the response Authn to be EDUID_MFA.
        """
        user = self.get_user_set_nins('test1@eduid.se', ['190101011234'])
        external_mfa = ExternalMfaData(issuer='issuer.example.com',
                                       authn_context='http://id.elegnamnden.se/loa/1.0/loa3',
                                       timestamp=datetime.datetime.utcnow())
        out = self._get_login_response_authn(user=user,
                                             req_class_ref=cc['EDUID_MFA'],
                                             credentials=['pw', external_mfa],
                                             )
        self.assertEqual(out.class_ref, cc['EDUID_MFA'])
        self.assertEqual(out.authn_attributes['eduPersonAssurance'], [SWAMID_AL1, SWAMID_AL2])

    def test__get_login_response_eduid_mfa_no_multifactor(self):
        """
        Test login with password, request EDUID_MFA.

        Expect a failure because MFA is needed for  EDUID_MFA.
        """
        with self.assertRaises(Forbidden):
            self._get_login_response_authn(req_class_ref=cc['EDUID_MFA'], credentials=['pw'])
