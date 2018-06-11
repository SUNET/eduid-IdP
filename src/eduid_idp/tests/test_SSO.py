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

import eduid_idp
from eduid_idp.loginstate import SSOLoginData
from eduid_idp.testing import IdPSimpleTestCase, FakeIdPApp
from eduid_idp.util import b64encode
from eduid_idp.authn import AuthnData

from eduid_userdb.nin import Nin
from eduid_userdb.credentials import U2F, Password, u2f_from_dict
import saml2.time_util

from saml2.authn_context import MOBILETWOFACTORCONTRACT
from saml2.authn_context import PASSWORD
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT

cc = {'REFEDS_MFA': 'https://refeds.org/profile/mfa',
      'REFEDS_SFA': 'https://refeds.org/profile/sfa',
      'FIDO_U2F': 'https://fidoalliance.org/specs/id-fido-u2f-ce-transports',
      'PASSWORD_PT': 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport',
      }

_U2F = u2f_from_dict({
    'version': 'U2F_V2',
    'app_id': 'unit test',
    'keyhandle': 'firstU2FElement',
    'public_key': 'foo',
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


def make_login_ticket(req_class_ref):
    xmlstr = make_SAML_request(class_ref = req_class_ref)
    binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    key = 'unique-key-for-request-1'

    start_response = lambda: False
    idp_app = FakeIdPApp()
    sso_session_1 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
                                                     authn_request_id='some-unique-id-1'
                                                     )
    SSO = eduid_idp.login.SSO(sso_session_1, start_response, idp_app)
    req_info = SSO.IDP.parse_authn_request(xmlstr, binding)
    return SSOLoginData(key, req_info, {'SAMLRequest': xmlstr}, binding)


# noinspection PyProtectedMember
class TestSSO(IdPSimpleTestCase):

    def setUp(self):
        super(TestSSO, self).setUp()

        self.start_response = lambda: False
        self.idp_app = FakeIdPApp()

        #sso_session_1 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
        #                                                 authn_request_id='some-unique-id-1'
        #                                                 )
        #self.SSO_AL1 = eduid_idp.login.SSO(sso_session_1, start_response, idp_app)
        #sso_session_2 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
        #                                                 authn_request_id='some-unique-id-2'
        #                                                 )
        #self.SSO_AL2 = eduid_idp.login.SSO(sso_session_2, start_response, idp_app)
        #sso_session_3 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
        #                                                 authn_request_id='some-unique-id-3'
        #                                                 )
        #self.SSO_AL3 = eduid_idp.login.SSO(sso_session_3, start_response, idp_app)

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
            this_nin = Nin(number = number,
                           application = 'unittest',
                           created_ts = True,
                           verified = True,
                           primary = user.nins.primary is None)
            user.nins.add(this_nin)
        return user

    # ------------------------------------------------------------------------

    def _get_login_response_authn(self, req_class_ref, credentials, user=None):
        if user is None:
            user = self.get_user_set_nins('test1@eduid.se', [])
        ticket = make_login_ticket(req_class_ref=req_class_ref)

        sso_session_1 = eduid_idp.sso_session.SSOSession(user_id=user.eppn,
                                                         authn_request_id='some-unique-id-1'
                                                         )
        if 'u2f' in credentials and not user.credentials.filter(U2F).to_list():
            # add a U2F credential to the user
            user.credentials.add(_U2F)
        for this in credentials:
            if this == 'pw':
                this = user.credentials.filter(Password).to_list()[0]
            elif this == 'u2f':
                this = user.credentials.filter(U2F).to_list()[0]
            data = AuthnData(user, this, datetime.datetime.now())
            sso_session_1.add_authn_credential(data)
        _SSO = eduid_idp.login.SSO(sso_session_1, self.start_response, self.idp_app)
        return _SSO._get_login_response_authn(ticket, user)

    # ------------------------------------------------------------------------

    def test__get_login_response_3(self):
        """
        Test login with password and U2F, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """

        out = self._get_login_response_authn(req_class_ref = cc['REFEDS_SFA'],
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out['class_ref'], cc['REFEDS_SFA'])

    def test__get_login_response_4(self):
        """
        Test login with password, request REFEDS SFA.

        Expect the response Authn to be REFEDS SFA.
        """

        out = self._get_login_response_authn(req_class_ref = cc['REFEDS_SFA'],
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out['class_ref'], cc['REFEDS_SFA'])

    def test__get_login_response_5(self):
        """
        Test login with password and U2F, request FIDO U2F.

        Expect the response Authn to be FIDO U2F.
        """

        out = self._get_login_response_authn(req_class_ref = cc['FIDO_U2F'],
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out['class_ref'], cc['FIDO_U2F'])

    def test__get_login_response_6(self):
        """
        Test login with password and U2F, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """

        out = self._get_login_response_authn(req_class_ref = PASSWORDPROTECTEDTRANSPORT,
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out['class_ref'], PASSWORDPROTECTEDTRANSPORT)

    def test__get_login_response_7(self):
        """
        Test login with password, request plain password-protected-transport.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(req_class_ref = PASSWORDPROTECTEDTRANSPORT,
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out['class_ref'], PASSWORDPROTECTEDTRANSPORT)

    def test__get_login_response_8(self):
        """
        Test login with password, request unknown context class.

        Expect the response Authn to be FIDO U2F.
        """
        out = self._get_login_response_authn(req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw', 'u2f'],
                                             )
        self.assertEqual(out['class_ref'], cc['FIDO_U2F'])

    def test__get_login_response_9(self):
        """
        Test login with password and U2F, request unknown context class.

        Expect the response Authn to be password-protected-transport.
        """
        out = self._get_login_response_authn(req_class_ref = 'urn:no-such-class',
                                             credentials = ['pw'],
                                             )
        self.assertEqual(out['class_ref'], PASSWORDPROTECTEDTRANSPORT)

