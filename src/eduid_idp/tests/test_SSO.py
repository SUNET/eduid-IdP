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

import eduid_idp

from eduid_idp.testing import IdPSimpleTestCase, FakeIdPApp

from eduid_userdb.nin import Nin
from eduid_userdb.exceptions import UserDBValueError
import saml2.time_util

from saml2.authn_context import MOBILETWOFACTORCONTRACT
from saml2.authn_context import PASSWORD
from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT


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
    return ''.join(data.split('\n')).encode('base64')


def make_login_ticket(req_class_ref):
    xmlstr = make_SAML_request(class_ref = req_class_ref)
    binding = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    key = 'unique-key-for-request-1'

    start_response = lambda: False
    idp_app = FakeIdPApp()
    sso_session_1 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
                                                     authn_ref='eduid.se:level:1:100',
                                                     authn_class_ref='eduid.se:level:1',
                                                     authn_request_id='some-unique-id-1'
                                                     )
    SSO = eduid_idp.login.SSO(sso_session_1, start_response, idp_app)
    req_info = SSO.IDP.parse_authn_request(xmlstr, binding)
    return eduid_idp.login.SSOLoginData(key, req_info, {'SAMLRequest': xmlstr}, binding)


# noinspection PyProtectedMember
class TestSSO(IdPSimpleTestCase):

    def setUp(self):
        super(TestSSO, self).setUp()

        start_response = lambda: False
        idp_app = FakeIdPApp()

        sso_session_1 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
                                                         authn_ref='eduid.se:level:1:100',
                                                         authn_class_ref='eduid.se:level:1',
                                                         authn_request_id='some-unique-id-1'
                                                         )
        self.SSO_AL1 = eduid_idp.login.SSO(sso_session_1, start_response, idp_app)
        sso_session_2 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
                                                         authn_ref='eduid.se:level:2:200',
                                                         authn_class_ref='eduid.se:level:2',
                                                         authn_request_id='some-unique-id-2'
                                                         )
        self.SSO_AL2 = eduid_idp.login.SSO(sso_session_2, start_response, idp_app)
        sso_session_3 = eduid_idp.sso_session.SSOSession(user_id='test',   # really ObjectId()
                                                         authn_ref='eduid.se:level:3:300',
                                                         authn_class_ref='eduid.se:level:3',
                                                         authn_request_id='some-unique-id-3'
                                                         )
        self.SSO_AL3 = eduid_idp.login.SSO(sso_session_3, start_response, idp_app)

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

    def test__get_login_response_authn_1(self):
        """
        Test login with AL2, request plain AL1.

        Expect the response Authn to be AL1.
        :return:
        """
        ticket = make_login_ticket(req_class_ref = eduid_idp.assurance.SWAMID_AL1)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL2._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL1, out['class_ref'])

    def test__get_login_response_authn_2a(self):
        """
        Test login with AL2, request plain AL2.

        Expect the response Authn to be AL2.
        :return:
        """
        ticket = make_login_ticket(req_class_ref = eduid_idp.assurance.SWAMID_AL2)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL2._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL2, out['class_ref'])

    def test__get_login_response_authn_2b(self):
        """
        Test login with AL2, request plain AL2 but with user that has no NIN.

        Expect a Forbidden exception.
        """
        ticket = make_login_ticket(req_class_ref = eduid_idp.assurance.SWAMID_AL2)
        # No NIN 1
        user = self.get_user_set_nins('test1@eduid.se', [])
        with self.assertRaises(eduid_idp.error.Forbidden):
            self.SSO_AL2._get_login_response_authn(ticket, user)
        # No NIN 2
        user = self.get_user_set_nins('test1@eduid.se', [])
        with self.assertRaises(eduid_idp.error.Forbidden):
            self.SSO_AL2._get_login_response_authn(ticket, user)
        # Invalid NIN
        with self.assertRaises(UserDBValueError):
            self.get_user_set_nins('test1@eduid.se', [False])

    def test__get_login_response_authn_3(self):
        """
        Test login with AL2, request plain AL3.

        Expect MustAuthenticate exception.
        """
        ticket = make_login_ticket(req_class_ref = eduid_idp.assurance.SWAMID_AL3)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        with self.assertRaises(eduid_idp.login.MustAuthenticate):
            self.SSO_AL2._get_login_response_authn(ticket, user)

    # ------------------------------------------------------------------------

    def test__get_login_response_authn_4_1(self):
        """
        Test login with AL1, request AL1 equivalent PASSWORD.

        Expect the response Authn to be AL1.
        PASSWORD is special in that it is mapped to AL1/AL2/AL3 in the response.
        """
        ticket = make_login_ticket(req_class_ref = PASSWORD)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL1._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL1, out['class_ref'])

    def test__get_login_response_authn_4_2(self):
        """
        Test login with AL2, request AL1 equivalent PASSWORD.

        Expect the response Authn to be AL1.
        PASSWORD is special in that it is mapped to AL1/AL2/AL3 in the response.
        """
        ticket = make_login_ticket(req_class_ref = PASSWORD)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL2._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL2, out['class_ref'])

    def test__get_login_response_authn_4_3(self):
        """
        Test login with AL3, request AL1 equivalent PASSWORD.

        We would have expected the response Authn to be AL3, but AL3 policy is not
        implemented yet so it should result in Forbidden for now.

        PASSWORD is special in that it is mapped to AL1/AL2/AL3 in the response.
        """
        ticket = make_login_ticket(req_class_ref = PASSWORD)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        with self.assertRaises(eduid_idp.error.Forbidden):
            self.SSO_AL3._get_login_response_authn(ticket, user)
        #self.assertEqual(eduid_idp.assurance.SWAMID_AL3, out['class_ref'])

    # ------------------------------------------------------------------------

    def test__get_login_response_authn_5_1(self):
        """
        Test login with AL1, request AL1 equivalent PASSWORDPROTECTEDTRANSPORT.

        Expect the response Authn to be the requested PASSWORDPROTECTEDTRANSPORT.
        """
        ticket = make_login_ticket(req_class_ref = PASSWORDPROTECTEDTRANSPORT)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL1._get_login_response_authn(ticket, user)
        self.assertEqual(PASSWORDPROTECTEDTRANSPORT, out['class_ref'])

    def test__get_login_response_authn_5_2(self):
        """
        Test login with AL2, request AL1 equivalent PASSWORDPROTECTEDTRANSPORT.

        Expect the response Authn to be the requested PASSWORDPROTECTEDTRANSPORT.
        """
        ticket = make_login_ticket(req_class_ref = PASSWORDPROTECTEDTRANSPORT)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL2._get_login_response_authn(ticket, user)
        self.assertEqual(PASSWORDPROTECTEDTRANSPORT, out['class_ref'])

    def test__get_login_response_authn_6_1(self):
        """
        Test login with AL1, request unknown context.

        Expect the response Authn to be AL1 (default response for unknown requested authn contexts is auth level).
        """
        ticket = make_login_ticket(req_class_ref = 'http://www.example.edu/assurance/UNKNOWN')
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL1._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL1, out['class_ref'])

    def test__get_login_response_authn_6_2(self):
        """
        Test login with AL2, request unknown context.

        Expect the response Authn to be AL2 (default response for unknown requested authn contexts is auth level).
        """
        ticket = make_login_ticket(req_class_ref = 'http://www.example.edu/assurance/UNKNOWN')
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        out = self.SSO_AL2._get_login_response_authn(ticket, user)
        self.assertEqual(eduid_idp.assurance.SWAMID_AL2, out['class_ref'])

    # ------------------------------------------------------------------------

    def test__get_login_response_authn_7_1(self):
        """
        Test login with AL1, request plain AL2.

        Expect MustAuthenticate exception.
        """
        ticket = make_login_ticket(req_class_ref = eduid_idp.assurance.SWAMID_AL2)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        with self.assertRaises(eduid_idp.login.MustAuthenticate):
            self.SSO_AL1._get_login_response_authn(ticket, user)

    def test__get_login_response_authn_7_2(self):
        """
        Test login with AL1, request AL2 equivalent MOBILETWOFACTORCONTRACT.

        Expect MustAuthenticate exception.
        """
        ticket = make_login_ticket(req_class_ref = MOBILETWOFACTORCONTRACT)
        user = self.get_user_set_nins('test1@eduid.se', ['123456780123'])
        with self.assertRaises(eduid_idp.login.MustAuthenticate):
            self.SSO_AL1._get_login_response_authn(ticket, user)

    # ------------------------------------------------------------------------

