#!/usr/bin/python
#
# Copyright (c) 2013 NORDUnet A/S
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

import logging

from unittest import TestCase
from saml2.authn_context import MOBILETWOFACTORCONTRACT
from saml2.authn_context import PASSWORD
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import requested_authn_context

import eduid_idp

from eduid_idp.assurance import EDUID_INTERNAL_1
from eduid_idp.assurance import EDUID_INTERNAL_2
from eduid_idp.assurance import EDUID_INTERNAL_3
from eduid_idp.assurance import EDUID_INTERNAL_1_NAME
from eduid_idp.assurance import EDUID_INTERNAL_2_NAME
from eduid_idp.assurance import EDUID_INTERNAL_3_NAME


TEST_AL1 = 'http://www.example.com/policy/assurance/al1'
TEST_AL2 = 'http://www.example.com/policy/assurance/al2'
TEST_AL3 = 'http://www.example.com/policy/assurance/al3'

PUBLICKEYX509 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'


class TestCanonical_req_authn_context(TestCase):
    def setUp(self):
        self.logger = logging.getLogger()
        self.broker = eduid_idp.assurance.init_AuthnBroker('https://unittest.example.com/idp.xml')

        self._context_to_internal = {
            'undefined': EDUID_INTERNAL_1,  # the default entry, used on unknown RequestedAuthnContext
            # Level 1
            TEST_AL1: EDUID_INTERNAL_1,
            PASSWORD: EDUID_INTERNAL_1,
            UNSPECIFIED: EDUID_INTERNAL_1,
            # Level 2
            TEST_AL2: EDUID_INTERNAL_2,
            MOBILETWOFACTORCONTRACT: EDUID_INTERNAL_2,
            # Level 3
            TEST_AL3: EDUID_INTERNAL_3,
            PUBLICKEYX509: EDUID_INTERNAL_3,
        }

    def test_canonical_req_authn_context(self):
        """
        Test straight forward translations for each AL level.
        """
        req_authn_ctx = requested_authn_context(PASSWORD)
        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    self._context_to_internal)
        self.assertEqual(canon_ctx.authn_context_class_ref[0].text, EDUID_INTERNAL_1_NAME)

        req_authn_ctx = requested_authn_context(MOBILETWOFACTORCONTRACT)
        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    self._context_to_internal)
        self.assertEqual(canon_ctx.authn_context_class_ref[0].text, EDUID_INTERNAL_2_NAME)

        req_authn_ctx = requested_authn_context(TEST_AL3)
        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    self._context_to_internal)
        self.assertEqual(canon_ctx.authn_context_class_ref[0].text, EDUID_INTERNAL_3_NAME)

    def test_unknown_canonical_req_authn_context(self):
        """
        Test SP requesting unknown AuthnContext.
        """
        _context_to_internal = self._context_to_internal.copy()

        req_authn_ctx = requested_authn_context('http://www.example.org/homemadeassurancce')
        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    _context_to_internal)
        self.assertEqual(canon_ctx.authn_context_class_ref[0].text, EDUID_INTERNAL_1_NAME)

        # now, remove the 'undefined' entry
        del _context_to_internal['undefined']

        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    _context_to_internal)
        self.assertEqual(canon_ctx, None)

    def test_no_req_authn_context(self):
        """
        Test what happens when an SP does not request any AuthnContext at all.
        """
        req_authn_ctx = None
        canon_ctx = eduid_idp.assurance.canonical_req_authn_context(req_authn_ctx, self.logger,
                                                                    self._context_to_internal)
        self.assertEqual(canon_ctx.authn_context_class_ref[0].text, EDUID_INTERNAL_1_NAME)


class TestResponse_authn(TestCase):
    def setUp(self):
        self.logger = logging.getLogger()
        self.broker = eduid_idp.assurance.init_AuthnBroker('https://unittest.example.com/idp.xml')

        self._response_translation = {
            EDUID_INTERNAL_1_NAME: TEST_AL1,
            EDUID_INTERNAL_2_NAME: TEST_AL2,
            EDUID_INTERNAL_3_NAME: TEST_AL3,
            PASSWORD: {
                EDUID_INTERNAL_1_NAME: TEST_AL1,
                EDUID_INTERNAL_2_NAME: TEST_AL2,
                EDUID_INTERNAL_3_NAME: TEST_AL3,
            },
            UNSPECIFIED: TEST_AL1,
        }

    def test_response_authn_AL1_1(self):
        """
        Test SP asking for UNSPECIFIED (AL1), authn at AL2.
        Expect AuthnContext AL1 in response.
        """
        req_authn_ctx = requested_authn_context(UNSPECIFIED)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_2_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_1_NAME, EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], TEST_AL1)

    def test_response_authn_AL1_2(self):
        """
        Test SP not asking for anything, authn at AL2.
        Expect AuthnContext AL2 in response.
        """
        req_authn_ctx = None
        actual_authn = {
            'class_ref': EDUID_INTERNAL_2_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_1_NAME, EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], TEST_AL2)

    def test_response_authn_AL2_1(self):
        """
        Test SP asking for MOBILE (AL2), authn at AL2.
        Expect AuthnContext MOBILE in response.
        """
        req_authn_ctx = requested_authn_context(MOBILETWOFACTORCONTRACT)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_2_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], MOBILETWOFACTORCONTRACT)

    def test_response_authn_AL2_2(self):
        """
        Test SP asking for MOBILE (AL2), authn at AL3.
        Expect AuthnContext MOBILE in response.
        """
        req_authn_ctx = requested_authn_context(MOBILETWOFACTORCONTRACT)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_3_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], MOBILETWOFACTORCONTRACT)

    def test_response_authn_AL2_3(self):
        """
        Test SP asking for MOBILE (AL2), authn at AL1.
        Expect AuthnContext AL1 default class_ref in response.
        """
        req_authn_ctx = requested_authn_context(MOBILETWOFACTORCONTRACT)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_1_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], TEST_AL1)

    def test_response_authn_AL3_1(self):
        """
        Test SP asking for AL3, authn at AL3.
        Expect AuthnContext AL3 in response.
        """
        req_authn_ctx = requested_authn_context(TEST_AL3)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_3_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], TEST_AL3)

    def test_response_authn_AL3_2(self):
        """
        Test SP asking for PASSWORD, authn at AL3.
        Expect AuthnContext AL3 in response.
        """
        req_authn_ctx = requested_authn_context(PASSWORD)
        actual_authn = {
            'class_ref': EDUID_INTERNAL_3_NAME,
            'authn_auth': 'me'
        }
        auth_levels = [EDUID_INTERNAL_1_NAME, EDUID_INTERNAL_2_NAME, EDUID_INTERNAL_3_NAME]
        response_ctx = eduid_idp.assurance.response_authn(req_authn_ctx, actual_authn, auth_levels, self.logger,
                                                          response_contexts=self._response_translation)
        self.assertEqual(response_ctx['class_ref'], TEST_AL3)
