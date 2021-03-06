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

import datetime
import logging
import os

import eduid_common.authn
import eduid_userdb
import pkg_resources
import vccs_client
from bson import ObjectId
from eduid_common.api import exceptions
from eduid_common.config.idp import IdPConfig
from eduid_common.session.testing import RedisTemporaryInstance
from eduid_userdb.testing import MongoTestCase
from mock import patch

import eduid_idp
from eduid_idp.idp import IdPApplication
from eduid_idp.testing import IdPSimpleTestCase

logger = logging.getLogger(__name__)

eduid_common.authn.TESTING = True


class TestIdPUserDb(IdPSimpleTestCase):
    def test_lookup_user(self):
        _this = self.idp_userdb.lookup_user('test@example.com')
        self.assertEqual(_this.mail_addresses.primary.email, 'test@example.com')

    def test_lookup_user_eppn(self):
        _this = self.idp_userdb.lookup_user('test2@eduid.se')
        self.assertEqual(_this.mail_addresses.primary.email, 'test2@example.com')

    def test_password_authn(self):
        self.assertTrue(self._test_authn('test@example.com', 'foo'))
        self.assertTrue(self._test_authn('test@example.com', 'bar'))
        self.assertTrue(self._test_authn('test2@example.com', 'baz'))
        self.assertTrue(self._test_authn('test2@eduid.se', 'baz'))

    def test_verify_username_and_incorrect_password(self):
        self.assertFalse(self._test_authn('test@example.com', 'baz'))
        self.assertFalse(self._test_authn('test@example.com', 'rAnDoM'))

    def _test_authn(self, username, password):
        data = {
            'username': username,
            'password': password,
        }
        return self.authn.password_authn(data)


class TestAuthentication(MongoTestCase):
    def setUp(self):
        super(TestAuthentication, self).setUp()
        self.redis_instance = RedisTemporaryInstance.get_instance()

        # load the IdP configuration
        datadir = pkg_resources.resource_filename(__name__, 'data')
        _defaults = {
            'mongo_uri': self.tmp_db.uri,
            'pysaml2_config': os.path.join(datadir, 'test_SSO_conf.py'),
            'tou_version': 'mock-version',
            'shared_session_secret_key': 'shared-session-secret-key',
            'redis_host': 'localhost',
            'redis_port': str(self.redis_instance.port),
            'insecure_cookies': 1,
        }
        self.config = IdPConfig.init_config(test_config=_defaults, debug=True)

        # Create the IdP app
        self.idp_app = IdPApplication(logger, self.config)

        self.test_user = self.amdb.get_user_by_mail('johnsmith@example.com')
        assert isinstance(self.test_user, eduid_userdb.User)

    def test_authn_unknown_user(self):
        data = {
            'username': 'foo',
            'password': 'bar',
        }
        self.assertFalse(self.idp_app.authn.password_authn(data))

    @patch('vccs_client.VCCSClient.add_credentials')
    def test_authn_known_user_wrong_password(self, mock_add_credentials):
        mock_add_credentials.return_value = False
        assert isinstance(self.test_user, eduid_userdb.User)
        cred_id = ObjectId()
        factor = vccs_client.VCCSPasswordFactor('foo', str(cred_id), salt=None)
        self.idp_app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        data = {
            'username': self.test_user.mail_addresses.primary.email,
            'password': 'bar',
        }
        self.assertFalse(self.idp_app.authn.password_authn(data))

    @patch('vccs_client.VCCSClient.authenticate')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_authn_known_user_right_password(self, mock_add_credentials, mock_authenticate):
        mock_add_credentials.return_value = True
        mock_authenticate.return_value = True
        assert isinstance(self.test_user, eduid_userdb.User)
        passwords = self.test_user.credentials.to_list()
        factor = vccs_client.VCCSPasswordFactor('foo', str(passwords[0].key), salt=passwords[0].salt)
        self.idp_app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        data = {
            'username': self.test_user.mail_addresses.primary.email,
            'password': 'foo',
        }
        self.assertTrue(self.idp_app.authn.password_authn(data))

    @patch('vccs_client.VCCSClient.authenticate')
    @patch('vccs_client.VCCSClient.add_credentials')
    def test_authn_expired_credential(self, mock_add_credentials, mock_authenticate):
        mock_add_credentials.return_value = False
        mock_authenticate.return_value = True
        assert isinstance(self.test_user, eduid_userdb.User)
        passwords = self.test_user.credentials.to_list()
        factor = vccs_client.VCCSPasswordFactor('foo', str(passwords[0].key), salt=passwords[0].salt)
        self.idp_app.authn.auth_client.add_credentials(str(self.test_user.user_id), [factor])
        data = {
            'username': self.test_user.mail_addresses.primary.email,
            'password': 'foo',
        }
        # Store a successful authentication using this credential three year ago
        three_years_ago = datetime.datetime.now() - datetime.timedelta(days=3 * 365)
        self.idp_app.authn.authn_store.credential_success([passwords[0].key], three_years_ago)
        with self.assertRaises(exceptions.EduidForbidden):
            self.assertTrue(self.idp_app.authn.password_authn(data))
        # Do the same thing again to make sure we didn't accidentally update the
        # 'last successful login' timestamp when it was a successful login with an
        # expired credential.
        with self.assertRaises(exceptions.EduidForbidden):
            self.assertTrue(self.idp_app.authn.password_authn(data))
