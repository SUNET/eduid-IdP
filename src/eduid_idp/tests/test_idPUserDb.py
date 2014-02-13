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
from vccs_client import VCCSPasswordFactor

import eduid_idp

logger = logging.getLogger()


def _create_passwords(username, factors):
    res = []
    for _f in factors:
        _this = {'id': _f.credential_id,
                 'salt': _f.salt,
                 'hash': _f.hash,
        }
        res.append(_this)
    return res


_PASSWORDS = [VCCSPasswordFactor("foo", "0"),
              VCCSPasswordFactor("bar", "1"),
              VCCSPasswordFactor("baz", "2"),
]

_USERDB = [
    {'_id': '0',
     'mail': 'test@example.com',
     'passwords': _create_passwords('user1', [_PASSWORDS[0], _PASSWORDS[1]])
    },
    {'_id': '1',
     'eduPersonPrincipalName': 'test2@eduid.se',
     'mail': 'test2@example.com',
     'passwords': _create_passwords('user1', [_PASSWORDS[2]]),
    }]


class FakeUserDb(object):
    def get_user_by_field(self, field, username):
        for _user in _USERDB:
            if _user.get(field)==username:
                return _user

    def get_user_by_mail(self, email):
        return self.get_user_by_field('mail', email)


class FakeAuthClient(object):
    userdb = FakeUserDb()

    def authenticate(self, username, factors):
        assert (len(factors)==1)
        _f = factors[0]
        _expect = {'id': _f.credential_id,
                   'salt': _f.salt,
                   'hash': _f.hash,
        }
        for field in ['mail', 'eduPersonPrincipalName']:
            _user = self.userdb.get_user_by_field(field, username)
            if _user:
                for _cred in _user['passwords']:
                    if _cred==_expect:
                        return True
        return False


class FakeConfig(object):
    authn_info_mongo_uri = None


class TestIdPUserDb(TestCase):
    def setUp(self):
        config = FakeConfig()
        #noinspection PyTypeChecker
        self.idp_userdb = eduid_idp.idp_user.IdPUserDb(logger, config, backend = FakeUserDb())
        self.authn = eduid_idp.authn.IdPAuthn(logger, config, self.idp_userdb,
                                              auth_client = FakeAuthClient())

    def test_lookup_user(self):
        _this = self.idp_userdb.lookup_user('test@example.com')
        self.assertEqual(_this.username, 'test@example.com')

    def test_lookup_user_eppn(self):
        _this = self.idp_userdb.lookup_user('test2@eduid.se')
        self.assertEqual(_this._data.get('mail'), 'test2@example.com')

    def test_verify_username_and_password(self):
        self.assertTrue(self._test_authn('test@example.com', 'foo'))
        self.assertTrue(self._test_authn('test@example.com', 'bar'))
        self.assertTrue(self._test_authn('test2@example.com', 'baz'))
        self.assertTrue(self._test_authn('test2@eduid.se', 'baz'))

        self.assertFalse(self._test_authn('test@example.com', 'baz'))
        self.assertFalse(self._test_authn('test@example.com', 'rAnDoM'))

    def _test_authn(self, username, password):
        data = {'username': username,
                'password': password,
                }
        return self.authn.verify_username_and_password(data,)