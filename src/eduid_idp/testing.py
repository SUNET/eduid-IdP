#
# Copyright (c) 2015 NORDUnet A/S
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

import os
import pkg_resources
from unittest import TestCase

import eduid_idp
from eduid_idp.idp_user import IdPUser
from eduid_idp.idp import IdPApplication

from vccs_client import VCCSPasswordFactor

from saml2 import server

import logging
logger = logging.getLogger()

__author__ = 'ft'

PWHASHES = {}


def _create_passwords(username, factors):
    res = []
    for _f in factors:
        _this = {'credential_id': str(_f.credential_id),
                 'salt': _f.salt,
                 }
        res.append(_this)
        # remember the hash for the correct password 'out-of-band' since the User
        # object will reject any unknown data in _this
        PWHASHES[_this['credential_id']] = _f.hash
    return res


_PASSWORDS = [VCCSPasswordFactor("foo", "a" * 24),
              VCCSPasswordFactor("bar", "b" * 24),
              VCCSPasswordFactor("baz", "c" * 24),
              ]

_USERDB = [
    {'_id': '0' * 24,
     'eduPersonPrincipalName': 'test1@eduid.se',
     'mail': 'test@example.com',
     'mailAliases': [{
                         'email': 'test@example.com',
                         'verified': True,
                         }],
     'passwords': _create_passwords('user1', [_PASSWORDS[0], _PASSWORDS[1]])
    },
    {'_id': '1' * 24,
     'eduPersonPrincipalName': 'test2@eduid.se',
     'mail': 'test2@example.com',
     'mailAliases': [{
                         'email': 'test2@example.com',
                         'verified': True,
                         }],
     'passwords': _create_passwords('user2', [_PASSWORDS[2]]),
     }]


class FakeUserDb(object):
    def get_user_by_field(self, field, username, raise_on_missing=True):
        for _user in _USERDB:
            if _user.get(field) == username:
                res = IdPUser(data=_user)
                return res
            elif raise_on_missing:
                raise Exception('No user with username {} found'.format(username))

    def get_user_by_mail(self, email, raise_on_missing=True):
        return self.get_user_by_field('mail', email, raise_on_missing)

    def get_user_by_eppn(self, eppn, raise_on_missing=True):
        return self.get_user_by_field('eduPersonPrincipalName', eppn, raise_on_missing)


class FakeAuthClient(object):
    userdb = FakeUserDb()

    def authenticate(self, username, factors):
        assert (len(factors) == 1)
        _f = factors[0]
        _expect = {'credential_id': str(_f.credential_id),
                   'salt': _f.salt,
                   'hash': _f.hash,
        }
        for field in ['_id', 'eduPersonPrincipalName']:
            _user = self.userdb.get_user_by_field(field, username, raise_on_missing=False)
            if _user:
                for _cred in _user.passwords.to_list_of_dicts():
                    # restore the expected hash from out-of-band memory
                    _cred['hash'] = PWHASHES[_cred['credential_id']]
                    if _cred == _expect:
                        return True
        return False


class FakeConfig(object):
    mongo_uri = None


class FakeSAML2Server(server.Server):

    def __init__(self):
        # avoid all the init of saml2.server - we just want the simple functions
        pass


class FakeMetadata(object):
    """
    Fake the SAML2 Server metadata.
    """
    def entity_attributes(self, _name):
        return {}


class FakeIdPApp(IdPApplication):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.AUTHN_BROKER = eduid_idp.assurance.init_AuthnBroker('unittest-idp.example.edu')
        datadir = pkg_resources.resource_filename(__name__, 'tests/data')
        config_file = os.path.join(datadir, 'test_SSO_conf.py')
        self.IDP = server.Server(config_file=config_file)
        self.config = {}
        self.IDP.metadata = FakeMetadata()


class IdPSimpleTestCase(TestCase):
    """
    For simple test cases that do not need a real mongodb, but rather work with the
    in-memory FakeUserDb().
    """
    def setUp(self):
        config = FakeConfig()
        #noinspection PyTypeChecker
        self.idp_userdb = eduid_idp.idp_user.IdPUserDb(logger, config, userdb = FakeUserDb())
        self.authn = eduid_idp.authn.IdPAuthn(logger, config, self.idp_userdb,
                                              auth_client = FakeAuthClient())
