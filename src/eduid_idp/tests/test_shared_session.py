#!/usr/bin/python
#
# Copyright (c) 2014 NORDUnet A/S
#               2019 SUNET
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

import os
import logging
import pkg_resources

import cherrypy
from cherrypy.lib.sessions import init

from eduid_userdb.testing import MongoTestCase
from eduid_common.session.testing import RedisTemporaryInstance
from eduid_common.session.redis_session import RedisEncryptedSession

from eduid_idp.config import init_config
from eduid_idp.eduid_session import EduidSession


logger = logging.getLogger(__name__)


# noinspection PyProtectedMember
class TestSessions(MongoTestCase):

    def setUp(self):
        MongoTestCase.setUp(self)

        # load the IdP configuration
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.redis_instance = RedisTemporaryInstance.get_instance()
        _defaults = {
                'MONGO_URI': self.tmp_db.uri,
                'PYSAML2_CONFIG': os.path.join(datadir, 'test_SSO_conf.py'),
                'TOU_VERSION': 'mock-version',
                'SHARED_SESSION_SECRET_KEY': 'shared-session-secret-key',
                'REDIS_HOST': 'localhost',
                'REDIS_PORT': str(self.redis_instance.port),
                'INSECURE_COOKIES': False,
                'LISTEN_ADDR': 'unittest-idp.example.edu',
                'LISTEN_PORT': 443,
                'BASE_URL': 'https://unittest-idp.example.edu/',
                'CONTENT_PACKAGES': [('eduid_idp', 'tests/static')],
                'ACTION_PLUGINS': ['tou', 'mfa']
        }
        self.config = init_config(test_config=_defaults)
        cherrypy.config.logger = logger
        # mount the IdP app in the cherrypy app server
        cherry_conf = {
                'tools.sessions.on': True,
                'tools.sessions.storage_class': EduidSession,
                'tools.sessions.name': 'sessid',
                'tools.sessions.domain': 'unittest-idp.example.edu',
                'tools.sessions.secure': True,
                'tools.sessions.httponly': False,
                }
        cherry_conf.update(self.config)
        cherrypy.config.update(cherry_conf)

        init(storage_class=EduidSession, path='/', name="sessid",
             domain="unittest-idp.example.edu")

    def test_session(self):
        cherrypy.session['test'] = 'test'
        self.assertEquals(cherrypy.session._session._data['test'], 'test')
        self.assertTrue(isinstance(cherrypy.session._session, RedisEncryptedSession))

        token = cherrypy.session._session.token.encode('ascii')
        session_id, sig = RedisEncryptedSession.decode_token(token)
        cherrypy.session._session.commit()
        encrypted_session = cherrypy.session._session.conn.get(session_id.hex())
        session_data = cherrypy.session._session.verify_data(encrypted_session)
        self.assertEquals(session_data, {'test': 'test'})
