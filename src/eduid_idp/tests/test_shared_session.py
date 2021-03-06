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

import logging
import os
import unittest

import cherrypy
from cherrypy.lib.sessions import expire, init
from eduid_common.config.idp import IdPConfig
from eduid_common.session.meta import SessionMeta
from eduid_common.session.namespaces import Common, LoginApplication
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.testing import RedisTemporaryInstance

from eduid_idp.shared_session import EduidSession

logger = logging.getLogger(__name__)


# noinspection PyProtectedMember
class TestSessions(unittest.TestCase):
    def setUp(self):
        # load the IdP configuration
        self.redis_instance = RedisTemporaryInstance.get_instance()
        _defaults = {
            'environment': 'test_suite',
            'tou_version': 'mock-version',
            'shared_session_secret_key': 'shared-session-secret-key',
            'redis_host': 'localhost',
            'redis_port': str(self.redis_instance.port),
            'redis_db': '0',
            'insecure_cookies': False,
            'listen_addr': 'unittest-idp.example.edu',
            'listen_port': 443,
            'base_url': 'https://unittest-idp.example.edu/',
            'content_packages': [('eduid_idp', 'tests/static')],
            'debug': False,
        }
        self.config = IdPConfig.init_config(test_config=_defaults)
        # mount the IdP app in the cherrypy app server
        cherry_conf = {
            'tools.sessions.on': True,
            'tools.sessions.storage_class': EduidSession,
            'tools.sessions.name': 'sessid',
            'tools.sessions.domain': 'unittest-idp.example.edu',
            'tools.sessions.secure': True,
            'tools.sessions.httponly': False,
        }
        cherry_conf.update(self.config.to_dict())
        cherrypy.config.update(cherry_conf)
        cherrypy.config.logger = logger

        name = 'sessid'

        if hasattr(cherrypy.request, '_session_init_flag'):
            del cherrypy.request._session_init_flag
        init(storage_class=EduidSession, path='/', name=name, domain="unittest-idp.example.edu")

    def tearDown(self):
        cherrypy.session.delete()
        del cherrypy.session

    def test_session(self):
        cherrypy.session['test'] = 'test'
        self.assertEqual(cherrypy.session._session._data['test'], 'test')
        self.assertTrue(isinstance(cherrypy.session._session, RedisEncryptedSession))
        cherrypy.session.load()
        cherrypy.session.save()

        cookie_val = cherrypy.session._session_meta.cookie_val
        token = SessionMeta.from_cookie(cookie_val, app_secret=self.config.shared_session_secret_key)
        encrypted_session = cherrypy.session._session.conn.get(token.session_id)
        session_data = cherrypy.session._session.decrypt_data(encrypted_session)
        self.assertEqual(session_data['test'], 'test')

    def test_session_namespace(self):
        cherrypy.session.common = Common(
            eppn='hubba-dubba', is_logged_in=True, login_source=LoginApplication(value='idp')
        )
        cherrypy.session.load()
        cherrypy.session.save()

        cookie_val = cherrypy.session._session_meta.cookie_val
        token = SessionMeta.from_cookie(cookie_val, app_secret=self.config.shared_session_secret_key)
        encrypted_session = cherrypy.session._session.conn.get(token.session_id)
        session_data = cherrypy.session._session.decrypt_data(encrypted_session)
        self.assertEqual(session_data['_common']['eppn'], 'hubba-dubba')
