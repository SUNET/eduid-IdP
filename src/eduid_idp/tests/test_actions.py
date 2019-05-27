#!/usr/bin/python
#
# Copyright (c) 2014 NORDUnet A/S
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
# Author : Enrique Perez <enrique@cazalla.net>
#

import os
import logging
import pkg_resources
from datetime import datetime

import six
import bson
import webtest
import cherrypy

from mock import patch

import eduid_idp
from eduid_idp.tests.test_SSO import make_SAML_request, make_login_ticket, SWAMID_AL2
from eduid_idp.tests.test_SSO import cc as CONTEXTCLASSREFS
from eduid_idp.idp import IdPApplication
from eduid_idp.config import init_config

import eduid_userdb
from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.tou import ToUEvent
from eduid_userdb.testing import MongoTestCase
from eduid_common.session.testing import RedisTemporaryInstance

from saml2.authn_context import PASSWORDPROTECTEDTRANSPORT


logger = logging.getLogger(__name__)

local = cherrypy.lib.httputil.Host('127.0.0.1', 50000, "")
remote = cherrypy.lib.httputil.Host('127.0.0.1', 50001, "")


class MockTicket:
    def __init__(self, key):
        self.key = key
        self.mfa_action_creds = {}


# noinspection PyProtectedMember
class TestActions(MongoTestCase):

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
        # Create the IdP app
        self.idp_app = IdPApplication(logger, self.config)
        # Actions db
        self.actions = self.idp_app.context.actions_db
        # setup some test data
        _email = 'johnsmith@example.com'
        self.test_user = self.amdb.get_user_by_mail(_email)
        self.test_action = self.actions.add_action(self.test_user.eppn,
                                                   action_type = 'dummy',
                                                   preference = 100,
                                                   params = {})


        # prevent the HTTP server from ever starting
        cherrypy.server.unsubscribe()
        # mount the IdP app in the cherrypy app server
        cherrypy.tree.mount(self.idp_app, '/')

        # create a webtest testing environment
        from six.moves.http_cookiejar import CookieJar
        self.http = webtest.TestApp(cherrypy.tree,
                                    extra_environ={'wsgi.url_scheme': 'https'},
                                    cookiejar=CookieJar())

    def tearDown(self):
        # reset the testing environment
        self.http.reset()
        MongoTestCase.tearDown(self)

    def _update_session(self):
        # make sure there is a redis common session ready to be used by the IdP
        session = self.idp_app.context.common_sessions._manager.get_session(data={'dummy':'data'})
        session.commit()
        self.idp_app._update_request_session(token=session.token)

    def test_no_actions(self):

        # Remove the standard test_action from the database
        self.actions.remove_action_by_id(self.test_action.action_id)

        # make the SAML authn request
        req = make_SAML_request(PASSWORDPROTECTEDTRANSPORT)

        # post the request to the test environment
        resp = self.http.post('/sso/post', {'SAMLRequest': req})

        # grab the login form from the response
        form = resp.forms['login-form']

        # fill in the form and post it to the test env
        _email = 'johnsmith@example.com'
        form['username'].value = _email
        form['password'].value = '123456'

        # Patch the VCCSClient so we do not need a vccs server
        from vccs_client import VCCSClient
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True

            # post the login form to the test env
            resp = form.submit()
            self.assertEqual(resp.status, '302 Found')

        # Register user acceptance for the ToU version in use
        tou = ToUEvent(version = self.config.get('TOU_VERSION'),
                       application = 'unit test',
                       created_ts = True,
                       event_id = bson.ObjectId(),
                       )
        user = self.amdb.get_user_by_mail(_email)
        assert(isinstance(user, eduid_userdb.User))
        user.tou.add(tou)
        self.amdb.save(user)

        # get the redirect url. set the cookies manually,
        # for some reason webtest doesn't set them in the request
        cookies = '; '.join(['{}={}'.format(k, v) for k, v
                             in self.http.cookies.items()])
        resp = self.http.get(resp.location, headers={'Cookie': cookies})
        self.assertEqual(resp.status, '200 Ok')
        self.assertIn(six.b('action="https://sp.example.edu/saml2/acs/"'), resp.body)

    def test_action_2(self):

        # make the SAML authn request
        req = make_SAML_request(PASSWORDPROTECTEDTRANSPORT)

        # make sure there is a common session
        self._update_session()

        # post the request to the test environment
        resp = self.http.post('/sso/post', {'SAMLRequest': req})

        # grab the login form from the response
        form = resp.forms['login-form']

        # fill in the form and post it to the test env
        form['username'].value = self.test_user.mail_addresses.primary.email
        form['password'].value = '123456'

        # Patch the VCCSClient so we do not need a vccs server
        from vccs_client import VCCSClient
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True

            # post the login form to the test env
            resp = form.submit()
            self.assertEqual(resp.status, '302 Found')

        # get the redirect url. set the cookies manually,
        # for some reason webtest doesn't set them in the request
        cookies = '; '.join(['{}={}'.format(k, v) for k, v
                             in self.http.cookies.items()])
        resp = self.http.get(resp.location, headers={'Cookie': cookies})
        self.assertEqual(resp.status, '302 Found')
        self.assertIn(self.config.get('ACTIONS_APP_URI'), resp.location)

    def test_add_action(self):

        # make the SAML authn request
        req = make_SAML_request(PASSWORDPROTECTEDTRANSPORT)

        # make sure there is a common session
        self._update_session()

        resp = self.http.post('/sso/post', {'SAMLRequest': req})

        # grab the login form from the response
        form = resp.forms['login-form']

        # fill in the form and post it to the test env
        form['username'].value = 'johnsmith@example.com'
        form['password'].value = '123456'

        # Patch the VCCSClient so we do not need a vccs server
        from vccs_client import VCCSClient
        with patch.object(VCCSClient, 'authenticate'):
            VCCSClient.authenticate.return_value = True

            # post the login form to the test env
            resp = form.submit()
            self.assertEqual(resp.status, '302 Found')

        # get the redirect url. set the cookies manually,
        # for some reason webtest doesn't set them in the request
        cookies = '; '.join(['{}={}'.format(k, v) for k, v
                             in self.http.cookies.items()])
        resp = self.http.get(resp.location, headers={'Cookie': cookies})
        self.assertEqual(resp.status, '302 Found')
        self.assertIn(self.config.get('ACTIONS_APP_URI'), resp.location)

    def test_add_mfa_action_no_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 0)

    def test_add_mfa_action_no_key_required_mfa(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=CONTEXTCLASSREFS['REFEDS_MFA'], context=self.idp_app.context,
                                        key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_mfa_action_old_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        u2f = U2F(version='U2F_V2',
                  app_id='https://dev.eduid.se/u2f-app-id.json',
                  keyhandle='test_key_handle',
                  public_key='test_public_key',
                  attest_cert='test_attest_cert',
                  description='test_description',
        )
        self.test_user.credentials.add(u2f)
        self.amdb.save(self.user, check_sync=False)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_mfa_action_new_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(keyhandle='test_key_handle',
                    credential_data='test_credential_data',
                    app_id='https://dev.eduid.se/u2f-app-id.json',
                    attest_obj='test_attest_obj',
                    description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.user, check_sync=False)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_mfa_action_no_db(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(keyhandle='test_key_handle',
                    credential_data='test_credential_data',
                    app_id='https://dev.eduid.se/u2f-app-id.json',
                    attest_obj='test_attest_obj',
                    description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.user, check_sync=False)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        with self.assertRaises(AttributeError):
            add_actions(self.idp_app, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 0)

    def _test_add_2nd_mfa_action(self, success=True, authn_context=True, cred_key=None, actions=0):
        self.actions.remove_action_by_id(self.test_action.action_id)
        webauthn = Webauthn(keyhandle='test_key_handle',
                    credential_data='test_credential_data',
                    app_id='https://dev.eduid.se/u2f-app-id.json',
                    attest_obj='test_attest_obj',
                    description='test_description',
        )
        self.test_user.credentials.add(webauthn)
        self.amdb.save(self.user, check_sync=False)
        cred = self.test_user.credentials.filter(Webauthn).to_list()[0]
        if cred_key is None:
            cred_key = cred.key
        completed_action = self.actions.add_action(self.test_user.eppn,
                                                   action_type = 'mfa',
                                                   preference = 100,
                                                   params = {},
                                                   session='mock-session')
        completed_action.result = {
            'cred_key': cred_key,
            'issuer': 'dummy-issuer',
            'success': success,
            'authn_context': authn_context
        }
        self.actions.update_action(completed_action)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), actions)
        return mock_ticket

    def test_add_mfa_action_already_authn(self):
        self._test_add_2nd_mfa_action(actions=0)

    def test_add_mfa_action_already_authn_not(self):
        ticket = self._test_add_2nd_mfa_action(success=False, actions=2)
        self.assertEquals(len(ticket.mfa_action_creds), 0)

    def test_add_2nd_mfa_action_no_context(self):
        ticket = self._test_add_2nd_mfa_action(authn_context=False, actions=0)
        self.assertEquals(len(ticket.mfa_action_creds), 1)

    def test_add_2nd_mfa_action_no_context_wrong_key(self):
        ticket = self._test_add_2nd_mfa_action(authn_context=False, cred_key='wrong key', actions=2)
        self.assertEquals(len(ticket.mfa_action_creds), 0)

    def test_add_tou_action(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_tou_action_already_accepted(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(ToUEvent(
            version = 'mock-version',
            application = 'test_tou_plugin',
            created_ts = datetime.utcnow(),
            event_id = event_id
        ))
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 0)

    def test_add_tou_action_already_accepted_other_version(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(ToUEvent(
            version = 'mock-version-2',
            application = 'test_tou_plugin',
            created_ts = datetime.utcnow(),
            event_id = event_id
        ))
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_tou_action_already_action(self):
        self.idp_app.context.actions_db.add_action(
            self.test_user.eppn,
            action_type = 'tou',
            preference = 100,
            params = {'version': 'mock-version'}
        )
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)

    def test_add_tou_action_already_action_other_version(self):
        self.idp_app.context.actions_db.add_action(
            self.test_user.eppn,
            action_type = 'tou',
            preference = 100,
            params = {'version': 'mock-version-2'}
        )
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 2)

    def test_add_tou_action_should_reaccept(self):
        event_id = bson.ObjectId()
        self.test_user.tou.add(ToUEvent(
            version = 'mock-version',
            application = 'test_tou_plugin',
            created_ts = datetime(2015, 9, 24, 1, 1, 1, 111111),
            modified_ts = datetime(2015, 9, 24, 1, 1, 1, 111111),
            event_id = event_id
        ))
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.tou_action import add_actions
        mock_ticket = make_login_ticket(req_class_ref=SWAMID_AL2, context=self.idp_app.context, key='mock-session')
        add_actions(self.idp_app.context, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 1)
