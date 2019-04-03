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

import six
import bson
import webtest
import cherrypy

from mock import patch

import eduid_idp
from eduid_idp.tests.test_SSO import make_SAML_request
from eduid_idp.idp import IdPApplication
from eduid_idp.mfa_action import add_actions
from eduid_idp.tou_action import add_actions

import eduid_userdb
from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.testing import MongoTestCase

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
        super().setUp()

        # load the IdP configuration
        datadir = pkg_resources.resource_filename(__name__, 'data')
        self.config_file = os.path.join(datadir, 'test_actions.ini')
        _defaults = eduid_idp.config._CONFIG_DEFAULTS
        _defaults['mongo_uri'] = self.tmp_db.uri
        _defaults['pysaml2_config'] = os.path.join(datadir, 'test_SSO_conf.py')
        self.config = eduid_idp.config.IdPConfig(self.config_file, debug=False, defaults=_defaults)

        # Create the IdP app
        self.idp_app = IdPApplication(logger, self.config)

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
        super(TestActions, self).tearDown()

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
        from eduid_userdb.tou import ToUEvent
        tou = ToUEvent(version = self.config.tou_version,
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
        self.assertIn(self.config.actions_app_uri, resp.location)

    def test_add_action(self):

        # make the SAML authn request
        req = make_SAML_request(PASSWORDPROTECTEDTRANSPORT)

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
        self.assertIn(self.config.actions_app_uri, resp.location)

    def test_add_mfa_action_no_key(self):
        self.actions.remove_action_by_id(self.test_action.action_id)
        from eduid_idp.mfa_action import add_actions
        mock_ticket = MockTicket(key='mock-session')
        add_actions(self.idp_app, self.test_user, mock_ticket)
        self.assertEquals(len(self.actions.get_actions(self.test_user.eppn, 'mock-session')), 0)

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
        mock_ticket = MockTicket(key='mock-session')
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
        mock_ticket = MockTicket(key='mock-session')
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
        mock_ticket = MockTicket(key='mock-session')
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
        mock_ticket = MockTicket(key='mock-session')
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
