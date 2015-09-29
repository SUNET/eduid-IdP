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
from unittest import TestCase
import cherrypy
from mock import patch
import webtest
from bson import ObjectId
from urlparse import urlsplit

import eduid_idp
from eduid_idp.tests.test_SSO import make_SAML_request
from eduid_idp.idp import IdPApplication

from eduid_userdb.testing import MongoTemporaryInstance


logger = logging.getLogger(__name__)


local = cherrypy.lib.httputil.Host('127.0.0.1', 50000, "")
remote = cherrypy.lib.httputil.Host('127.0.0.1', 50001, "")


TEST_ACTION = {
        '_id': ObjectId('234567890123456789012301'),
        'user_oid': ObjectId('123467890123456789014567'),
        'action': 'dummy',
        'preference': 100, 
        'params': {
            }
        }

TEST_USER = {
    '_id': ObjectId('123467890123456789014567'),
    'givenName': 'John',
    'sn': 'Smith',
    'displayName': 'John Smith',
    'norEduPersonNIN': ['197801011234'],
    'preferredLanguage': 'en',
    'eduPersonPrincipalName': 'hubba-bubba',
    'eduPersonEntitlement': [
        'urn:mace:eduid.se:role:admin',
        'urn:mace:eduid.se:role:student',
    ],
    'mobile': [],
    'mail': 'johnsmith@example.com',
    'mailAliases': [{
        'email': 'johnsmith@example.com',
        'verified': True,
    }],
    'passwords': [{
        'id': ObjectId('112345678901234567890123'),
        'salt': '$NDNv1H1$9c810d852430b62a9a7c6159d5d64c41c3831846f81b6799b54e1e8922f11545$32$32$',
    }],
    'postalAddress': [],
}


# noinspection PyProtectedMember
class TestActions(TestCase):

    @classmethod
    def setUpClass(cls):
        # This code was originally in the setUp method, but there was
        # something missing in the tearDown method to reset the IdP,
        # so only the first test would work. Subsequent tests would fail
        # due to some corruption in the config.

        # create a temporary mongo instance
        try:
            cls.tmp_db = MongoTemporaryInstance.get_instance(port=44444)
        except OSError:
            raise unittest.SkipTest("requires accessible mongod executable")
        cls.conn = cls.tmp_db.conn
        cls.port = cls.tmp_db.port

        # load the IdP configuration
        datadir = pkg_resources.resource_filename(__name__, 'data')
        cls.config_file = os.path.join(datadir, 'test_actions.ini')
        debug = False
        cls.config = eduid_idp.config.IdPConfig(cls.config_file, debug)

        # Create the IdP app
        cls.idp_app = IdPApplication(logger, cls.config)


    def setUp(self):
        # drop the mongo dbs
        for db_name in self.conn.database_names():
            self.conn.drop_database(db_name)

        # prevent the HTTP server from ever starting
        cherrypy.server.unsubscribe()
        # mount the IdP app in the cherrypy app server
        cherrypy.tree.mount(self.idp_app, '/')

        # create a webtest testing environment
        import cookielib
        self.http = webtest.TestApp(cherrypy.tree,
                extra_environ={'wsgi.url_scheme': 'https'},
                cookiejar=cookielib.CookieJar())

    def tearDown(self):
        # drop the mongo dbs
        for db_name in self.conn.database_names():
            self.conn.drop_database(db_name)
        # reset the testing environment
        self.http.reset()

    def test_no_actions(self):

        # insert a test user in the users db
        amdb = self.conn['eduid_am']
        amdb.attributes.insert(TEST_USER)

        # make the SAML authn request
        req = make_SAML_request(eduid_idp.assurance.SWAMID_AL1)

        # post the request to the test environment
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
        url = urlsplit(resp.location)
        url = '?'.join( (url.path, url.query) )

        # get the redirect url. set the cookies manually,
        # for some reason webtest doesn't set them in the request
        cookies = '; '.join(['{}={}'.format(k, v) for k, v
                              in self.http.cookies.items()])
        resp = self.http.get(resp.location, headers={'Cookie': cookies})
        self.assertEqual(resp.status, '200 Ok')
        self.assertIn('action="https://sp.example.edu/saml2/acs/"', resp.body)

    def test_action(self):

        # insert a test user in the users db
        amdb = self.conn['eduid_am']
        amdb.attributes.insert(TEST_USER)

        # insert a test action in the actions db
        actionsdb = self.conn['eduid_actions']
        actionsdb.actions.insert(TEST_ACTION)
        
        # make the SAML authn request
        req = make_SAML_request(eduid_idp.assurance.SWAMID_AL1)

        # post the request to the test environment
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
        url = urlsplit(resp.location)
        url = '?'.join( (url.path, url.query) )

        # get the redirect url. set the cookies manually,
        # for some reason webtest doesn't set them in the request
        cookies = '; '.join(['{}={}'.format(k, v) for k, v
                              in self.http.cookies.items()])
        resp = self.http.get(resp.location, headers={'Cookie': cookies})
        self.assertEqual(resp.status, '302 Found')
        self.assertIn(self.config.actions_app_uri, resp.location)

    def test_add_action(self):

        # insert a test user in the users db
        amdb = self.conn['eduid_am']
        amdb.attributes.insert(TEST_USER)

        # insert a test action in the actions db
        actionsdb = self.conn['eduid_actions']
        actionsdb.actions.insert(TEST_ACTION)

        # make the SAML authn request
        req = make_SAML_request(eduid_idp.assurance.SWAMID_AL1)

        resp = self.http.post('/sso/post', {'SAMLRequest': req})

        # grab the login form from the response
        form = resp.forms['login-form']

        # fill in the form and post it to the test env
        form['username'].value = 'johnsmith@example.com'
        form['password'].value = '123456'

        # Patch pkg_resources.iter_entry_points
        def mock_iep(name):
            if name == 'eduid_actions.add_actions':
                class inner():
                    name = 'dummy'
                    def load(self):
                        def action_test(idp_app, ticket):
                            actions = idp_app.actions_db._coll
                            dummy = {u'action': u'dummy',
                                    u'user_oid': ObjectId('123467890123456789014567'),
                                    u'params': {},
                                    u'preference': 100,
                                    u'session': ticket.key}
                            actions.insert(dummy)
                        return action_test
                return [inner()]
            else:
                import pkg_resources
                return [ep for ep in pkg_resources.iter_entry_points(name)]

        from eduid_idp import idp_actions
        with patch.object(idp_actions, 'iter_entry_points', mock_iep):

            # Patch the VCCSClient so we do not need a vccs server
            from vccs_client import VCCSClient
            with patch.object(VCCSClient, 'authenticate'):
                VCCSClient.authenticate.return_value = True

                # post the login form to the test env
                resp = form.submit()
                self.assertEqual(resp.status, '302 Found')
            url = urlsplit(resp.location)
            url = '?'.join( (url.path, url.query) )

            # get the redirect url. set the cookies manually,
            # for some reason webtest doesn't set them in the request
            cookies = '; '.join(['{}={}'.format(k, v) for k, v
                                  in self.http.cookies.items()])
            resp = self.http.get(resp.location, headers={'Cookie': cookies})
            self.assertEqual(resp.status, '302 Found')
            self.assertIn(self.config.actions_app_uri, resp.location)
