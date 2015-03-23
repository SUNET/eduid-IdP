#
# Copyright (c) 2013, 2014 NORDUnet A/S
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
import time
import pymongo

import eduid_idp.util


DEFAULT_MONGODB_HOST = 'localhost'
DEFAULT_MONGODB_PORT = 27017
DEFAULT_MONGODB_NAME = 'eduid_actions'
DEFAULT_MONGODB_URI = 'mongodb://%s:%d/%s' % (DEFAULT_MONGODB_HOST,
                                              DEFAULT_MONGODB_PORT,
                                              DEFAULT_MONGODB_NAME)


class ActionsDB(object):
    """Simple wrapper to get pymongo real objects from the settings uri"""

    def __init__(self, logger, db_uri=DEFAULT_MONGODB_URI,
                 connection_factory=None, **kwargs):

        self.logger = logger
        if db_uri == "mongodb://":
            db_uri = DEFAULT_MONGODB_URI
        self.db_uri = db_uri

        self.parsed_uri = pymongo.uri_parser.parse_uri(db_uri)

        if 'replicaSet=' in db_uri:
            if 'socketTimeoutMS' not in kwargs:
                kwargs['socketTimeoutMS'] = 5000
            if 'connectTimeoutMS' not in kwargs:
                kwargs['connectTimeoutMS'] = 5000
            connection_factory = pymongo.MongoReplicaSetClient
        else:
            connection_factory = pymongo.MongoClient

        self.connection = connection_factory(
            host=self.db_uri,
            tz_aware=True,
            **kwargs)

        if self.parsed_uri.get("database", None):
            self.database_name = self.parsed_uri["database"]
        else:
            self.database_name = DEFAULT_MONGODB_NAME

    def get_connection(self):
        return self.connection

    def get_database(self, database_name=None, username=None, password=None):
        if database_name is None:
            db = self.connection[self.database_name]
        else:
            db = self.connection[database_name]
        if username and password:
            db.authenticate(username, password)
        elif self.parsed_uri.get("username", None):
            db.authenticate(
                self.parsed_uri.get("username", None),
                self.parsed_uri.get("password", None)
            )
        return db

    def pending_actions(self, user, session=None):
        '''
        Find out whether the user has pending actions.
        If session is None, search actions with no session,
        otherwise search actions with either no session
        or with the specified session.

        :param user: The user with possible pending actions
        :type user: eduid_idp.idp_user.IdPUser
        :param session: The actions session for the user
        :type session: str

        :rtype: bool
        '''
        userid = user.get_id()
        query = {'user_oid': userid}
        if session is None:
            query['session'] = {'$exists': False}
        else:
            query['session'] = {'$or': [{'$exists': False}, session]}
        actions = self.get_database().find(query)
        return actions.count() > 0


def check_for_pending_actions(idp_app, user, ticket):
    '''
    Check whether there are any pending actions for the current user,
    and if there are, redirect to the actions app.
    The redirection is performed by raising a eduid_idp.mischttp.Redirect.

    :param idp_app: IdP application instance
    :type idp_app: eduid_idp.idp.IdPApplication
    :param user: the authenticating user
    :type user: eduid_idp.idp_user.IdPUser
    :param ticket: SSOLoginData instance
    :type ticket: SSOLoginData

    :rtype: None
    '''

    actions_session = ticket.key
    SpecialActions(ticket).add_actions()

    # Check for pending actions and redirect to the actions app
    # in case there are.
    if idp_app.actions_db is not None and idp_app.actions_db.pending_actions():
        idp_app.logger.info("There are pending actions for userid {0}".format(
            user.get_id()))
        # create auth token for actions app
        eppn = user.identity.get('eduPersonPrincipalName')
        secret = idp_app.config.actions_auth_shared_secret
        timestamp = '{:x}'.format(int(time.time()))
        nonce = os.urandom(16).encode('hex')
        auth_token = eduid_idp.util.generate_auth_token(secret,
                                                        eppn,
                                                        nonce,
                                                        timestamp)
        actions_uri = idp_app.config.actions_app_uri
        idp_app.logger.info("Redirecting userid {0} to actions app {1}".format(
            user.get_id(), actions_uri))

        uri = '{0}?userid={1}&token={2}&nonce={3}&ts={4}&session={5}'.format(
                actions_uri, user.get_id(), auth_token,
                nonce, timestamp, actions_session)
        raise eduid_idp.mischttp.Redirect(uri)


class SpecialActions(object):
    '''
    class that holds methods that add pending actions to the
    eduid_actions db.
    Each method can examine self.sso_session to decide whether
    to add new actions.
    The names of these methods have to start with 'action_'
    '''

    def __init__(self, ticket):
        '''
        :param ticket: the SSO login data
        :type ticket: eduid_idp.login.SSOLoginData
        '''
        self.ticket = ticket

    def add_actions(self):
        '''
        Iterate over the methods is this class that start with 'action_',
        and call them.
        '''
        for name, method in self.__class__.__dict__.items():
            if callable(method) and name.startswith('action_'):
                method(self)
