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
from bson import ObjectId
import pymongo

import eduid_idp.util


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

    # Add any actions that may depend on the login data
    actions_session = ticket.key
    SpecialActions(idp_app, ticket).add_actions()

    if idp_app.actions_db is None:
        idp_app.logger.info("This IdP is not initialized for special actions")
        return

    # Check for pending actions and redirect to the actions app
    # in case there are.
    if idp_app.actions_db.has_pending_actions(user.user_id):
        idp_app.logger.info("There are pending actions for userid {0}".format(
            str(user.user_id)))
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
            str(user.user_id), actions_uri))

        uri = '{0}?userid={1}&token={2}&nonce={3}&ts={4}&session={5}'.format(
                actions_uri, str(user.user_id), auth_token,
                nonce, timestamp, actions_session)
        raise eduid_idp.mischttp.Redirect(uri)
    else:
        idp_app.logger.info("There aren't pending actions for userid {0}".format(
            str(user.user_id)))


class SpecialActions(object):
    '''
    class that holds methods that add pending actions to the
    eduid_actions db.
    Each method can examine self.ticket to decide whether
    to add new actions.
    The names of these methods have to start with 'action_'

    XXX This functionality probably belongs in each actions
    plugin, that would then provide the logic for both the
    production and the consupmtion of actions.
    '''

    def __init__(self, idp_app, ticket):
        '''
        :param ticket: the SSO login data
        :type ticket: eduid_idp.login.SSOLoginData
        '''
        self.ticket = ticket
        self.idp_app = idp_app

    def add_actions(self):
        '''
        Iterate over the methods is this class that start with 'action_',
        and call them.
        '''
        for name, method in self.__class__.__dict__.items():
            if callable(method) and name.startswith('action_'):
                method(self)

    def action_test(self):
        '''
        Dummy method to be patched with real methods in tests
        '''
        pass
