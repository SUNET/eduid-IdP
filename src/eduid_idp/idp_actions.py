#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
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

import time

import eduid_idp.util
import eduid_idp.mischttp

import eduid_idp.mfa_action
import eduid_idp.tou_action

from eduid_idp.authn import AuthnData
from eduid_idp.idp_user import IdPUser
from eduid_idp.context import IdPContext
from eduid_idp.loginstate import SSOLoginData
from eduid_idp.sso_session import SSOSession


def check_for_pending_actions(context: IdPContext, user: IdPUser, ticket: SSOLoginData,
                              sso_session: SSOSession) -> None:
    """
    Check whether there are any pending actions for the current user,
    and if there are, redirect to the actions app.

    The redirection is performed by raising an eduid_idp.mischttp.Redirect.

    :param context: IdP context
    :param user: the authenticating user
    :param ticket: SSOLoginData instance
    :param sso_session: SSOSession
    """

    if context.actions_db is None:
        context.logger.info("This IdP is not initialized for special actions")
        return

    # Add any actions that may depend on the login data
    add_idp_initiated_actions(context, user, ticket)

    actions_eppn = context.actions_db.get_actions(user.eppn, session = ticket.key)
    actions_userid = context.actions_db.get_actions(user.user_id, session = ticket.key)

    # Check for pending actions
    pending_actions = [a for a in actions_eppn if a.result is None]
    pending_actions += [a for a in actions_userid if a.result is None]
    if not pending_actions:
        # eduid_action.mfa.idp.check_authn_result will have added the credential used
        # to the ticket.mfa_action_creds hash - transfer it to the session
        update = False
        for cred, ts in ticket.mfa_action_creds.items():
            authn = AuthnData(user = user, credential = cred, timestamp = ts)
            sso_session.add_authn_credential(authn)
            update = True

        if update:
            context.sso_sessions.update_session(user.user_id, sso_session.to_dict())

        context.logger.debug('There are no pending actions for user {}'.format(user))
        return

    # Pending actions found, redirect to the actions app
    context.logger.debug('There are pending actions for user {}: {}'.format(user, pending_actions))

    ts = int(time.time())
    timestamp = '{:x}'.format(ts)

    actions_uri = context.config.actions_app_uri
    context.logger.info("Redirecting user {!s} to actions app {!s}".format(user, actions_uri))

    context.session['_implicit_login'] = {
            'ts': timestamp,
            'session': ticket.key
        }
    context.session.commit()
    raise eduid_idp.mischttp.Redirect(actions_uri)


def add_idp_initiated_actions(context: IdPContext, user: IdPUser, ticket: SSOLoginData):
    """
    Load the configured action plugins and execute their `add_actions`
    functions.
    These functions take the IdP app, the user, and the login data (ticket)
    and add actions that depend on those.

    Also iterate over add_actions entry points and execute them (for backwards
    compatibility).

    :param context: IdP context
    :param user: the authenticating user
    :param ticket: the SSO login data
    """
    if 'mfa' in context.config.action_plugins:
        eduid_idp.mfa_action.add_actions(context, user, ticket)
    if 'tou' in context.config.action_plugins:
        eduid_idp.tou_action.add_actions(context, user, ticket)
