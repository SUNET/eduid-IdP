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


import os
import six
import time
from importlib import import_module

import eduid_idp.util
import eduid_idp.mischttp

from eduid_idp.authn import AuthnData


def check_for_pending_actions(idp_app, user, ticket, sso_session):
    """
    Check whether there are any pending actions for the current user,
    and if there are, redirect to the actions app.

    The redirection is performed by raising an eduid_idp.mischttp.Redirect.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: SSOLoginData instance
    :param sso_session: SSOSession

    :type user: eduid_idp.idp_user.IdPUser
    :type idp_app: eduid_idp.idp.IdPApplication
    :type ticket: eduid_idp.loginstate.SSOLoginData
    :type sso_session: eduid_idp.sso_session.SSOSession

    :rtype: None
    """

    if idp_app.actions_db is None:
        idp_app.logger.info("This IdP is not initialized for special actions")
        return

    # Add any actions that may depend on the login data
    add_idp_initiated_actions(idp_app, user, ticket)

    actions = idp_app.actions_db.get_actions(eppn_or_userid = user.eppn, session = ticket.key)

    # Check for pending actions
    pending_actions = [a for a in actions if a.result is None]
    if not pending_actions:
        # eduid_action.mfa.idp.check_authn_result will have added the credential used
        # to the ticket.mfa_action_creds hash - transfer it to the session
        update = False
        for cred, ts in ticket.mfa_action_creds.items():
            authn = AuthnData(user = user, credential = cred, timestamp = ts)
            sso_session.add_authn_credential(authn)
            update = True

        if update:
            idp_app.IDP.cache.update_session(user.user_id, sso_session.to_dict())

        idp_app.logger.debug('There are no pending actions for user {}'.format(user))
        return

    # Pending actions found, redirect to the actions app
    idp_app.logger.debug('There are pending actions for user {}: {}'.format(user, pending_actions))

    # create auth token for actions app
    secret = idp_app.config.actions_auth_shared_secret
    nonce = os.urandom(16)
    if six.PY2:
        nonce = nonce.encode('hex')
    else:
        nonce = nonce.hex()
    timestamp = '{:x}'.format(int(time.time()))
    auth_token = eduid_idp.util.generate_auth_token(secret, user.eppn, nonce, timestamp)

    actions_uri = idp_app.config.actions_app_uri
    idp_app.logger.info("Redirecting user {!s} to actions app {!s}".format(user, actions_uri))

    actions_session = ticket.key
    uri = '{uri!s}?eppn={eppn!s}&token={auth_token!s}&nonce={nonce!s}&ts={ts!s}&session={session!s}'.format(
            uri = actions_uri,
            eppn = user.eppn,
            auth_token = auth_token,
            nonce = nonce,
            ts = timestamp,
            session = actions_session)
    raise eduid_idp.mischttp.Redirect(uri)


def add_idp_initiated_actions(idp_app, user, ticket):
    """
    Load the configured action plugins and execute their `add_actions`
    functions.
    These functions take the IdP app, the user, and the login data (ticket)
    and add actions that depend on those.

    Also iterate over add_actions entry points and execute them (for backwards
    compatibility).

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: the SSO login data

    :type idp_app: eduid_idp.idp.IdPApplication
    :type user: eduid_idp.idp_user.IdPUser
    :type ticket: eduid_idp.login.SSOLoginData
    """
    for plugin_name in idp_app.config.action_plugins:
        try:
            plugin_module = import_module('eduid_action.{}.idp'.format(plugin_name))
        except ImportError:
            idp_app.logger.warn('Configured plugin {} missing from sys.path'.format(plugin_name))
            continue
        idp_app.logger.debug('Using plugin {!r} to add new actions'.format(plugin_name))
        try:
            # load() here is the function eduid_action.mfa.add_mfa_actions()
            getattr(plugin_module, 'add_actions')(idp_app, user, ticket)
        except Exception as exc:
            idp_app.logger.warn('Error executing plugin {!r}: {!s}'.format(plugin_name, exc))
            raise
