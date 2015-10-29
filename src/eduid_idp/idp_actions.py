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
import time
from pkg_resources import iter_entry_points

import eduid_idp.util


def check_for_pending_actions(idp_app, user, ticket):
    """
    Check whether there are any pending actions for the current user,
    and if there are, redirect to the actions app.

    The redirection is performed by raising an eduid_idp.mischttp.Redirect.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: SSOLoginData instance

    :type user: eduid_idp.idp_user.IdPUser
    :type idp_app: eduid_idp.idp.IdPApplication
    :type ticket: SSOLoginData

    :rtype: None
    """

    if idp_app.actions_db is None:
        idp_app.logger.info("This IdP is not initialized for special actions")
        return

    # Add any actions that may depend on the login data
    add_idp_initiated_actions(idp_app, user, ticket)

    # Check for pending actions
    if not idp_app.actions_db.has_pending_actions(user.user_id, clean_cache=True):
        idp_app.logger.debug("There are no pending actions for user {!s}".format(user))
        return

    # Pending actions found, redirect to the actions app
    idp_app.logger.debug("There are pending actions for user {!s}".format(user))

    # create auth token for actions app
    secret = idp_app.config.actions_auth_shared_secret
    nonce = os.urandom(16).encode('hex')
    timestamp = '{:x}'.format(int(time.time()))
    auth_token = eduid_idp.util.generate_auth_token(secret, user.user_id, nonce, timestamp)

    actions_uri = idp_app.config.actions_app_uri
    idp_app.logger.info("Redirecting user {!s} to actions app {!s}".format(user, actions_uri))

    actions_session = ticket.key
    uri = '{uri!s}?userid={user_id!s}&token={auth_token!s}&nonce={nonce!s}&ts={ts!s}&session={session!s}'.format(
            uri = actions_uri,
            user_id = user.user_id,
            auth_token = auth_token,
            nonce = nonce,
            ts = timestamp,
            session = actions_session)
    raise eduid_idp.mischttp.Redirect(uri)


def add_idp_initiated_actions(idp_app, user, ticket):
    """
    Iterate over add_actions entry points and execute them.
    These entry points take the IdP app and the login data (ticket)
    and add actions that depend on those.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: the SSO login data

    :type user: eduid_idp.idp_user.IdPUser
    :type idp_app: eduid_idp.idp.IdPApplication
    :type ticket: eduid_idp.login.SSOLoginData
    """
    for entry_point in iter_entry_points('eduid_actions.add_actions'):
        idp_app.logger.debug('Using entry point {!r} to add new actions'.format(entry_point.name))
        try:
            entry_point.load()(idp_app, user, ticket)
        except Exception as exc:
            idp_app.logger.warn('Error executing entry point {!r}: {!s}'.format(entry_point.name, exc))
