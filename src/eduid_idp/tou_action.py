#
# Copyright (c) 2015 NORDUnet A/S
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

__author__ = 'eperez'


def add_actions(idp_app, user, ticket):
    """
    Add an action requiring the user to accept a new version of the Terms of Use,
    in case the IdP configuration points to a version the user hasn't accepted.

    This function is called by the IdP when it iterates over all the registered
    action plugins entry points.

    :param idp_app: IdP application instance
    :param user: the authenticating user
    :param ticket: the SSO login data

    :type idp_app: eduid_idp.idp.IdPApplication
    :type user: eduid_idp.idp_user.IdPUser
    :type ticket: eduid_idp.login.SSOLoginData

    :return: None
    """
    version = idp_app.config.tou_version

    if user.tou.has_accepted(version):
        idp_app.logger.debug('User has already accepted ToU version {!r}'.format(version))
        return

    if not idp_app.actions_db:
        idp_app.logger.warning('No actions_db - aborting ToU action')
        return None

    if not idp_app.actions_db.has_actions(user.eppn,
                                          action_type = 'tou',
                                          params = {'version': version}):
        idp_app.logger.debug('User must accept ToU version {!r}'.format(version))
        idp_app.actions_db.add_action(
            user.eppn,
            action_type = 'tou',
            preference = 100,
            params = {'version': version})
