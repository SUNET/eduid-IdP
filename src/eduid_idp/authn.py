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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
Module handling authentication of users. Also applies login policies
such as rate limiting.
"""

import pprint
import vccs_client

import eduid_idp.assurance


class IdPAuthn(object):

    def __init__(self, logger, config, userdb, auth_client=None):
        self.logger = logger
        self.config = config
        self.userdb = userdb
        self.auth_client = auth_client
        if self.auth_client is None:
            self.auth_client = vccs_client.VCCSClient()

    def get_authn_user(self, login_data, user_authn, idp_app):
        user = None
        try:
            if user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_1_NAME:
                user = self.verify_username_and_password(login_data)
            elif user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_2_NAME:
                user = self.verify_username_and_password(login_data, min_length=12)
            else:
                del login_data['password']  # keep out of any exception logs
                idp_app.self.logger.info("Authentication for class {!r} not implemented".format(user_authn['class_ref']))
                raise eduid_idp.error.ServiceError("Authentication for class {!r} not implemented".format(
                    user_authn['class_ref'], logger=self.logger))
        except Exception:
            self.logger.error("Failed authenticating user", exc_info=1, extra={'stack': True})
        return user

    def verify_username_and_password(self, data, min_length=0):
        """
        :param data: dict() with POST parameters
        :param min_length: Minimum required length of password

        :return: IdPUser instance or False

        :type data: dict
        :rtype: IdPUser | False
        """
        username = data['username']
        password = data['password']

        user = self._verify_username_and_password2(username, password)
        if user:
            if len(password) >= min_length:
                return user
            self.logger.debug("User {!r} authenticated, but denied by password length constraints".format(user))
        return False

    def _verify_username_and_password2(self, username, password):
        """
        Attempt to verify that a password is valid for a specific user.

        Currently, the naive approach of looping through all the users password credentials
        is taken. This is bad because the more passwords a user has, the more likely an
        online attacker is to guess any one of them.
        :param username: identifier given by user, probably an e-mail address or eppn
        :param password: password given by user
        :return: IdPUser on successful authentication

        :type username: string
        :type password: string
        :rtype: IdPUser | None
        """
        user = self.userdb.lookup_user(username)
        if not user:
            self.logger.info("Unknown user : {!r}".format(username))
            # XXX we effectively disclose there was no such user by the quick
            # response in this case. Maybe send bogus auth request to backends?
            return None
        self.logger.debug("Found user {!r}".format(user))
        self.logger.debug("Extra debug: user {!r} attributes :\n{!s}".format(user, pprint.pformat(user.identity)))
        # XXX for now, try the password sequentially against all the users password credentials
        for cred in user.passwords:
            try:
                factor = vccs_client.VCCSPasswordFactor(password, str(cred['id']), str(cred['salt']))
            except ValueError as exc:
                self.logger.info("User {!r} password factor {!s} unusable: {!r}".format(username, cred['id'], exc))
                continue
            self.logger.debug("Password-authenticating {!r}/{!r} with VCCS: {!r}".format(
                username, str(cred['id']), factor))
            # Old credentials were created using the username (user['mail']) of the user
            # instead of the user['_id']. Try both during a transition period.
            user_ids = [str(user.identity['_id']), user.identity['mail']]
            if cred.get('user_id_hint') is not None:
                user_ids.insert(0, cred.get('user_id_hint'))
            for user_id in user_ids:
                try:
                    if self.auth_client.authenticate(user_id, [factor]):
                        self.logger.debug("VCCS authenticated user {!r} (user_id {!r})".format(user, user_id))
                        return user
                except vccs_client.VCCSClientHTTPError as exc:
                    if exc.http_code == 500:
                        self.logger.debug("VCCS credential {!r} might be revoked".format(cred['id']))
                        continue
        self.logger.debug("VCCS username-password authentication FAILED for user {!r}".format(user))
        return None
