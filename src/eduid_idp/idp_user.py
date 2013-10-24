#
# Copyright (c) 2013 NORDUnet A/S
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

import pprint

import vccs_client
from eduid_am.celery import celery, get_attribute_manager


class NoSuchUser(Exception):
    pass


class IdPUser():

    def __init__(self, username, userdb=None):
        self._username = username
        for field in ['mail', 'eduPersonPrincipalName']:
            self._data = userdb.get_user_by_field(field, username)
            if self._data:
                break
        if not self._data:
            raise NoSuchUser("User {!r} not found".format(username))

    def __repr__(self):
        return ('<{} instance at {:#x}: user={username!r}>'.format(
                self.__class__.__name__,
                id(self),
                username=self._username,
                ))

    @property
    def identity(self):
        return self._data

    @property
    def username(self):
        return self._username

    @property
    def passwords(self):
        """
        Return the password credentials for this user.
        This is a list of dicts with "salt" and "id" keys.
        """
        return self._data['passwords']


class IdPUserDb():

    def __init__(self, logger, config, userdb = None, auth_client = None):
        self.logger = logger
        self.config = config
        self.auth_client = auth_client
        if auth_client is None:
            self.auth_client = vccs_client.VCCSClient()
        self.userdb = userdb
        if userdb is None:
            if config.userdb_mongo_uri and config.userdb_mongo_database:
                settings = {'MONGO_URI': config.userdb_mongo_uri,
                            }
                celery.conf.update(settings)
            self.userdb = get_attribute_manager(celery)

    def verify_username_and_password(self, username, password):
        """
        Attempt to verify that a password is valid for a specific user.

        Currently, the naive approach of looping through all the users password credentials
        is taken. This is bad because the more passwords a user has, the more likely an
        online attacker is to guess any one of them.
        :param username: string
        :param password: string
        :return: IdPUser on successful authentication
        """
        user = self.lookup_user(username)
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
                self.logger.info("User {!r} password factor {!s} unusable : {!r}".format(username, cred['id'], exc))
                continue
            self.logger.debug("Password-authenticating {!r}/{!r} with VCCS : {!r}".format(
                    username, cred['id'], factor))
            if self.auth_client.authenticate(username, [factor]):
                self.logger.debug("VCCS authenticated user {!r}".format(user))
                return user
        self.logger.debug("VCCS username-password authentication FAILED for user {!r}".format(user))
        return None

    def lookup_user(self, username):
        """
        Load IdPUser from userdb.

        :param username: string
        :return: IdPUser or None
        """
        try:
            return IdPUser(username, userdb=self.userdb)
        except NoSuchUser:
            return None
