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

"""
User and user database module.
"""

import pprint

import vccs_client
from eduid_am.celery import celery, get_attribute_manager


class NoSuchUser(Exception):
    """
    Exception raised when a user can't be found in the userdb.
    """
    pass


class IdPUser(object):
    """
    Representation of a user. Used to load data about a user from the
    userdb, and then represent it in a readable way.

    :param username: username to search for in userdb
    :param backend: user database instance, probably a Celery task
    :raise NoSuchUser: if 'username' was not found in the userdb

    :type username: string or ObjectId
    :type backend:
    """

    def __init__(self, username, backend):
        self._username = username
        self._data = None
        if isinstance(username, basestring):
            if '@' in username:
                self._data = backend.get_user_by_mail(username)
            if not self._data:
                self._data = backend.get_user_by_field('eduPersonPrincipalName', username)
        if not self._data:
            # username will be ObjectId if this is a lookup using an existing SSO session
            self._data = backend.get_user_by_id(username, raise_on_missing=False)
        if not self._data:
            raise NoSuchUser("User {!r} not found".format(username))
        assert isinstance(self._data, dict)

    def __repr__(self):
        return ('<{} instance at {:#x}: user={username!r}>'.format(
                self.__class__.__name__,
                id(self),
                username=self._username,
                ))

    @property
    def identity(self):
        """
        All the key-value pairs of this user in the user database.

        :return: Full user identity

        :rtype: dict
        """
        return self._data

    @property
    def username(self):
        """
        Primary identifying username for this user.

        :return: username

        :rtype: string
        """
        return self._username

    @property
    def passwords(self):
        """
        Return the password credentials for this user.
        This is a list of dicts with "salt" and "id" keys.
        """
        return self._data['passwords']


class IdPUserDb(object):
    """

    :param logger: logging logger
    :param config: IdP config
    :param backend: User database
    :param auth_client: VCCS authentication client

    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    :type auth_client: vccs_client.VCCSClient
    """

    def __init__(self, logger, config, backend = None, auth_client = None):
        self.logger = logger
        self.config = config
        self.auth_client = auth_client
        if auth_client is None:
            self.auth_client = vccs_client.VCCSClient()
        self.backend = backend
        if backend is None:
            if config.userdb_mongo_uri and config.userdb_mongo_database:
                settings = {'MONGO_URI': config.userdb_mongo_uri,
                            }
                celery.conf.update(settings)
            self.backend = get_attribute_manager(celery)

    def verify_username_and_password(self, username, password):
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

    def lookup_user(self, username):
        """
        Load IdPUser from userdb.

        :param username: string
        :return: user found in database
        :rtype: IdPUser | None
        """
        try:
            return IdPUser(username, backend = self.backend)
        except NoSuchUser:
            return None
