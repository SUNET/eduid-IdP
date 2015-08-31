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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

"""
User and user database module.
"""

from eduid_userdb import UserDB, User
from eduid_userdb.exceptions import UserDoesNotExist


class IdPUser(object):
    """
    Representation of a user. Used to load data about a user from the
    userdb, and then represent it in a readable way.

    :param username: username to search for in userdb
    :param userdb: user database instance
    :raise NoSuchUser: if 'username' was not found in the userdb

    :type username: str or unicode or ObjectId
    :type userdb: UserDB
    """

    def __init__(self, username, userdb):
        self._username = username
        _user = None
        if isinstance(username, str) or isinstance(username, unicode):
            if '@' in username:
                _user = userdb.get_user_by_mail(username.lower())
            if not _user:
                _user = userdb.get_user_by_eppn(username.lower())
        if not _user:
            # username will be ObjectId if this is a lookup using an existing SSO session
            _user = userdb.get_user_by_id(username)
        if not isinstance(_user, User):
            raise ValueError('Unknown User returned')
        self._user = _user

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
        return self._user.to_dict(old_userdb_format = True)

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

        If a user is halfway into the signup process, an account exists but
        has no passwords. Return empty list in that case.

        :return: User password credentials

        :rtype: [dict]
        """
        return self._user.passwords.to_list_of_dicts()


class IdPUserDb(object):
    """

    :param logger: logging logger
    :param config: IdP config
    :param userdb: User database

    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    """

    def __init__(self, logger, config, userdb = None):
        self.logger = logger
        self.config = config
        if userdb is None:
            userdb = UserDB(config.userdb_mongo_uri, db_name=config.userdb_mongo_database)
        self.userdb = userdb

    def lookup_user(self, username):
        """
        Load IdPUser from userdb.

        :param username: string
        :return: user found in database
        :rtype: IdPUser | None
        """
        try:
            return IdPUser(username, userdb = self.userdb)
        except UserDoesNotExist:
            return None
