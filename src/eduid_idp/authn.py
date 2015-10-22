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

import datetime
import vccs_client

import eduid_idp.assurance
import eduid_idp.error

from eduid_userdb import MongoDB, Password
from eduid_userdb.exceptions import UserHasNotCompletedSignup


class IdPAuthn(object):
    """

    :param logger: logging logger
    :param config: IdP configuration data

    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    """

    def __init__(self, logger, config, userdb, auth_client=None, authn_store=None):
        self.logger = logger
        self.config = config
        self.userdb = userdb
        self.auth_client = auth_client
        if self.auth_client is None:
            self.auth_client = vccs_client.VCCSClient(base_url = config.vccs_url)
        self.authn_store = authn_store
        if self.authn_store is None and config.mongo_uri:
            self.authn_store = AuthnInfoStoreMDB(uri = config.mongo_uri, logger = logger)

    def get_authn_user(self, login_data, user_authn):
        """
        Authenticate someone and, if successful, return the IdPUser object.

        :param login_data: Login credentials (dict with 'username' and 'password')
        :param user_authn: Information about the authentication attempted
        :return: User, if authenticated

        :type login_data: dict
        :type: user_authn: dict
        :rtype: IdPUser | None
        """
        if user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_1_NAME or \
                user_authn['class_ref'] == eduid_idp.assurance.EDUID_INTERNAL_2_NAME:
            user = self.verify_username_and_password(login_data)
        else:
            del login_data['password']  # keep out of any exception logs
            self.logger.info("Authentication for class {!r} not implemented".format(
                user_authn['class_ref']))
            raise eduid_idp.error.ServiceError("Authentication for class {!r} not implemented".format(
                user_authn['class_ref'], logger=self.logger))
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
        del data  # keep sensitive data out of Sentry logs

        user = self._verify_username_and_password2(username, password)
        if user:
            if len(password) >= min_length:
                return user
            self.logger.debug("User {!r} authenticated, but denied by password length constraints ({!r})".format(
                user, min_length))
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
        try:
            user = self.userdb.lookup_user(username)
        except UserHasNotCompletedSignup:
            # XXX Redirect user to some kind of info page
            user = None
        if not user:
            self.logger.info("Unknown user : {!r}".format(username))
            # XXX we effectively disclose there was no such user by the quick
            # response in this case. Maybe send bogus auth request to backends?
            return None
        self.logger.debug("Found user {!r}".format(user))

        if self.authn_store:  # requires optional configuration
            authn_info = self.authn_store.get_user_authn_info(user)
            if authn_info.failures_this_month() > self.config.max_authn_failures_per_month:
                self.logger.debug("User AuthN failures this month {!r} > {!r}".format(
                    authn_info.failures_this_month(), self.config.max_authn_failures_per_month))
                raise eduid_idp.error.TooManyRequests("Too Many Requests")

            # Optimize list of credentials to try based on which credentials the
            # user used in the last successful authentication. This optimization
            # is based on plain assumption, no measurements whatsoever.
            last_creds = authn_info.last_used_credentials()
            creds = sorted(user.passwords.to_list(), key=lambda x: x.id not in last_creds)
            if creds != user.passwords.to_list():
                self.logger.debug("Re-sorted list of credentials:\n{!r} into\n{!r}\nbased on last-used {!r}".format(
                    [x.id for x in user.passwords.to_list()],
                    [x.id for x in creds],
                    last_creds))
        else:
            creds = user.passwords.to_list()

        return self._authn_passwords(user, username, password, creds)

    def _authn_passwords(self, user, username, password, credentials):
        """
        Perform the final actual authentication of a user based on a list of (password) credentials.

        :param user: User object
        :param username: Username provided
        :param password: Password provided
        :param credentials: Authn credentials to try
        :return: User | None

        :type user: IdPUser
        :type username: string
        :type password: string
        :type credentials: [Password]
        :rtype: IdPUser | None
        """
        for cred in credentials:
            if isinstance(cred, Password):
                try:
                    factor = vccs_client.VCCSPasswordFactor(password, str(cred.id), str(cred.salt))
                except ValueError as exc:
                    self.logger.info("User {!r} password factor {!s} unusable: {!r}".format(username, cred.id, exc))
                    continue
                self.logger.debug("Password-authenticating {!r}/{!r} with VCCS: {!r}".format(
                    username, str(cred.id), factor))
                user_id = str(user.user_id)
                try:
                    if self.auth_client.authenticate(user_id, [factor]):
                        self.logger.debug("VCCS authenticated user {!r} (user_id {!r})".format(user, user_id))
                        self.log_authn(user, success=[cred.id], failure=[])
                        return user
                except vccs_client.VCCSClientHTTPError as exc:
                    if exc.http_code == 500:
                        self.logger.debug("VCCS credential {!r} might be revoked".format(cred.id))
                        continue
            else:
                self.logger.debug("Unknown credential: {!s}".format(cred))
        self.logger.debug("VCCS username-password authentication FAILED for user {!r}".format(user))
        self.log_authn(user, success=[], failure=[cred.id for cred in user.passwords.to_list()])
        return None

    def log_authn(self, user, success, failure):
        """
        Log user authn success as well as failures.

        :param user: User
        :param success: List of successfully authenticated credentials
        :param failure: List of failed credentials

        :type user: IdPUser
        :type success: [bson.ObjectId()]
        :type failure: [bson.ObjectId()]
        :rtype: None
        """
        if not self.authn_store:  # requires optional configuration
            return None
        if success:
            self.authn_store.credential_success(success)
        if success or failure:
            self.authn_store.update_user(user.user_id, success, failure)
        return None


class AuthnInfoStore(object):
    """
    Abstract AuthnInfoStore.
    """
    def __init__(self, logger):
        self.logger = logger


class AuthnInfoStoreMDB(AuthnInfoStore):
    """
    This is a MongoDB version of AuthnInfoStore().
    """

    def __init__(self, uri, logger, db_name = 'eduid_idp',
                 collection_name = 'authn_info',
                 **kwargs):
        AuthnInfoStore.__init__(self, logger)

        logger.debug("Setting up AuthnInfoStoreMDB with URI {!r}, db_name {!r}".format(uri, db_name))
        self._db = MongoDB(db_uri = uri, db_name = db_name)
        self.collection = self._db.get_collection(collection_name)

    def credential_success(self, cred_ids, ts=None):
        """
        Kantara AL2_CM_CSM#050 requires that any credential that is not used for
        a period of 18 months is disabled (taken to mean revoked).

        Therefor we need to log all successful authentications and have a cron
        job handling the revoking of unused ccredentials.

        :param cred_ids: List of Credential ID
        :param ts: Optional timestamp
        :return: None

        :type ts: datetime.datetime()
        :type cred_ids: [bson.ObjectId]
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        # Update all existing entrys in one go would've been nice, but pymongo does not
        # return meaningful data for multi=True, so it is not possible to figure out
        # which entrys were actually updated :(
        for this in cred_ids:
            self.collection.save(
                {
                    '_id': this,
                    'success_ts': ts,
                },
            )
        return None

    def update_user(self, user_id, success, failure, ts=None):
        """
        Log authentication result data for this user.

        The fail_count.month is logged to be able to lock users out after too
        many failed authentication attempts in a month (yet unspecific Kantara
        requirement).

        The success_count.month is logged for symmetry.

        The last_credential_ids are logged so that the IdP can sort
        the list of credentials giving preference to these the next
        time, to not load down the authentication backends with
        authentication requests for credentials the user might not
        be using (as often).

        :param user_id: User identifier
        :param success: List of Credential Ids successfully authenticated
        :param failure: List of Credential Ids for which authentication failed
        :param ts: Optional timestamp
        :return: None

        :type user_id: bson.ObjectId
        :type success: [bson.ObjectId]
        :type failure: [bson.ObjectId]
        :type ts: datetime.datetime()
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_and_modify(
            query = {
                '_id': user_id,
            }, update = {
                '$set': {
                    'success_ts': ts,
                    'last_credential_ids': success,
                },
                '$inc': {
                    'fail_count.' + str(this_month): len(failure),
                    'success_count.' + str(this_month): len(success)
                },
            }, upsert = True, new = True, multi = False)
        return None

    def get_user_authn_info(self, user):
        """
        Load stored Authn information for user.

        :param user: User object

        :type user: IdPUser
        :rtype: UserAuthnInfo
        """
        data = self.collection.find({'_id': user.user_id})
        if not data.count():
            return UserAuthnInfo({})
        return UserAuthnInfo(data[0])


class UserAuthnInfo(object):
    """
    Interpret data loaded from the AuthnInfoStore.
    """

    def __init__(self, data):
        self._data = data

    def failures_this_month(self, ts=None):
        """
        Return the number of failed login attempts for a user in a certain month.

        :param ts: Optional timestamp

        :return: Number of failed attempts

        :type ts: datetime.datetime
        :rtype: int
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        return self._data.get('fail_count', {}).get(str(this_month), 0)

    def last_used_credentials(self):
        """
        Get the credential IDs used in the last successful authentication for this user.

        :return: List of IDs

        :rtype: [bson.ObjectId]
        """
        return self._data.get('last_credential_ids', [])
