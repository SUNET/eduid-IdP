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
from typing import Optional

import eduid_idp.error
import vccs_client
from eduid_common.authn import get_vccs_client
from eduid_common.idp.user import IdPUser
from eduid_userdb import MongoDB
from eduid_userdb.credentials import Password, U2F
from eduid_userdb.exceptions import UserHasNotCompletedSignup


class AuthnData(object):
    """
    Data about a successful authentication.

    Returned from functions performing authentication.
    """
    def __init__(self, user, credential, timestamp):
        self.user = user
        self.credential = credential
        self.timestamp = timestamp

    @property
    def user(self):
        """
        :rtype: IdPUser
        """
        return self._user

    @user.setter
    def user(self, value):
        """
        :type value: IdPUser
        """
        if not isinstance(value, IdPUser):
            raise ValueError('Invalid user (expect IdPUser, got {})'.format(type(value)))
        self._user = value

    @property
    def credential(self):
        """
        :rtype: Password | U2F
        """
        return self._credential

    @credential.setter
    def credential(self, value):
        """
        :type value: Password | U2F
        """
        # isinstance is broken here with Python2:
        #   ValueError: Invalid/unknown credential (got <class 'eduid_userdb.u2f.U2F'>)
        #if not isinstance(value, Password) or isinstance(value, U2F):
        if not hasattr(value, 'key'):
            raise ValueError('Invalid/unknown credential (got {})'.format(type(value)))
        self._credential = value

    @property
    def timestamp(self):
        """
        :rtype: datetime.datetime
        """
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        """
        :type value: datetime.datetime
        """
        if not isinstance(value, datetime.datetime):
            raise ValueError('Invalid timestamp (expect datetime, got {})'.format(type(value)))
        self._timestamp = value.replace(tzinfo = None)  # thanks for not having timezone.utc, Python2

    def to_session_dict(self):
        return {'cred_id': self.credential.key,
                'authn_ts': self.timestamp,
                }


class IdPAuthn(object):
    """
    :param logger: logging logger
    :param config: IdP configuration data

    :type logger: logging.Logger
    :type config: IdPConfig
    """

    def __init__(self, logger, config, userdb, auth_client=None, authn_store=None):
        self.logger = logger
        self.config = config
        self.userdb = userdb
        self.auth_client = auth_client
        if self.auth_client is None:
            self.auth_client = get_vccs_client(config.vccs_url)
        self.authn_store = authn_store
        if self.authn_store is None and config.mongo_uri:
            self.authn_store = AuthnInfoStoreMDB(uri = config.mongo_uri, logger = logger)

    def password_authn(self, data: dict) -> Optional[AuthnData]:
        """
        Authenticate someone using a username and password.

        :param login_data: Login credentials (dict with 'username' and 'password')
        :returns: AuthnData on success
        """
        username = data['username']
        password = data['password']
        del data  # keep sensitive data out of Sentry logs

        try:
            user = self.userdb.lookup_user(username)
        except UserHasNotCompletedSignup:
            # XXX Redirect user to some kind of info page
            return None
        if not user:
            self.logger.info('Unknown user : {!r}'.format(username))
            # XXX we effectively disclose there was no such user by the quick
            # response in this case. Maybe send bogus auth request to backends?
            return None
        self.logger.debug('Found user {!r}'.format(user))

        cred = self._verify_username_and_password2(user, password)
        if not cred:
            return None

        return AuthnData(user, cred, datetime.datetime.utcnow())

    def _verify_username_and_password2(self, user, password):
        """
        Attempt to verify that a password is valid for a specific user.

        Currently, the naive approach of looping through all the users password credentials
        is taken. This is bad because the more passwords a user has, the more likely an
        online attacker is to guess any one of them.
        :param username: identifier given by user, probably an e-mail address or eppn
        :param password: password given by user
        :return: IdPUser on successful authentication

        :type user: IdPUser
        :type password: string
        :rtype: Credential | None
        """
        pw_credentials = user.credentials.filter(Password).to_list()
        if self.authn_store:  # requires optional configuration
            authn_info = self.authn_store.get_user_authn_info(user)
            if authn_info.failures_this_month() > self.config.max_authn_failures_per_month:
                self.logger.info("User {!r} AuthN failures this month {!r} > {!r}".format(
                    user, authn_info.failures_this_month(), self.config.max_authn_failures_per_month))
                raise eduid_idp.error.TooManyRequests("Too Many Requests")

            # Optimize list of credentials to try based on which credentials the
            # user used in the last successful authentication. This optimization
            # is based on plain assumption, no measurements whatsoever.
            last_creds = authn_info.last_used_credentials()
            sorted_creds = sorted(pw_credentials, key=lambda x: x.credential_id not in last_creds)
            if sorted_creds != pw_credentials:
                self.logger.debug("Re-sorted list of credentials into\n{}\nbased on last-used {!r}".format(
                    sorted_creds,
                    last_creds))
                pw_credentials = sorted_creds

        return self._authn_passwords(user, password, pw_credentials)

    def _authn_passwords(self, user, password, pw_credentials):
        """
        Perform the final actual authentication of a user based on a list of (password) credentials.

        :param user: User object
        :param password: Password provided
        :param pw_credentials: Password credentials to try
        :return: Credential used, or None if authentication failed

        :type user: IdPUser
        :type password: string
        :type pw_credentials: [Password]
        :rtype: Password | None
        """
        for cred in pw_credentials:
            try:
                factor = vccs_client.VCCSPasswordFactor(password, str(cred.credential_id), str(cred.salt))
            except ValueError as exc:
                self.logger.info("User {} password factor {!s} unusable: {!r}".format(
                    user, cred.credential_id, exc))
                continue
            self.logger.debug("Password-authenticating {}/{!r} with VCCS: {!r}".format(
                user, str(cred.credential_id), factor))
            user_id = str(user.user_id)
            try:
                if self.auth_client.authenticate(user_id, [factor]):
                    self.logger.debug("VCCS authenticated user {} (user_id {!r})".format(user, user_id))
                    # Verify that the credential had been successfully used in the last 18 monthts
                    # (Kantara AL2_CM_CSM#050).
                    if self.credential_expired(cred):
                        self.logger.info('User {} credential {!r} has expired'.format(user, cred.key))
                        raise eduid_idp.error.Forbidden('CREDENTIAL_EXPIRED')
                    self.log_authn(user, success=[cred.credential_id], failure=[])
                    return cred
            except vccs_client.VCCSClientHTTPError as exc:
                if exc.http_code == 500:
                    self.logger.debug("VCCS credential {!r} might be revoked".format(cred.credential_id))
                    continue
        self.logger.debug('VCCS username-password authentication FAILED for user {}'.format(user))
        self.log_authn(user, success=[], failure=[cred.credential_id for cred in pw_credentials])
        return None

    def credential_expired(self, cred):
        """
        Check that a credential hasn't been unused for too long according to Kantara AL2_CM_CSM#050.
        :param cred: Authentication credential

        :type cred: Password
        :rtype: bool
        """
        if not self.authn_store:  # requires optional configuration
            self.logger.debug("Can't check if credential {!r} is expired, no authn_store available".format(cred.key))
            return False
        last_used = self.authn_store.get_credential_last_used(cred.credential_id)
        if last_used is None:
            # Can't disallow this while there is a short-path from signup to dashboard unforch...
            self.logger.debug('Allowing never-used credential {!r}'.format(cred))
            return False
        now = datetime.datetime.utcnow().replace(tzinfo = None)  # thanks for not having timezone.utc, Python2
        delta = now - last_used.replace(tzinfo = None)
        self.logger.debug("Credential {} last used {!r} days ago".format(cred.key, delta.days))
        return delta.days >= int(365 * 1.5)

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

    def __init__(self, uri, logger, db_name = 'eduid_idp_authninfo',
                 collection_name = 'authn_info',
                 **kwargs):
        AuthnInfoStore.__init__(self, logger)

        logger.debug("Setting up AuthnInfoStoreMDB")
        self._db = MongoDB(db_uri = uri, db_name = db_name)
        self.collection = self._db.get_collection(collection_name)

    def credential_success(self, cred_ids, ts=None):
        """
        Kantara AL2_CM_CSM#050 requires that any credential that is not used for
        a period of 18 months is disabled (taken to mean revoked).

        Therefor we need to log all successful authentications and have a cron
        job handling the revoking of unused credentials.

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
        :type ts: datetime.datetime() | None
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

    def unlock_user(self, user_id, fail_count = 0, ts=None):
        """
        Set the fail count for a specific user and month.

        Used from the CLI `unlock_user`.

        :param user_id: User identifier
        :param fail_count: Number of failed attempts to put the user at
        :param ts: Optional timestamp

        :type user_id: bson.ObjectId
        :type fail_count: int
        :type ts: datetime.datetime() | None

        :return: None
        """
        if ts is None:
            ts = datetime.datetime.utcnow()
        this_month = (ts.year * 100) + ts.month  # format year-month as integer (e.g. 201402)
        self.collection.find_and_modify(
            query = {
                '_id': user_id,
            }, update = {
                '$set': {
                    'fail_count.' + str(this_month): fail_count,
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

    def get_credential_last_used(self, cred_id):
        """
        Get the timestamp for when a specific credential was last used successfully.

        :param cred_id: Id of credential
        :type cred_id: bson.ObjectId

        :return: None | datetime.datetime
        """
        # Locate documents written by credential_success() above
        data = self.collection.find({'_id': cred_id})
        if not data.count():
            return None
        return data[0]['success_ts']


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

        :type ts: datetime.datetime | None
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
