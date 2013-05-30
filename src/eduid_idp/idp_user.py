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

import vccs_client
from eduid_am.celery import celery, get_attribute_manager

USERS = {
    "roland": {
        "sn": "Hedberg",
        "givenName": "Roland",
        "eduPersonScopedAffiliation": "staff@example.com",
        "eduPersonPrincipalName": "rohe@example.com",
        "uid": "rohe",
        "eduPersonTargetedID": "one!for!all",
        "c": "SE",
        "o": "Example Co.",
        "ou": "IT",
        "initials": "P",
        "schacHomeOrganization": "example.com",
        "email": "roland@example.com",
        "displayName": "P. Roland Hedberg",
        "labeledURL": "http://www.example.com/rohe My homepage",
        "norEduPersonNIN": "SE197001012222"
    },
    "babs": {
        "surname": "Babs",
        "givenName": "Ozzie",
        "eduPersonAffiliation": "affiliate"
    },
    "upper": {
        "surname": "Jeter",
        "givenName": "Derek",
        "eduPersonAffiliation": "affiliate",
        "eduPersonTargetedID": "youknowme",
    },
}

EXTRA = {
    "roland": {
        "eduPersonEntitlement": "urn:mace:swamid.se:foo:bar",
        "schacGender": "male",
        "schacUserPresenceID": "skype:pepe.perez"
    }
}


PASSWD = {"roland": "dianakra",
          "babs": "howes",
          "upper": "crust"}

class NoSuchUser(Exception):
    pass

class IdPUser():

    def __init__(self, username, userdb=None):
        self._username = username
        if username in USERS:
            self._data = USERS[username]
        else:
            if not userdb:
                raise NoSuchUser("Local user {!r} does not exist".format(username))
            self._data = userdb.get_user_by_field('eppn', username)

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
    def password_credential_id(self):
        return int(self._data['eduID_password_credential_id'])


class IdPUserDb():

    def __init__(self, logger, config):
        self.logger = logger
        self.config = config
        self.vccs_client = vccs_client.VCCSClient()
        self.userdb = None
        if config.userdb_mongo_uri:
            celery.conf.update({'MONGO_URI', config.userdb_mongo_uri})
            am = get_attribute_manager(celery)
            self.userdb = am.conn.get_database(config.userdb_mongo_database)

    def verify_username_and_password(self, username, password):
        # verify username and password
        if username in PASSWD:
            if PASSWD[username] == password:
                return IdPUser(username)
        else:
            user = IdPUser(username, userdb=self.userdb)
            factor = vccs_client.VCCSPasswordFactor(password, user.password_credential_id)
            if self.vccs_client.authenticate(username, [factor]):
                return user
        return None
