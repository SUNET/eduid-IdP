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
from typing import Optional, Dict

import time
from eduid_common.session.logindata import ExternalMfaData
from eduid_userdb.idp import IdPUser
from eduid_common.authn.idp_authn import AuthnData


class SSOSession(object):
    """
    Single Sign On sessions are used to remember a previous authenticaction
    performed, to avoid re-authenticating users for every Service Provider
    they visit.

    The references to 'authn' here are strictly about what kind of Authn
    the user has performed. The resulting SAML AuthnContext is a product
    of this, as well as other policy decisions (such as what ID-proofing
    has taken place, what AuthnContext the SP requested and so on).

    :param user_id: User id, typically MongoDB _id
    :param authn_request_id: SAML request id of request that caused authentication
    :param authn_credentials: Data about what credentials were used to authn
    :param ts: Authentication timestamp, in UTC

    :type user_id: bson.ObjectId | object
    :type authn_ref: object
    :type authn_request_id: string
    :type authn_credentials: None | [AuthnData]
    :type ts: int
    """

    def __init__(self, user_id, authn_request_id,
                 authn_credentials = None, ts=None, external_mfa=None):
        if ts is None:
            ts = int(time.time())
        self._data = {'user_id': user_id,
                      'authn_request_id': authn_request_id,
                      'authn_credentials': [],
                      'authn_timestamp': ts,
                      'external_mfa': None,
                      }
        if authn_credentials is not None:
            for x in authn_credentials:
                if isinstance(x, dict):
                    # reconstructing from storage
                    self._data['authn_credentials'] += [x]
                else:
                    self.add_authn_credential(x)
        if external_mfa is not None:
            if isinstance(external_mfa, dict):
                self._data['external_mfa'] = external_mfa
            else:
                self.external_mfa = external_mfa

        # Extra information not serialized
        self._idp_user = None

    def __repr__(self):
        return '<{cl} instance at {addr}: uid={uid!s}, ts={ts!s}>'.format(
            cl = self.__class__.__name__,
            addr = hex(id(self)),
            uid = str(self._data['user_id']),
            ts = self._data['authn_timestamp'],
        )

    def to_dict(self):
        """
        Return the object in dict format (serialized for storing in MongoDB).
        :return: serialized object
        :rtype: dict
        """
        return self._data

    @property
    def authn_timestamp(self):
        """
        Return the UTC UNIX timestamp for when the actual authentication took place.

        :return: Authn timestamp
        :rtype: int
        """
        return self._data['authn_timestamp']

    @property
    def user_id(self):
        """
        Return the user id (MongoDB _id) of the user for this SSO session.

        :rtype: bson.ObjectId
        """
        return self._data['user_id']

    @property
    def public_id(self):
        """
        Return a identifier for this session that can't be used to hijack sessions
        if leaked through a log file etc.
        """
        return "{!s}.{!s}".format(str(self._data['user_id']), self._data['authn_timestamp'])

    @property
    def user_authn_request_id(self):
        """
        Return the ID of the SAML request that caused the creation of the SSO session.

        E.g. u'id-809ecef1cd265efedef7a68708e54b84'
        """
        return self._data['authn_request_id']

    @property
    def idp_user(self):
        """
        Get the IdPUser object stored in the SSO session using set_user().

        :rtype: IdPUser
        """
        return self._idp_user

    def set_user(self, user):
        """
        Store the result of a userdb lookup.

        :param user: User object

        :type user: IdPUser
        """
        assert isinstance(user, IdPUser)
        self._idp_user = user

    @property
    def minutes_old(self):
        """
        Return the age of this SSO session, in minutes.

        :rtype: int
        """
        age = (int(time.time()) - self.authn_timestamp) / 60
        return age

    @property
    def authn_credentials(self):
        """
        Get the data about what credentials have been used (at what time) during
        this SSO session.

        :return: Used credentials information
        :rtype: [AuthnData]
        """
        return self._data['authn_credentials']

    def add_authn_credential(self, data):
        """
        Add information about a credential successfully used in this session.

        :param data: Authentication data
        :type data: AuthnData
        :return: None
        """
        if not isinstance(data, AuthnData):
            raise ValueError('data should be AuthnData (not {})'.format(type(data)))
        self._data['authn_credentials'] += [data.to_session_dict()]

    @property
    def external_mfa(self) -> Optional[ExternalMfaData]:
        """
        Get the data about any external service used for mfa.
        """
        if self._data['external_mfa'] is not None:
            return ExternalMfaData.from_session_dict(self._data['external_mfa'])
        return self._data['external_mfa']

    @external_mfa.setter
    def external_mfa(self, data: ExternalMfaData):
        self._data['external_mfa'] = data.to_session_dict()


def from_dict(data):
    """
    Re-create object from serialized format (after loading it from MongoDB).

    :param data: dict
    :return: SSO session object

    :type data: dict
    :rtype: SSOSession
    """
    return SSOSession(user_id = data['user_id'],
                      authn_request_id = data['authn_request_id'],
                      authn_credentials = data.get('authn_credentials'),
                      ts = data['authn_timestamp'],
                      external_mfa = data.get('external_mfa'),
                      )
