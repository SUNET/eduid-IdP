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
import pprint

from six import string_types

from eduid_userdb import UserDB, User

# default list of SAML attributes to release
_SAML_ATTRIBUTES = ['displayName',
                    'eduPersonAssurance',
                    'eduPersonEntitlement',
                    'eduPersonPrincipalName',
                    'eduPersonScopedAffiliation',
                    'givenName',
                    'mail',
                    'norEduPersonNIN',
                    'preferredLanguage',
                    'sn',
                    ]


class IdPUser(User):
    """
    Wrapper class for eduid_userdb.User adding functions useful in the IdP.
    """

    def to_saml_attributes(self, config, logger, filter_attributes=_SAML_ATTRIBUTES):
        """
        Return a list of SAML attributes for a user.

        Note that this is _all_ parts of the user that this IdP knows how to express as
        SAML attributes. It is not necessarily the attributes that will actually be released.

        :param config: IdP config
        :param logger: logging logger
        :param filter_attributes: Filter to apply

        :type config: eduid_idp.config.IdPConfig
        :type logger: logging.Logger
        :type filter_attributes: [str | unicode]

        :return: SAML attributes
        :rtype: dict
        """
        attributes_in = self.to_dict(old_userdb_format = True)
        attributes = {}
        for approved in filter_attributes:
            if approved in attributes_in:
                attributes[approved] = attributes_in.pop(approved)
        logger.debug('Discarded non-attributes:\n{!s}'.format(pprint.pformat(attributes_in)))
        attributes1 = _make_scoped_eppn(attributes, config)
        attributes2 = _add_scoped_affiliation(attributes1, config)
        attributes = _add_eduperson_assurance(attributes2, self)
        return attributes


class IdPUserDb(object):
    """

    :param logger: logging logger
    :param config: IdP config
    :param userdb: User database

    :type logger: logging.Logger
    :type config: eduid_idp.config.IdPConfig
    :type userdb: eduid_userdb.UserDB
    """

    def __init__(self, logger, config, userdb = None):
        self.logger = logger
        self.config = config
        if userdb is None:
            userdb = UserDB(config['MONGO_URI'], db_name=config['USERDB_MONGO_DATABASE'], user_class=IdPUser)
        self.userdb = userdb

    def lookup_user(self, username):
        """
        Load IdPUser from userdb.

        :param username: string
        :return: user found in database
        :rtype: IdPUser | None
        """
        _user = None
        if isinstance(username, string_types):
            if '@' in username:
                _user = self.userdb.get_user_by_mail(username.lower(), raise_on_missing=False)
            if not _user:
                _user = self.userdb.get_user_by_eppn(username.lower(), raise_on_missing=False)
        if not _user:
            # username will be ObjectId if this is a lookup using an existing SSO session
            _user = self.userdb.get_user_by_id(username, raise_on_missing=False)
        return _user


def _make_scoped_eppn(attributes, config):
    """
    Add scope to unscoped eduPersonPrincipalName attributes before relasing them.

    What scope to add, if any, is currently controlled by the configuration parameter
    `default_eppn_scope'.

    :param attributes: Attributes of a user
    :param config: IdP configuration data
    :return: New attributes

    :type attributes: dict
    :type config: IdPConfig
    :rtype: dict
    """
    eppn = attributes.get('eduPersonPrincipalName')
    scope = config['DEFAULT_EPPN_SCOPE']
    if not eppn or not scope:
        return attributes
    if '@' not in eppn:
        attributes['eduPersonPrincipalName'] = eppn + '@' + scope
    return attributes


def _add_scoped_affiliation(attributes, config):
    """
    Add eduPersonScopedAffiliation if configured, and not already present.

    This default affiliation is currently controlled by the configuration parameter
    `default_scoped_affiliation'.

    :param attributes: Attributes of a user
    :param config: IdP configuration data

    :type attributes: dict
    :type config: IdPConfig

    :return: New attributes
    :rtype: dict
    """
    epsa = 'eduPersonScopedAffiliation'
    if epsa not in attributes and config.get('DEFAULT_SCOPED_AFFILIATION'):
        attributes[epsa] = config['DEFAULT_SCOPED_AFFILIATION']
    return attributes


def _add_eduperson_assurance(attributes, user):
    """
    Add an eduPersonAssurance attribute indicating the level of id-proofing
    a user has achieved, regardless of current session authentication strength.

    :param attributes: Attributes of a user
    :param user: The user in question

    :type attributes: dict
    :type user: IdPUser

    :return: New attributes
    :rtype: dict
    """
    attributes['eduPersonAssurance'] = 'http://www.swamid.se/policy/assurance/al1'
    _verified_nins = [x for x in user.nins.to_list() if x.is_verified]
    if _verified_nins:
        attributes['eduPersonAssurance'] = 'http://www.swamid.se/policy/assurance/al2'
    return attributes
