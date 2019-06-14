#
# Copyright (c) 2013, 2014, 2016 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

import pprint
from datetime import datetime
from html import escape
from logging import Logger
from typing import Dict, Mapping, Optional, Union
from urllib.parse import urlencode

from eduid_common.config.cherrypy_idp import IdPConfig
from eduid_common.session.idp_cache import ExpiringCache, ExpiringCacheCommonSession, ExpiringCacheMem
from eduid_idp.authn import ExternalMfaData
from eduid_common.authn.idp_saml import IdP_SAMLRequest
from eduid_userdb.credentials import Credential


class SSOLoginData(object):
    """
    Class to hold data about an ongoing login process - i.e. data relating to a
    particular IdP visitor in the process of logging in, but not yet fully logged in.

    :param key: unique reference for this instance
    :param req_info: pysaml2 AuthnRequest data
    :param data: dict
    """
    def __init__(self, key: str, saml_req: IdP_SAMLRequest, relay_state: str = '', fail_count: int = 0):
        self._key = key
        self._saml_req = saml_req
        self._SAMLRequest = saml_req.request
        self._RelayState = relay_state
        self._FailCount = fail_count
        self._binding = saml_req.binding
        # dict to transfer data about credentials successfully used from the MFA plugin
        # to the IdP code, where it will be transferred to the SSO session
        self.mfa_action_creds: Dict[Credential, datetime] = {}
        self.mfa_action_external: Optional[ExternalMfaData] = None

    def __str__(self):
        data = self.to_dict()
        if 'SAMLRequest' in data:
            data['SAMLRequest length'] = len(data['SAMLRequest'])
            del data['SAMLRequest']
        return pprint.pformat(data)

    def to_dict(self):
        res = {'key': self._key,
               'req_info': self._saml_req,
               'SAMLRequest': self._saml_req.request,  # backwards compat
               'RelayState': self._RelayState,
               'binding': self._saml_req.binding,  # backwards compat
               'FailCount': self._FailCount,
               }
        return res

    @property
    def key(self):
        """
        Unique reference for this instance. Used for storing SSOLoginData instances
        in SSOLoginDataCache.
        :rtype: string
        """
        return escape(self._key, quote=True)

    @property
    def SAMLRequest(self):
        """
        The SAML request in transport encoding (base 64).

        :rtype : string
        """
        return escape(self._SAMLRequest, quote=True)

    @property
    def saml_req(self) -> IdP_SAMLRequest:
        """Parsed SAML request."""
        return self._saml_req

    @property
    def RelayState(self):
        """
        This is an opaque string generated by a SAML SP that must be sent to the
        SP when the authentication is finished and the user redirected to the SP.

        :rtype: string
        """
        return escape(self._RelayState, quote=True)

    @property
    def FailCount(self):
        """
        The number of failed login attempts. Used to show an alert message to the
        user to make them aware of the reason they got back to the IdP login page.

        :rtype: int
        """
        return self._FailCount

    @FailCount.setter
    def FailCount(self, value):
        """
        Set the FailCount.

        :param value: new value
        :type value: int
        """
        assert isinstance(value, int)
        self._FailCount = value

    @property
    def binding(self):
        """
        binding this request was received with

        :rtype: string
        """
        return escape(self._binding, quote=True)

    @property
    def query_string(self):
        qs = {
            'SAMLRequest': self._SAMLRequest,
            'RelayState': self._RelayState
        }
        return urlencode(qs)


class SSOLoginDataCache(object):
    """
    Login data is state kept between rendering the login screen, to when the user is
    completely logged in and redirected from the IdP to the original resource the
    user is accessing.

    :param name: string describing this cache
    :param logger: logging logger
    :param ttl: expire time of data in seconds
    :param config: IdP configuration data
    :param lock: threading.Lock() instance

    :type lock: threading.Lock
    """

    def __init__(self, name: str, logger: Logger, ttl: int, config: IdPConfig, lock = None):
        self.logger = logger
        self._cache: ExpiringCache
        if (config.get('REDIS_SENTINEL_HOSTS') or config.get('REDIS_HOST')) and config.get('SHARED_SESSION_SECRET_KEY'):
            self._cache = ExpiringCacheCommonSession(name, logger, ttl, config, secret=config['SHARED_SESSION_SECRET_KEY'])
        else:
            # This is used in tests
            self._cache = ExpiringCacheMem(name, logger, ttl, lock)
        logger.debug('Set up IDP ticket cache {!s}'.format(self._cache))

    def store_ticket(self, ticket):
        """
        Add an entry to the IDP.ticket cache.

        :param ticket: SSOLoginData instance
        :returns: True on success
        """
        _key = ticket.key
        self.logger.debug('Storing login state {!r} (IdP ticket) in {!r}:\n{!s}'.format(_key, self._cache, ticket))
        self._cache.add(_key, ticket)
        return True

    def get_ticket(self, key: str) -> Optional[Union[SSOLoginData, Mapping]]:
        """
        Lookup session from key.
        """
        self.logger.debug("Lookup SSOLoginData (ticket) using key {!r}".format(key))
        _ticket = self._cache.get(key)
        if not _ticket:
            self.logger.debug("Key {!r} not found in IDP.ticket ({!r})".format(key, self._cache))
            return None

        self.logger.debug("Retreived login state (IdP.ticket) :\n{!s}".format(_ticket))

        # TODO: is this code needed?
        #if isinstance(_ticket, dict):
        #    # Ticket was stored in a backend that could not natively store a SSOLoginData instance. Recreate.
        #    _ticket = self.create_ticket(_ticket, _ticket['binding'], key=_key)
        #    self.logger.debug('Re-created SSOLoginData from stored ticket state:\n{!s}'.format(_ticket))

        return _ticket
