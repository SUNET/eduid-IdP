from logging import Logger
from typing import Optional, Union

from copy import deepcopy
from dataclasses import dataclass, asdict

from eduid_idp.cache import ExpiringCache, ExpiringCacheCommonSession, ExpiringCacheMem
from eduid_idp.config import IdPConfig
from eduid_common.session.session import RedisEncryptedSession

from saml2.request import AuthnRequest


@dataclass()
class IdPSessionData(object):
    sso_db_key: Optional[str] = None
    SAMLRequest: Optional[str] = None
    req_info: Optional[AuthnRequest] = None
    RelayState: Optional[str] = None
    binding: Optional[str] = None
    FailCount: int = 0

    def to_dict(self):
        res = asdict(self)
        #if res.get('login_source') is not None:
        #    res['login_source'] = res['login_source'].value
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        #if _data.get('login_source') is not None:
        #    _data['login_source'] = LoginApplication(_data['login_source'])
        return cls(**_data)

@dataclass()
class IdPSession(object):
    idp: IdPSessionData
    common_session: Union[RedisEncryptedSession, dict]


class IdPSessionFactory(object):
    """
    Session backend abstraction layer to sessions either in memory or Redis.

    These sessions are shared with eduid actions and webapps.

    :param logger: logging logger
    :param ttl: expire time of data in seconds
    :param config: IdP configuration data
    :param lock: threading.Lock() instance

    :type lock: threading.Lock
    """

    def __init__(self, logger: Logger, ttl: int, config: IdPConfig, lock = None):
        self.logger = logger
        self._backend: ExpiringCache
        name = 'eduIDCommonSession'
        if (config.redis_sentinel_hosts or config.redis_host) and config.session_app_key:
            self._backend = ExpiringCacheCommonSession(name, logger, ttl, config)
        else:
            # This is used in tests
            self._backend = ExpiringCacheMem(name, logger, ttl, lock)
        logger.debug('Set up session backend {!s}'.format(self._backend))

    def store_session(self, key, session: IdPSession) -> None:
        """ Add an entry to the IDP.ticket cache. """
        self.logger.debug('Storing session in {}:\n{}'.format(self._backend, session))
        # Update the IdP application data on store
        self.logger.debug('Storing session IdP data: {}'.format(session.idp))
        session.common_session['idp'] = session.idp.to_dict()
        self._backend.add(key, session.common_session)

    def get_session(self, key: str) -> Optional[IdPSession]:
        """ Lookup session from key. """
        self.logger.debug('Lookup session using key {!r}'.format(key))
        _common_session = self._backend.get(key)
        if not _common_session:
            self.logger.debug('Key {!r} not found in session store {}'.format(key, self._backend))
            return None

        self.logger.debug('Retreived session :\n{}'.format(_common_session))
        _idp_session = IdPSessionData.from_dict(_common_session.get('idp', {}))
        self.logger.debug('Loaded session IdP data: {}'.format(_idp_session))
        return IdPSession(idp = _idp_session, common_session=_common_session)

        # TODO: is this code needed?
        #if isinstance(_common_session, dict):
        #    # Ticket was stored in a backend that could not natively store a SSOLoginData instance. Recreate.
        #    _common_session = self.create_ticket(_common_session, _common_session['binding'], key=_key)
        #    self.logger.debug('Re-created SSOLoginData from stored ticket state:\n{!s}'.format(_common_session))
