# -*- coding: utf-8 -*-
import datetime
from typing import Optional, Tuple

import cherrypy
from cherrypy.lib.sessions import Session

from eduid_common.api.exceptions import BadConfiguration
from eduid_common.session.redis_session import SessionManager
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.namespaces import Common, Actions
import eduid_idp.mischttp


class EduidSession(Session):
    '''
    Cherrypy session that keeps data encrypted in Redis,
    shared with the rest of the eduid apps by way of a
    shared encryption key.
    '''

    @classmethod
    def setup(cls, **config):
        '''
        Initialize Redis connection pool. Only called once per process.
        See cherrypy.lib.sessions.init
        '''
        for k, v in config.items():
            setattr(cls, k, v)

        cls.session_factory = SessionFactory(cherrypy.config)

    def __init__(self, id: str, token: str = None, **kwargs):
        self._session = self.session_factory.get_base_session(token=token)
        token = self._session.token
        if isinstance(token, bytes):
            token = token.decode('ascii')
        super(EduidSession, self).__init__(id=token, **kwargs)

        # namespaces
        self._common: Optional[Common] = None
        self._actions: Optional[Actions] = None

    def _exists(self) -> bool:
        return bool(self._session.conn.get(self._session.session_id))

    def _load(self) -> Tuple[dict, datetime.datetime]:
        ttl = cherrypy.config.get('SHARED_SESSION_TTL')
        expires = self.now() + datetime.timedelta(seconds=ttl)
        return (self._session._data, expires)

    def _save(self, expiration_time: datetime.datetime):
        if isinstance(self.common, Common):
            self._data['_common'] = self.common.to_dict()
        if isinstance(self.actions, Actions):
            self._data['_actions'] = self.actions.to_dict()
        self._session._data = self._data
        self._session.commit()
        self._session.conn.expire(self.id, int(expiration_time.timestamp()))

    def _delete(self):
        self._data = None
        self._common = None
        self._actions = None
        self._session.clear()

    def acquire_lock(self, path=None):
        pass

    def release_lock(self, path=None):
        pass

    # Namespaces
    @property
    def common(self) -> Optional[Common]:
        if not self._common:
            self._common = Common.from_dict(self._session.get('_common', {}))
        return self._common

    @common.setter
    def common(self, value: Optional[Common]):
        if not self._common:
            self._common = value

    @property
    def actions(self) -> Optional[Actions]:
        if not self._actions:
            self._actions = Actions.from_dict(self._session.get('_actions', {}))
        return self._actions

    @actions.setter
    def actions(self, value: Optional[Actions]):
        if not self._actions:
            self._actions = value


class SessionFactory:
    """
    Session factory, to provide eduID's IdP
    encrypted redis-based sessions shared with the APIs.
    """

    def __init__(self, config: dict):
        self.config = config
        ttl = config['SHARED_SESSION_TTL']
        secret = config['SHARED_SESSION_SECRET_KEY']
        if secret is None:
            cherrypy.config.logger.error('SHARED_SESSION_SECRET_KEY not set in config')
            raise BadConfiguration('SHARED_SESSION_SECRET_KEY not set in config')
        self.manager = SessionManager(config, ttl=ttl, secret=secret)

    def get_base_session(self, token: str = None) -> RedisEncryptedSession:
        logger = cherrypy.config.logger
        debug = self.config['DEBUG']
        if token is None:
            cookie_name = self.config['SHARED_SESSION_COOKIE_NAME']
            # Load token from cookie
            token = eduid_idp.mischttp.read_cookie(cookie_name, logger)
        if token:
            try:
                return self.manager.get_session(token=token, debug=debug)
            except (KeyError, ValueError) as exc:
                logger.warning(f'Failed to load session from token {token}: {exc}')

        return self.manager.get_session(data={}, debug=debug)
