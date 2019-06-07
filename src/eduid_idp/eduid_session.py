# -*- coding: utf-8 -*-
import datetime
from typing import Optional

import cherrypy
from cherrypy.lib.sessions import Session

from eduid_common.session.redis_session import SessionManager
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.namespaces import Common, Actions
import eduid_idp.mischttp


class EduidSession(Session):

    @classmethod
    def setup(cls, **config):
        '''
        Initialize Redis connection pool. Only called once per process.
        '''
        for k, v in config.items():
            setattr(cls, k, v)

        cls.session_factory = SessionFactory(cherrypy.config)

    def __init__(self, id, **kwargs):
        self.id_observers = []
        if 'base_session' in kwargs:
            self._session = kwargs["base_session"]
        else:
            other = self.session_factory.open_session()
            self._session = other._session
        self._id = self._session.session_id
        self._common: Optional[Common] = None
        self._actions: Optional[Actions] = None

    def _exists(self):
        return bool(self._session.conn.get(self.id))

    def _load(self):
        ttl = cherrypy.config.get('SHARED_SESSION_TTL')
        expires = self.now() + datetime.timedelta(seconds=ttl)
        return (self._session._data, expires)

    def _save(self, expiration_time):
        if self._common is not None:
            self._data['_common'] = self._common.to_dict()
        if self._actions is not None:
            self._data['_actions'] = self._actions.to_dict()
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
    Session factory,
    to provide eduID redis-based sessions to the APIs.
    """

    def __init__(self, config: dict):
        self.config = config
        ttl = config.get('SHARED_SESSION_TTL')
        secret = config.get('SHARED_SESSION_SECRET_KEY')
        self.manager = SessionManager(config, ttl=ttl, secret=secret)

    def open_session(self) -> EduidSession:
        """
        """
        logger = cherrypy.config.logger
        debug = self.config.get('DEBUG')
        try:
            cookie_name = self.config.get('SHARED_SESSION_COOKIE_NAME')
        except KeyError:
            logger.error('SHARED_SESSION_COOKIE_NAME not set in config')
            raise BadConfiguration('SHARED_SESSION_COOKIE_NAME not set in config')

        # Load token from cookie
        token = eduid_idp.mischttp.read_cookie(cookie_name, logger)
        if debug:
            logger.debug('Session cookie {} == {}'.format(cookie_name, token))

        if token:
            # Existing session
            try:
                base_session = self.manager.get_session(token=token, debug=debug)
                sess = EduidSession(base_session.session_id, base_session=base_session)
                if debug:
                    logger.debug('Loaded existing session {}'.format(sess))
                return sess
            except (KeyError, ValueError) as exc:
                logger.warning(f'Failed to load session from token {token}: {exc}')

        # New session
        base_session = self.manager.get_session(data={}, debug=debug)
        sess = EduidSession(base_session.session_id, base_session=base_session)
        if debug:
            logger.debug('Created new session {}'.format(sess))
        return sess
