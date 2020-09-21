# -*- coding: utf-8 -*-
#!/usr/bin/env python
#
# Copyright (c)             2019 SUNET. All rights reserved.
# Copyright (c) 2013, 2014, 2017 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.

import datetime
from random import random
from typing import Optional, Tuple

import cherrypy
from cherrypy.lib.sessions import Session
from eduid_common.config.exceptions import BadConfiguration
from eduid_common.session.logindata import SSOLoginData
from eduid_common.session.namespaces import Actions, Common
from eduid_common.session.redis_session import RedisEncryptedSession, SessionManager

import eduid_idp.mischttp


class EduidSession(Session):
    """
    Cherrypy session that keeps data encrypted in Redis,
    shared with the rest of the eduid apps by way of a
    shared encryption key.
    """

    @classmethod
    def setup(cls, **config):
        """
        Initialize Redis connection pool. Only called once per process.
        See cherrypy.lib.sessions.init
        """
        for k, v in config.items():
            setattr(cls, k, v)

        cls.session_factory = SessionFactory()

    def __init__(self, id: str = None, **kwargs):
        self._session = self.session_factory.get_base_session(cookie_val=id)
        # In case no session was found, a new ID will have been generated and we need to tell it to CherryPy
        id = self._session.token.cookie_val
        super(EduidSession, self).__init__(id=id, **kwargs)

        # namespaces
        self._common: Optional[Common] = None
        self._actions: Optional[Actions] = None
        self._sso_ticket: Optional[SSOLoginData] = None

    def _exists(self) -> bool:
        return bool(self._session.token.cookie_val)

    def _load(self) -> Tuple[dict, datetime.datetime]:
        ttl = cherrypy.config['shared_session_ttl']
        expires = self.now() + datetime.timedelta(seconds=ttl)
        return (self._session._data, expires)

    def _save(self, expiration_time: datetime.datetime):
        if isinstance(self._common, Common):
            self._data['_common'] = self.common.to_dict()  # type: ignore
        if isinstance(self._actions, Actions):
            self._data['_actions'] = self.actions.to_dict()  # type: ignore
        if isinstance(self._sso_ticket, SSOLoginData):
            self._data['_sso_ticket'] = self.sso_ticket.to_dict()  # type: ignore
        self._session._data.update(self._data)
        self._session.commit()
        self._session.conn.expire(self._session.token.session_id, int(expiration_time.timestamp()))

    def _delete(self):
        self._data = {}
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
        self['flag'] = f'dirty session to force saving to redis {random()}'

    @property
    def actions(self) -> Optional[Actions]:
        if not self._actions:
            self._actions = Actions.from_dict(self._session.get('_actions', {}))
        return self._actions

    @actions.setter
    def actions(self, value: Optional[Actions]):
        if not self._actions:
            self._actions = value
        self['flag'] = f'dirty session to force saving to redis {random()}'

    @property
    def sso_ticket(self) -> Optional[SSOLoginData]:
        if not self._sso_ticket and '_sso_ticket' in self._session:
            try:
                self._sso_ticket = SSOLoginData.from_dict(self._session['_sso_ticket'])
            except Exception:
                cherrypy.config['logger'].exception('Failed loading SSOLoginData')
                self._sso_ticket = None
        return self._sso_ticket

    @sso_ticket.setter
    def sso_ticket(self, value: Optional[SSOLoginData]):
        self._sso_ticket = value
        if value is None:
            del self._session._data['_sso_ticket']
        else:
            self._session._data['_sso_ticket'] = value.to_dict()
        self['flag'] = f'dirty session to force saving to redis {random()}'


class SessionFactory:
    """
    Session factory, to provide eduID's IdP
    encrypted redis-based sessions shared with the APIs.
    """

    def __init__(self):
        ttl = cherrypy.config['shared_session_ttl']
        secret = cherrypy.config['shared_session_secret_key']
        if secret is None:
            cherrypy.config['logger'].error('shared_session_secret_key not set in config')
            raise BadConfiguration('shared_session_secret_key not set in config')
        self.manager = SessionManager(cherrypy.config, ttl=ttl, app_secret=secret)

    def get_base_session(self, cookie_val: str = None) -> RedisEncryptedSession:
        logger = cherrypy.config.logger
        debug = cherrypy.config['debug']
        if cookie_val is None:
            cookie_name = cherrypy.config['shared_session_cookie_name']
            # Load token from cookie
            cookie_val = eduid_idp.mischttp.read_cookie(cookie_name, logger)
        if cookie_val:
            try:
                return self.manager.get_session(cookie_val=cookie_val)
            except (KeyError, ValueError) as exc:
                logger.warning(f'Failed to load session from token {cookie_val}: {exc}')

        return self.manager.get_session()
