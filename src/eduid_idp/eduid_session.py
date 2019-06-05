# -*- coding: utf-8 -*-
from typing import Optional

import cherrypy
from cherrypy.process import wspbus, plugins

from eduid_common.session.redis_session import SessionManager
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_common.session.namespaces import Common, Actions


class EduIDSession:

    def __init__(self, base_session: RedisEncryptedSession):
        self._session = base_session
        self._common: Optional[Common] = None

    def __getitem__(self, key, default=None):
        return self._session.__getitem__(key, default=None)

    def __setitem__(self, key, value):
        return self._session.__setitem__(key, value)

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


class SessionManagerPlugin(plugins.SimplePlugin):

    def __init__(self, bus, config, logger):
        """
        The plugin is registered to the CherryPy engine and therefore
        is part of the bus (the engine *is* a bus) registery.

        We use this plugin to create the eduID session manager.
        """
        plugins.SimplePlugin.__init__(self, bus)
        self.session_manager = None
        self.config = config
        self.logger = logger

    def start(self):
        self.logger.info('Starting up session manager')
        self.session_manager = SessionManager(cfg=self.config,
                                              ttl=self.config.get('SHARED_SESSION_TTL'),
                                              secret=self.config.get('SHARED_SESSION_SECRET_KEY'))
        self.bus.subscribe("bind-session", self.bind)

    def stop(self):
        self.logger.info('Stopping down session manager')
        self.bus.unsubscribe("bind-session", self.bind)
        self.session_manager = None

    def bind(self) -> EduIDSession:
        """
        Whenever this plugin receives the 'bind-session' command, it applies
        this method to retrieve session data from redis.

        It then returns the session to the caller.
        """
        cookie_name = self.config.get('SHARED_SESSION_COOKIE_NAME')
        token = eduid_idp.mischttp.read_cookie(cookie_name, self.logger)
        base_session = self.session_manager.get_session(token=token)
        return EduIDSession(base_session)


class EduIDSessionTool(cherrypy.Tool):

    def __init__(self):
        """
        This tool is responsible for keeping an eduID session manager
        and attaching sessions to the current request.

        This tools binds an eduid redis session to the request each time
        a request starts and commits whenever the request terminates.
        """
        cherrypy.Tool.__init__(self, 'on_start_resource',
                               self.bind_session,
                               priority=20)

    def _setup(self):
        cherrypy.Tool._setup(self)
        cherrypy.request.hooks.attach('on_end_resource',
                                      self.commit_transaction,
                                      priority=80)

    def bind_session(self):
        """
        Attaches a session to the request's scope by requesting
        the Session to bind a session to the SA engine.
        """
        session = cherrypy.engine.publish('bind-session').pop()
        cherrypy.request.eduid_session = session

    def commit_transaction(self):
        """
        Commits to redis the current changes to the session.
        """
        if not hasattr(cherrypy.request, 'eduid_session'):
            return
        cherrypy.request.eduid_session.commit()
