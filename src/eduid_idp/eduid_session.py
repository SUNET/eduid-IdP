# -*- coding: utf-8 -*-
import cherrypy
from cherrypy.process import wspbus, plugins

from eduid_common.session.redis_session import SessionManager

        
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
        self.bus.log('Starting up session manager')
        self.session_manager = SessionManager(cfg=self.config,
                                              ttl=self.config.get('SHARED_SESSION_TTL'),
                                              secret=self.config.get('SHARED_SESSION_SECRET_KEY'))
        self.bus.subscribe("bind-session", self.bind)
        self.bus.subscribe("commit-session", self.commit)
 
    def stop(self):
        self.bus.log('Stopping down session manager')
        self.bus.unsubscribe("bind-session", self.bind)
        self.bus.unsubscribe("commit-session", self.commit)
        self.session_manager = None
 
    def bind(self):
        """
        Whenever this plugin receives the 'bind-session' command, it applies
        this method and to bind the current session to the engine.

        It then returns the session to the caller.
        """
        cookie_name = self.config.get('SHARED_SESSION_COOKIE_NAME')
        token = eduid_idp.mischttp.read_cookie(cookie_name, self.logger)
        self.session = self.session_manager.get_session(token=token)
        return self.session

    def commit(self):
        """
        Commits the current transaction or rollbacks if an error occurs.

        In all cases, the current session is unbound and therefore
        not usable any longer.
        """
        self.session.commit()


class EduIDSessionTool(cherrypy.Tool):
    def __init__(self):
        """
        This tool is responsible for keeping an eduID session manager
        and attaching sessions to the current request.
 
        This tools binds a session to the engine each time
        a request starts and commits/rollbacks whenever
        the request terminates.
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
        the SA plugin to bind a session to the SA engine.
        """
        session = cherrypy.engine.publish('bind-session').pop()
        cherrypy.request.db = session
 
    def commit_transaction(self):
        """
        Commits the current transaction or rolls back
        if an error occurs. Removes the session handle
        from the request's scope.
        """
        if not hasattr(cherrypy.request, 'db'):
            return
        cherrypy.request.db = None
        cherrypy.engine.publish('commit-session')
