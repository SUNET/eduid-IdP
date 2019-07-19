"""
A context for the IdP.
"""

from dataclasses import dataclass
from typing import Optional
from logging import Logger

from eduid_common.config.idp import IdPConfig
from eduid_common.session.redis_session import RedisEncryptedSession
from eduid_idp.authn import IdPAuthn
from eduid_common.session.sso_cache import SSOSessionCache

from eduid_userdb.actions import ActionDB

from saml2.server import Server as Saml2Server


@dataclass(frozen=True)
class IdPContext(object):
    config: IdPConfig
    sso_sessions: SSOSessionCache
    idp: Saml2Server
    logger: Logger
    authn: IdPAuthn
    actions_db: Optional[ActionDB] = None
    session: Optional[RedisEncryptedSession] = None
