"""
A context for the IdP.
"""

from dataclasses import dataclass
from typing import Optional
from logging import Logger

from eduid_idp.authn import IdPAuthn
from eduid_idp.config import IdPConfig
from eduid_idp.loginstate import SSOLoginDataCache
from eduid_idp.cache import ExpiringCacheCommonSession, SSOSessionCache, RedisEncryptedSession

from eduid_userdb.actions import ActionDB

from saml2.server import Server as Saml2Server


@dataclass(frozen=True)
class IdPContext(object):
    config: IdPConfig
    sso_sessions: SSOSessionCache
    ticket_sessions: SSOLoginDataCache
    common_sessions: Optional[ExpiringCacheCommonSession]
    idp: Saml2Server
    logger: Logger
    authn: IdPAuthn
    actions_db: Optional[ActionDB] = None
    session: Optional[RedisEncryptedSession] = None
