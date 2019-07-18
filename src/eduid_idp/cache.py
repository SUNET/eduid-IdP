#
# Copyright (c) 2018 SUNET
# Copyright (c) 2013, 2014, 2016, 2017 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#
import logging
import time
import uuid
import datetime
from hashlib import sha1
from collections import deque
from binascii import unhexlify

from typing import NewType, List, Deque, AnyStr

import six

from eduid_common.session.redis_session import SessionManager, RedisEncryptedSession
from eduid_common.config.idp import IdPConfig
from eduid_userdb import MongoDB

_SHA1_HEXENCODED_SIZE = 160 // 8 * 2


class NoOpLock(object):
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """

    def __init__(self):
        pass

    # noinspection PyUnusedLocal
    def acquire(self, _block = True):
        """
        Fake acquiring a lock.

        :param _block: boolean, whether to block or not (NO-OP in this implementation)
        """
        return True

    def release(self):
        """
        Fake releasing a lock.
        """
        pass


class ExpiringCacheMem:
    """
    Simplistic implementation of a cache that removes entrys as they become too old.

    This implementation invokes garbage collecting on every addition of data. This
    is believed to be a pragmatic approach for small to medium sites. For a large
    site with e.g. load balancers causing uneven traffic patterns, this might not
    work that well and the use of an external cache such as memcache is recommended.

    :param name: name of cache as string, only used for debugging
    :param logger: logging logger instance
    :param ttl: data time to live in this cache, as seconds (integer)
    :param lock: threading.Lock compatible locking instance
    """

    def __init__(self, name, logger, ttl, lock = None):
        self.logger = logger
        self.ttl = ttl
        self.name = name
        self._data: dict = {}
        self._ages: Deque = deque()
        self.lock = lock
        if self.lock is None:
            self.lock = NoOpLock()

    def add(self, key, info, now = None):
        """
        Add entry to the cache.

        Ability to supply current time is only meant for test cases!

        :param key: Lookup key for entry
        :param info: Value to be stored for 'key'
        :param now: Current time - do not use unless testing!
        :return: None
        """
        self._data[key] = info
        # record when this entry shall be purged
        _now = now
        if _now is None:
            _now = int(time.time())
        self._ages.append((_now, key))
        self._purge_expired(_now - self.ttl)

    def _purge_expired(self, timestamp):
        """
        Purge expired records.

        :param timestamp: Purge any entrys older than this (integer)
        :return: None
        """
        if not self.lock.acquire(False):
            # if we don't get the lock, don't worry about it and just skip purging
            return None
        try:
            # purge any expired records. self._ages have the _data entries listed with oldest first.
            while True:
                try:
                    (_exp_ts, _exp_key) = self._ages.popleft()
                except IndexError:
                    break
                if _exp_ts > timestamp:
                    # entry not expired - reinsert in queue and end purging
                    self._ages.appendleft((_exp_ts, _exp_key))
                    break
                self.logger.debug('Purged {!s} cache entry {!s} seconds over limit : {!s}'.format(
                    self.name, timestamp - _exp_ts, _exp_key))
                self.delete(_exp_key)
        finally:
            self.lock.release()

    def get(self, key):
        """
        Fetch data from cache based on `key'.

        :param key: hash key to use for lookup
        :returns: Any data found matching `key', or None.
        """
        return self._data.get(key)

    def update(self, key, info):
        """
        Update an entry in the cache.

        :param key: Lookup key for entry
        :param info: Value to be stored for 'key'
        :return: None
        """
        self._data[key] = info

    def delete(self, key):
        """
        Delete an item from the cache.

        :param key: hash key to delete
        :return: True on success
        """
        try:
            del self._data[key]
            return True
        except KeyError:
            self.logger.debug('Failed deleting key {!r} from {!s} cache (entry did not exist)'.format(
                key, self.name))

    def items(self):
        """
        Return all items from cache.
        """
        return self._data


# A distinct type for session ids
SSOSessionId = NewType('SSOSessionId', bytes)


class SSOSessionCache(object):
    """
    This cache holds all SSO sessions, meaning information about what users
    have a valid session with the IdP in order to not be authenticated again
    (until the SSO session expires).
    """

    def __init__(self, logger, ttl, lock = None):
        self.logger = logger
        self._ttl = ttl
        self._lock = lock
        if self._lock is None:
            self._lock = NoOpLock()

    def remove_session(self, sid: SSOSessionId):
        """
        Remove entrys when SLO is executed.

        :param sid: Session identifier as string
        :return: True on success
        """
        raise NotImplementedError()

    def add_session(self, username, data) -> SSOSessionId:
        """
        Add a new SSO session to the cache.

        The mapping of uid -> user (and data) is used when a user visits another SP before
        the SSO session expires, and the mapping of user -> uid is used if the user requests
        logout (SLO).

        :param username: Username as string
        :param data: opaque, should be SSOSession converted to dict()
        :return: Unique session identifier
        """
        raise NotImplementedError()

    def update_session(self, username, data):
        """
        Update a SSO session in the cache.

        :param username: Username as string
        :param data: opaque, should be SSOSession converted to dict()
        :return: Unique session identifier
        """
        raise NotImplementedError()

    def get_session(self, sid: SSOSessionId):
        """
        Lookup an SSO session using the session id (same `sid' previously used with add_session).

        :param sid: Unique session identifier as string
        :return: opaque
        """
        raise NotImplementedError()

    def get_sessions_for_user(self, username) -> List[SSOSessionId]:
        """
        Lookup all SSO sessions for a given username. Used in SLO with SOAP binding.

        :param username: The username to look for

        :return: Zero or more SSO session_id's
        """

    def _create_session_id(self) -> SSOSessionId:
        """
        Create a unique value suitable for use as session identifier.

        The uniqueness and unability to guess is security critical!
        :return: session_id as bytes (to match what cookie decoding yields)
        """
        return SSOSessionId(str(uuid.uuid4()).encode('utf-8'))


class SSOSessionCacheMem(SSOSessionCache):
    """
    This cache holds all SSO sessions, meaning information about what users
    have a valid session with the IdP in order to not be authenticated again
    (until the SSO session expires).

    Do NOT use this in-memory SSO session cache in a clustered setup -
    only for a (small) single IdP.
    """

    def __init__(self, logger, ttl, lock = None):
        SSOSessionCache.__init__(self, logger, ttl, lock)
        self.lid2data = ExpiringCacheMem('SSOSession.uid2user', self.logger, self._ttl, lock = self._lock)

    def remove_session(self, sid: SSOSessionId):
        self.logger.debug('Purging SSO session {!r}, data : {!s}'.format(sid, self.lid2data.get(sid)))
        return self.lid2data.delete(sid)

    def add_session(self, username, data) -> SSOSessionId:
        _sid = self._create_session_id()
        self.lid2data.add(_sid, {'username': username,
                                 'data': data,
                                 })
        self.logger.debug('Added SSO session {!r}, data : {!s}'.format(_sid, self.lid2data.get(_sid)))
        return _sid

    def update_session(self, username, data):
        # TODO: This is completely broken - we add a new state rather than updating the old one
        _sid = self._create_session_id()
        self.logger.debug('Updating data by adding it using new session id {}. FIXME.'.format(_sid))
        self.lid2data.update(_sid, {'username': username,
                                    'data': data,
                                    })

    def get_session(self, sid: SSOSessionId):
        try:
            this = self.lid2data.get(sid)
            if this:
                return this['data']
        except KeyError:
            self.logger.debug('Failed looking up SSO session with session id={!r}'.format(sid))
            raise

    def get_sessions_for_user(self, username) -> List[SSOSessionId]:
        res = []
        for _key, _val in self.lid2data.items():
            # Traversing all of lid2data could be a bit slow, but any non-trivial
            # setup of eduid-IdP is expected to use another backend anyways. In-memory
            # backend won't work well with multiple IdP:s anyway (think log in to one IdP,
            # log out to another).
            if _val.get('username') == username:
                res.append(_key)
        self.logger.debug('Found SSO sessions for user {!r}: {!r}'.format(username, res))
        return res


class SSOSessionDB(MongoDB):
    """
    MongoDB interface using eduid_userdb
    """
    pass


class SSOSessionCacheMDB(SSOSessionCache):
    """
    This is a MongoDB version of SSOSessionCache().

    Expiration is done using simple non-blocking delete-querys on an indexed date-field.
    A simple timestamp is used to not invoke expiration more often than once every
    `expiration_freq' seconds.
    """

    def __init__(self, uri, logger, ttl, lock = None, expiration_freq = 60, conn = None, db_name = 'eduid_idp',
                 **kwargs):
        SSOSessionCache.__init__(self, logger, ttl, lock)
        self._expiration_freq = expiration_freq
        self._last_expire_at = None

        self._db = SSOSessionDB(db_uri = uri, db_name = db_name)
        self.sso_sessions = self._db.get_collection('sso_sessions')
        for retry in range(2, -1, -1):
            try:
                self.sso_sessions.ensure_index('created_ts', name = 'created_ts_idx', unique = False)
                self.sso_sessions.ensure_index('session_id', name = 'session_id_idx', unique = True)
                self.sso_sessions.ensure_index('username', name = 'username_idx', unique = False)
                break
            except Exception:
                if not retry:
                    raise
                self.logger.error('Failed ensuring mongodb index, retrying ({})'.format(retry))

    def remove_session(self, sid: SSOSessionId):
        res = self.sso_sessions.remove({'session_id': sid}, w = 'majority')
        try:
            return res['n']  # number of deleted records
        except (KeyError, TypeError):
            self.logger.warning('Remove session {!r} failed, result: {!r}'.format(sid, res))
            return False

    def add_session(self, username, data) -> SSOSessionId:
        _ts = time.time()
        isodate = datetime.datetime.fromtimestamp(_ts, None)
        _sid = self._create_session_id()
        _doc = {'session_id': _sid,
                'username': username,
                'data': data,
                'created_ts': isodate,
                }
        self.sso_sessions.insert(_doc)
        self.expire_old_sessions()
        return _sid

    def update_session(self, username, data):
        # TODO: This is completely broken - we add a new state rather than updating the old one
        _sid = self._create_session_id()
        self.logger.debug('Updating data by adding it using new session id {}. FIXME.'.format(_sid))
        _test_doc = {'session_id': _sid,
                     'username': username,
                     }
        self.sso_sessions.update(_test_doc, {'$set': {'data': data}})

    def get_session(self, sid: SSOSessionId):
        try:
            res = self.sso_sessions.find_one({'session_id': sid})
            if res:
                return res['data']
        except KeyError:
            self.logger.debug('Failed looking up SSO session with id={!r}'.format(sid))
            raise

    def get_sessions_for_user(self, username) -> List[SSOSessionId]:
        res = []
        entrys = self.sso_sessions.find({'username': username})
        for this in entrys:
            res.append(this['session_id'])
        return res

    def expire_old_sessions(self, force=False):
        """
        Remove expired sessions from the MongoDB database.

        Unless force=True, this will be a no-op if less than `expiration_freq' seconds
        has passed since the last time this operation was invoked.

        :param force: Boolean, force run even if not enough time has passed
        :return: True if expiration was performed, False otherwise
        """
        _ts = time.time() - self._ttl
        if not force and self._last_expire_at is not None:
            if self._last_expire_at > _ts - self._expiration_freq:
                return False
        self._last_expire_at = _ts
        isodate = datetime.datetime.fromtimestamp(_ts, None)
        self.sso_sessions.remove({'created_ts': {'$lt': isodate}})
        return True
