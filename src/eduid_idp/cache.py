#
# Copyright (c) 2013 NORDUnet A/S
# Copyright 2012 Roland Hedberg. All rights reserved.
# All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

import time
from collections import deque
from hashlib import sha1
import datetime

import pymongo


class NoOpLock():
    """
    A No-op lock class, to avoid a lot of "if self.lock:" in code using locks.
    """

    def __init__(self):
        pass

    # noinspection PyUnusedLocal
    def acquire(self, _block = True):
        return True

    def release(self):
        pass


class ExpiringCache():
    """
    Simplistic implementation of a cache that removes entrys as they become too old.

    This implementation invokes garbage collecting on every addition of data. This
    is believed to be a pragmatic approach for small to medium sites. For a large
    site with e.g. load balancers causing uneven traffic patterns, this might not
    work that well and the use of an external cache such as memcache is recommended.
    """

    def __init__(self, name, logger, ttl, lock = None):
        self.logger = logger
        self._data = {}
        self._ages = deque()
        self._ttl = ttl
        self._name = name
        self.lock = lock
        if self.lock is None:
            self.lock = NoOpLock()

    def key(self, something):
        return sha1(something).hexdigest()

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
        self.purge_expired(_now - self._ttl)

    def purge_expired(self, timestamp):
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
                self.logger.debug("Purged {!s} cache entry {!s} seconds over limit : {!s}".format(
                    self._name, timestamp - _exp_ts, _exp_key))
                self.delete(_exp_key)
        finally:
            self.lock.release()

    def get(self, key):
        return self._data.get(key)

    def items(self):
        return self._data

    def delete(self, key):
        try:
            del self._data[key]
            return True
        except KeyError:
            self.logger.debug("Failed deleting key {!r} from {!s} cache (entry did not exist)".format(
                key, self._name))


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
        self.user2uid = ExpiringCache('SSOSession.user2uid', self.logger, self._ttl, lock = self._lock)
        self.uid2user = ExpiringCache('SSOSession.uid2user', self.logger, self._ttl, lock = self._lock)

    def remove_using_local_id(self, _lid):
        """
        Remove entrys when SLO is executed.

        :param _lid: Local identifier as string (username?)
        :return: True on success
        """
        _uid = self.user2uid.get(_lid)
        self.logger.debug("Purging SSO session, uid : {!s}".format(self.uid2user.get(_uid)))
        self.logger.debug("Purging SSO session, lid : {!s}".format(self.user2uid.get(_lid)))
        if self.uid2user.delete(_uid) and self.user2uid.delete(_lid):
            return True

    def add_session(self, lid, username, data):
        """
        Add a new SSO session to the cache.

        The mapping of uid -> user (and data) is used when a user visits another SP before
        the SSO session expires, and the mapping of user -> uid is used if the user requests
        logout (SLO).

        :param lid: local unique id as string (uniqueness and unability to guess is security critical!)
        :param username: Username as string
        :param data: opaque, should be dict
        :return:
        """
        self.uid2user.add(lid, data)
        self.user2uid.add(username, lid)

    def get_using_local_id(self, lid):
        """
        Lookup an SSO session using the local id (same lid previously used with add_session).

        :param lid: Unique id as string
        :return: opaque, should be dict
        """
        try:
            return self.uid2user.get(lid)
        except KeyError:
            self.logger.debug('Failed looking up SSO session with local_id={!r}'.format(lid))
            raise


class SSOSessionCacheMDB(object):
    """
    This is a MongoDB version of SSOSessionCache().

    Expiration is done using simple non-blocking delete-querys on an indexed date-field.
    A simple timestamp is used to not invoke expiration more often than once every
    `expiration_freq' seconds.
    """

    def __init__(self, uri, logger, ttl, lock = None, expiration_freq = 60, conn = None, db_name = "eduid_idp",
                 **kwargs):
        self.logger = logger
        self._ttl = ttl
        self._lock = lock
        if self._lock is None:
            self._lock = NoOpLock()
        self._expiration_freq = expiration_freq
        self._last_expire_at = None

        if conn is not None:
            self.connection = conn
        else:
            if "replicaSet=" in uri:
                self.connection = pymongo.mongo_replica_set_client.MongoReplicaSetClient(uri, **kwargs)
            else:
                self.connection = pymongo.MongoClient(uri, **kwargs)
        self.db = self.connection[db_name]
        self.sso_sessions = self.db.sso_sessions
        for this in xrange(2):
            try:
                self.sso_sessions.ensure_index('expire_at', name = 'expire_at_idx', unique = False)
                self.sso_sessions.ensure_index('local_id', name = 'local_id_idx', unique = True)
                break
            except pymongo.errors.AutoReconnect, e:
                if this == 1:
                    raise
                self.logger.error("Failed ensuring mongodb index, retrying ({!r})".format(e))

    def remove_using_local_id(self, _lid):
        """
        Remove entrys when SLO is executed.

        :param _lid: Local identifier as string (username?)
        :return: True on success
        """
        return self.sso_sessions.remove({'local_id': _lid}, w = 1, getLastError = True)

    def add_session(self, lid, username, data):
        """
        Add a new SSO session to the cache.

        The mapping of uid -> user (and data) is used when a user visits another SP before
        the SSO session expires, and the mapping of user -> uid is used if the user requests
        logout (SLO).

        :param lid: Unique local id as string (uniqueness and unability to guess is security critical!)
        :param username: Username as string
        :param data: opaque, should be dict
        :return: True on success
        """
        _ts = time.time()
        isodate = datetime.datetime.fromtimestamp(_ts, None)
        _doc = {'local_id': lid,
                'username': username,
                'data': data,
                'created_ts': isodate,
                }
        self.sso_sessions.insert(_doc)
        self.expire_old_sessions()
        return True

    def get_using_local_id(self, lid):
        """
            Lookup an SSO session using the local id (same lid previously used with add_session).

            :param lid: Unique id as string
            :return: opaque, should be dict
            """
        try:
            res = self.sso_sessions.find_one({'local_id': lid})
            if res:
                return res['data']
        except KeyError:
            self.logger.debug('Failed looking up SSO session with local id={!r}'.format(lid))
            raise

    def expire_old_sessions(self, force=False):
        """
        Remove expired sessions from the MongoDB database.

        Unless force=True, this will be a no-op if less than `expiration_freq' seconds
        has passed since the last time this operation was invoked.

        :param force: Boolean, force run even if not enough time has passed
        :return: True if expiration was performed, False otherwise
        """
        _ts = time.time() - self._ttl
        if not force:
            if self._last_expire_at > _ts - self._expiration_freq:
                return False
        self._last_expire_at = _ts
        isodate = datetime.datetime.fromtimestamp(_ts, None)
        self.sso_sessions.remove({'created_ts': {'$lt': isodate}})
        return True
