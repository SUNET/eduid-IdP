#!/usr/bin/python
#
# Copyright (c) 2013 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import time
import logging
from unittest import TestCase

import eduid_idp

logger = logging.getLogger()


class BusyLock(object):
    """
    Locking class that never succeeds acquire()
    """

    def acquire(self, _block = True):
        return False

    def release(self):
        pass


class TestExpiringCache(TestCase):
    def test_add(self):
        ttl = 30
        c = eduid_idp.cache.ExpiringCache('TestCache', logger, ttl)
        now = int(time.time())
        c.add('one', 'ett', now = now - 60)
        self.assertEqual('ett', c.get('one'))
        c.add('two', 'tvaa', now = now)
        # first entry should be purged now
        self.assertEqual(None, c.get('one'))

    def test_add_locked(self):
        ttl = 30
        c = eduid_idp.cache.ExpiringCache('TestCache', logger, ttl, lock = BusyLock())
        now = int(time.time())
        c.add('one', 'ett', now = now - 60)
        self.assertEqual('ett', c.get('one'))
        c.add('two', 'tvaa', now = now)
        # since BusyLock did not give a lock to the purging code, the first entry
        # should still be available
        self.assertEqual('ett', c.get('one'))

    def test_items(self):
        ttl = 30
        c = eduid_idp.cache.ExpiringCache('TestCache', logger, ttl)
        c.add(1, 'one')
        c.add(2, 'two')
        self.assertEqual({1: 'one', 2: 'two'}, c.items())

    def test_key(self):
        ttl = 30
        c = eduid_idp.cache.ExpiringCache('TestCache', logger, ttl)
        self.assertNotEqual(c.key('1'), c.key('2'))

    def test_delete(self):
        ttl = 30
        c = eduid_idp.cache.ExpiringCache('TestCache', logger, ttl)
        c.add(1, 'one')
        c.add(2, 'two')
        c.delete(3)
        self.assertEqual({1: 'one', 2: 'two'}, c.items())
        c.delete(1)
        self.assertEqual({2: 'two'}, c.items())
        c.delete(2)
        self.assertEqual({}, c.items())
