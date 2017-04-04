# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from .. import unittest

from synapse.util.caches.snapshot_cache import SnapshotCache
from twisted.internet.defer import Deferred


class SnapshotCacheTestCase(unittest.TestCase):

    def setUp(self):
        self.cache = SnapshotCache()
        self.cache.DURATION_MS = 1

    def test_get_set(self):
        # Check that getting a missing key returns None
        self.assertEquals(self.cache.get(0, "key"), None)

        # Check that setting a key with a deferred returns
        # a deferred that resolves when the initial deferred does
        d = Deferred()
        set_result = self.cache.set(0, "key", d)
        self.assertIsNotNone(set_result)
        self.assertFalse(set_result.called)

        # Check that getting the key before the deferred has resolved
        # returns a deferred that resolves when the initial deferred does.
        get_result_at_10 = self.cache.get(10, "key")
        self.assertIsNotNone(get_result_at_10)
        self.assertFalse(get_result_at_10.called)

        # Check that the returned deferreds resolve when the initial deferred
        # does.
        d.callback("v")
        self.assertTrue(set_result.called)
        self.assertTrue(get_result_at_10.called)

        # Check that getting the key after the deferred has resolved
        # before the cache expires returns a resolved deferred.
        get_result_at_11 = self.cache.get(11, "key")
        self.assertIsNotNone(get_result_at_11)
        if isinstance(get_result_at_11, Deferred):
            # The cache may return the actual result rather than a deferred
            self.assertTrue(get_result_at_11.called)

        # Check that getting the key after the deferred has resolved
        # after the cache expires returns None
        get_result_at_12 = self.cache.get(12, "key")
        self.assertIsNone(get_result_at_12)
