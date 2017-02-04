# -*- coding: utf-8 -*-
# Copyright 2017 OpenMarket Ltd
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

from synapse.util.caches.expiringcache import ExpiringCache

from tests.utils import MockClock


class ExpiringCacheTestCase(unittest.TestCase):

    def test_get_set(self):
        clock = MockClock()
        cache = ExpiringCache("test", clock, max_len=1)

        cache["key"] = "value"
        self.assertEquals(cache.get("key"), "value")
        self.assertEquals(cache["key"], "value")

    def test_eviction(self):
        clock = MockClock()
        cache = ExpiringCache("test", clock, max_len=2)

        cache["key"] = "value"
        cache["key2"] = "value2"
        self.assertEquals(cache.get("key"), "value")
        self.assertEquals(cache.get("key2"), "value2")

        cache["key3"] = "value3"
        self.assertEquals(cache.get("key"), None)
        self.assertEquals(cache.get("key2"), "value2")
        self.assertEquals(cache.get("key3"), "value3")

    def test_iterable_eviction(self):
        clock = MockClock()
        cache = ExpiringCache("test", clock, max_len=5, iterable=True)

        cache["key"] = [1]
        cache["key2"] = [2, 3]
        cache["key3"] = [4, 5]

        self.assertEquals(cache.get("key"), [1])
        self.assertEquals(cache.get("key2"), [2, 3])
        self.assertEquals(cache.get("key3"), [4, 5])

        cache["key4"] = [6, 7]
        self.assertEquals(cache.get("key"), None)
        self.assertEquals(cache.get("key2"), None)
        self.assertEquals(cache.get("key3"), [4, 5])
        self.assertEquals(cache.get("key4"), [6, 7])

    def test_time_eviction(self):
        clock = MockClock()
        cache = ExpiringCache("test", clock, expiry_ms=1000)
        cache.start()

        cache["key"] = 1
        clock.advance_time(0.5)
        cache["key2"] = 2

        self.assertEquals(cache.get("key"), 1)
        self.assertEquals(cache.get("key2"), 2)

        clock.advance_time(0.9)
        self.assertEquals(cache.get("key"), None)
        self.assertEquals(cache.get("key2"), 2)

        clock.advance_time(1)
        self.assertEquals(cache.get("key"), None)
        self.assertEquals(cache.get("key2"), None)
