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

from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.treecache import TreeCache

from mock import Mock


class LruCacheTestCase(unittest.TestCase):

    def test_get_set(self):
        cache = LruCache(1)
        cache["key"] = "value"
        self.assertEqual(cache.get("key"), "value")
        self.assertEqual(cache["key"], "value")

    def test_eviction(self):
        cache = LruCache(2)
        cache[1] = 1
        cache[2] = 2

        self.assertEqual(cache.get(1), 1)
        self.assertEqual(cache.get(2), 2)

        cache[3] = 3

        self.assertEqual(cache.get(1), None)
        self.assertEqual(cache.get(2), 2)
        self.assertEqual(cache.get(3), 3)

    def test_setdefault(self):
        cache = LruCache(1)
        self.assertEqual(cache.setdefault("key", 1), 1)
        self.assertEqual(cache.get("key"), 1)
        self.assertEqual(cache.setdefault("key", 2), 1)
        self.assertEqual(cache.get("key"), 1)
        cache["key"] = 2  # Make sure overriding works.
        self.assertEqual(cache.get("key"), 2)

    def test_pop(self):
        cache = LruCache(1)
        cache["key"] = 1
        self.assertEqual(cache.pop("key"), 1)
        self.assertEqual(cache.pop("key"), None)

    def test_del_multi(self):
        cache = LruCache(4, 2, cache_type=TreeCache)
        cache[("animal", "cat")] = "mew"
        cache[("animal", "dog")] = "woof"
        cache[("vehicles", "car")] = "vroom"
        cache[("vehicles", "train")] = "chuff"

        self.assertEqual(len(cache), 4)

        self.assertEqual(cache.get(("animal", "cat")), "mew")
        self.assertEqual(cache.get(("vehicles", "car")), "vroom")
        cache.del_multi(("animal",))
        self.assertEqual(len(cache), 2)
        self.assertEqual(cache.get(("animal", "cat")), None)
        self.assertEqual(cache.get(("animal", "dog")), None)
        self.assertEqual(cache.get(("vehicles", "car")), "vroom")
        self.assertEqual(cache.get(("vehicles", "train")), "chuff")
        # Man from del_multi say "Yes".

    def test_clear(self):
        cache = LruCache(1)
        cache["key"] = 1
        cache.clear()
        self.assertEqual(len(cache), 0)


class LruCacheCallbacksTestCase(unittest.TestCase):
    def test_get(self):
        m = Mock()
        cache = LruCache(1)

        cache.set("key", "value")
        self.assertFalse(m.called)

        cache.get("key", callbacks=[m])
        self.assertFalse(m.called)

        cache.get("key", "value")
        self.assertFalse(m.called)

        cache.set("key", "value2")
        self.assertEqual(m.call_count, 1)

        cache.set("key", "value")
        self.assertEqual(m.call_count, 1)

    def test_multi_get(self):
        m = Mock()
        cache = LruCache(1)

        cache.set("key", "value")
        self.assertFalse(m.called)

        cache.get("key", callbacks=[m])
        self.assertFalse(m.called)

        cache.get("key", callbacks=[m])
        self.assertFalse(m.called)

        cache.set("key", "value2")
        self.assertEqual(m.call_count, 1)

        cache.set("key", "value")
        self.assertEqual(m.call_count, 1)

    def test_set(self):
        m = Mock()
        cache = LruCache(1)

        cache.set("key", "value", callbacks=[m])
        self.assertFalse(m.called)

        cache.set("key", "value")
        self.assertFalse(m.called)

        cache.set("key", "value2")
        self.assertEqual(m.call_count, 1)

        cache.set("key", "value")
        self.assertEqual(m.call_count, 1)

    def test_pop(self):
        m = Mock()
        cache = LruCache(1)

        cache.set("key", "value", callbacks=[m])
        self.assertFalse(m.called)

        cache.pop("key")
        self.assertEqual(m.call_count, 1)

        cache.set("key", "value")
        self.assertEqual(m.call_count, 1)

        cache.pop("key")
        self.assertEqual(m.call_count, 1)

    def test_del_multi(self):
        m1 = Mock()
        m2 = Mock()
        m3 = Mock()
        m4 = Mock()
        cache = LruCache(4, 2, cache_type=TreeCache)

        cache.set(("a", "1"), "value", callbacks=[m1])
        cache.set(("a", "2"), "value", callbacks=[m2])
        cache.set(("b", "1"), "value", callbacks=[m3])
        cache.set(("b", "2"), "value", callbacks=[m4])

        self.assertEqual(m1.call_count, 0)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 0)
        self.assertEqual(m4.call_count, 0)

        cache.del_multi(("a",))

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 1)
        self.assertEqual(m3.call_count, 0)
        self.assertEqual(m4.call_count, 0)

    def test_clear(self):
        m1 = Mock()
        m2 = Mock()
        cache = LruCache(5)

        cache.set("key1", "value", callbacks=[m1])
        cache.set("key2", "value", callbacks=[m2])

        self.assertEqual(m1.call_count, 0)
        self.assertEqual(m2.call_count, 0)

        cache.clear()

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 1)

    def test_eviction(self):
        m1 = Mock(name="m1")
        m2 = Mock(name="m2")
        m3 = Mock(name="m3")
        cache = LruCache(2)

        cache.set("key1", "value", callbacks=[m1])
        cache.set("key2", "value", callbacks=[m2])

        self.assertEqual(m1.call_count, 0)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 0)

        cache.set("key3", "value", callbacks=[m3])

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 0)

        cache.set("key3", "value")

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 0)

        cache.get("key2")

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 0)

        cache.set("key1", "value", callbacks=[m1])

        self.assertEqual(m1.call_count, 1)
        self.assertEqual(m2.call_count, 0)
        self.assertEqual(m3.call_count, 1)


class LruCacheSizedTestCase(unittest.TestCase):

    def test_evict(self):
        cache = LruCache(5, size_callback=len)
        cache["key1"] = [0]
        cache["key2"] = [1, 2]
        cache["key3"] = [3]
        cache["key4"] = [4]

        self.assertEqual(cache["key1"], [0])
        self.assertEqual(cache["key2"], [1, 2])
        self.assertEqual(cache["key3"], [3])
        self.assertEqual(cache["key4"], [4])
        self.assertEqual(len(cache), 5)

        cache["key5"] = [5, 6]

        self.assertEqual(len(cache), 4)
        self.assertEqual(cache.get("key1"), None)
        self.assertEqual(cache.get("key2"), None)
        self.assertEqual(cache["key3"], [3])
        self.assertEqual(cache["key4"], [4])
        self.assertEqual(cache["key5"], [5, 6])
