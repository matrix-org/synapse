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


class LruCacheTestCase(unittest.TestCase):

    def test_get_set(self):
        cache = LruCache(1)
        cache["key"] = "value"
        self.assertEquals(cache.get("key"), "value")
        self.assertEquals(cache["key"], "value")

    def test_eviction(self):
        cache = LruCache(2)
        cache[1] = 1
        cache[2] = 2

        self.assertEquals(cache.get(1), 1)
        self.assertEquals(cache.get(2), 2)

        cache[3] = 3

        self.assertEquals(cache.get(1), None)
        self.assertEquals(cache.get(2), 2)
        self.assertEquals(cache.get(3), 3)

    def test_setdefault(self):
        cache = LruCache(1)
        self.assertEquals(cache.setdefault("key", 1), 1)
        self.assertEquals(cache.get("key"), 1)
        self.assertEquals(cache.setdefault("key", 2), 1)
        self.assertEquals(cache.get("key"), 1)

    def test_pop(self):
        cache = LruCache(1)
        cache["key"] = 1
        self.assertEquals(cache.pop("key"), 1)
        self.assertEquals(cache.pop("key"), None)

    def test_del_multi(self):
        cache = LruCache(4, 2, cache_type=TreeCache)
        cache[("animal", "cat")] = "mew"
        cache[("animal", "dog")] = "woof"
        cache[("vehicles", "car")] = "vroom"
        cache[("vehicles", "train")] = "chuff"

        self.assertEquals(len(cache), 4)

        self.assertEquals(cache.get(("animal", "cat")), "mew")
        self.assertEquals(cache.get(("vehicles", "car")), "vroom")
        cache.del_multi(("animal",))
        self.assertEquals(len(cache), 2)
        self.assertEquals(cache.get(("animal", "cat")), None)
        self.assertEquals(cache.get(("animal", "dog")), None)
        self.assertEquals(cache.get(("vehicles", "car")), "vroom")
        self.assertEquals(cache.get(("vehicles", "train")), "chuff")
        # Man from del_multi say "Yes".

    def test_clear(self):
        cache = LruCache(1)
        cache["key"] = 1
        cache.clear()
        self.assertEquals(len(cache), 0)
