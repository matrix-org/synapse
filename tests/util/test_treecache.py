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

from synapse.util.caches.treecache import TreeCache


class TreeCacheTestCase(unittest.TestCase):
    def test_get_set_onelevel(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        self.assertEquals(cache.get(("a",)), "A")
        self.assertEquals(cache.get(("b",)), "B")
        self.assertEquals(len(cache), 2)

    def test_pop_onelevel(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        self.assertEquals(cache.pop(("a",)), "A")
        self.assertEquals(cache.pop(("a",)), None)
        self.assertEquals(cache.get(("b",)), "B")
        self.assertEquals(len(cache), 1)

    def test_get_set_twolevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEquals(cache.get(("a", "a")), "AA")
        self.assertEquals(cache.get(("a", "b")), "AB")
        self.assertEquals(cache.get(("b", "a")), "BA")
        self.assertEquals(len(cache), 3)

    def test_pop_twolevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEquals(cache.pop(("a", "a")), "AA")
        self.assertEquals(cache.get(("a", "a")), None)
        self.assertEquals(cache.get(("a", "b")), "AB")
        self.assertEquals(cache.pop(("b", "a")), "BA")
        self.assertEquals(cache.pop(("b", "a")), None)
        self.assertEquals(len(cache), 1)

    def test_pop_mixedlevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEquals(cache.get(("a", "a")), "AA")
        cache.pop(("a",))
        self.assertEquals(cache.get(("a", "a")), None)
        self.assertEquals(cache.get(("a", "b")), None)
        self.assertEquals(cache.get(("b", "a")), "BA")
        self.assertEquals(len(cache), 1)

    def test_clear(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        cache.clear()
        self.assertEquals(len(cache), 0)

    def test_contains(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        self.assertTrue(("a",) in cache)
        self.assertFalse(("b",) in cache)
