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


from synapse.util.caches.treecache import TreeCache, iterate_tree_cache_entry

from .. import unittest


class TreeCacheTestCase(unittest.TestCase):
    def test_get_set_onelevel(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        self.assertEqual(cache.get(("a",)), "A")
        self.assertEqual(cache.get(("b",)), "B")
        self.assertEqual(len(cache), 2)

    def test_pop_onelevel(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        self.assertEqual(cache.pop(("a",)), "A")
        self.assertEqual(cache.pop(("a",)), None)
        self.assertEqual(cache.get(("b",)), "B")
        self.assertEqual(len(cache), 1)

    def test_get_set_twolevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEqual(cache.get(("a", "a")), "AA")
        self.assertEqual(cache.get(("a", "b")), "AB")
        self.assertEqual(cache.get(("b", "a")), "BA")
        self.assertEqual(len(cache), 3)

    def test_pop_twolevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEqual(cache.pop(("a", "a")), "AA")
        self.assertEqual(cache.get(("a", "a")), None)
        self.assertEqual(cache.get(("a", "b")), "AB")
        self.assertEqual(cache.pop(("b", "a")), "BA")
        self.assertEqual(cache.pop(("b", "a")), None)
        self.assertEqual(len(cache), 1)

    def test_pop_mixedlevel(self):
        cache = TreeCache()
        cache[("a", "a")] = "AA"
        cache[("a", "b")] = "AB"
        cache[("b", "a")] = "BA"
        self.assertEqual(cache.get(("a", "a")), "AA")
        popped = cache.pop(("a",))
        self.assertEqual(cache.get(("a", "a")), None)
        self.assertEqual(cache.get(("a", "b")), None)
        self.assertEqual(cache.get(("b", "a")), "BA")
        self.assertEqual(len(cache), 1)

        self.assertEqual({"AA", "AB"}, set(iterate_tree_cache_entry(popped)))

    def test_clear(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        cache[("b",)] = "B"
        cache.clear()
        self.assertEqual(len(cache), 0)

    def test_contains(self):
        cache = TreeCache()
        cache[("a",)] = "A"
        self.assertTrue(("a",) in cache)
        self.assertFalse(("b",) in cache)
