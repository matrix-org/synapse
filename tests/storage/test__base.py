# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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


from mock import Mock

from twisted.internet import defer

from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.descriptors import Cache, cached

from tests import unittest


class CacheTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.cache = Cache("test")

    def test_empty(self):
        failed = False
        try:
            self.cache.get("foo")
        except KeyError:
            failed = True

        self.assertTrue(failed)

    def test_hit(self):
        self.cache.prefill("foo", 123)

        self.assertEquals(self.cache.get("foo"), 123)

    def test_invalidate(self):
        self.cache.prefill(("foo",), 123)
        self.cache.invalidate(("foo",))

        failed = False
        try:
            self.cache.get(("foo",))
        except KeyError:
            failed = True

        self.assertTrue(failed)

    def test_eviction(self):
        cache = Cache("test", max_entries=2)

        cache.prefill(1, "one")
        cache.prefill(2, "two")
        cache.prefill(3, "three")  # 1 will be evicted

        failed = False
        try:
            cache.get(1)
        except KeyError:
            failed = True

        self.assertTrue(failed)

        cache.get(2)
        cache.get(3)

    def test_eviction_lru(self):
        cache = Cache("test", max_entries=2)

        cache.prefill(1, "one")
        cache.prefill(2, "two")

        # Now access 1 again, thus causing 2 to be least-recently used
        cache.get(1)

        cache.prefill(3, "three")

        failed = False
        try:
            cache.get(2)
        except KeyError:
            failed = True

        self.assertTrue(failed)

        cache.get(1)
        cache.get(3)


class CacheDecoratorTestCase(unittest.HomeserverTestCase):
    @defer.inlineCallbacks
    def test_passthrough(self):
        class A(object):
            @cached()
            def func(self, key):
                return key

        a = A()

        self.assertEquals((yield a.func("foo")), "foo")
        self.assertEquals((yield a.func("bar")), "bar")

    @defer.inlineCallbacks
    def test_hit(self):
        callcount = [0]

        class A(object):
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()
        yield a.func("foo")

        self.assertEquals(callcount[0], 1)

        self.assertEquals((yield a.func("foo")), "foo")
        self.assertEquals(callcount[0], 1)

    @defer.inlineCallbacks
    def test_invalidate(self):
        callcount = [0]

        class A(object):
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()
        yield a.func("foo")

        self.assertEquals(callcount[0], 1)

        a.func.invalidate(("foo",))

        yield a.func("foo")

        self.assertEquals(callcount[0], 2)

    def test_invalidate_missing(self):
        class A(object):
            @cached()
            def func(self, key):
                return key

        A().func.invalidate(("what",))

    @defer.inlineCallbacks
    def test_max_entries(self):
        callcount = [0]

        class A(object):
            @cached(max_entries=10)
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()

        for k in range(0, 12):
            yield a.func(k)

        self.assertEquals(callcount[0], 12)

        # There must have been at least 2 evictions, meaning if we calculate
        # all 12 values again, we must get called at least 2 more times
        for k in range(0, 12):
            yield a.func(k)

        self.assertTrue(
            callcount[0] >= 14, msg="Expected callcount >= 14, got %d" % (callcount[0])
        )

    def test_prefill(self):
        callcount = [0]

        d = defer.succeed(123)

        class A(object):
            @cached()
            def func(self, key):
                callcount[0] += 1
                return d

        a = A()

        a.func.prefill(("foo",), ObservableDeferred(d))

        self.assertEquals(a.func("foo").result, d.result)
        self.assertEquals(callcount[0], 0)

    @defer.inlineCallbacks
    def test_invalidate_context(self):
        callcount = [0]
        callcount2 = [0]

        class A(object):
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

            @cached(cache_context=True)
            def func2(self, key, cache_context):
                callcount2[0] += 1
                return self.func(key, on_invalidate=cache_context.invalidate)

        a = A()
        yield a.func2("foo")

        self.assertEquals(callcount[0], 1)
        self.assertEquals(callcount2[0], 1)

        a.func.invalidate(("foo",))
        yield a.func("foo")

        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 1)

        yield a.func2("foo")

        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 2)

    @defer.inlineCallbacks
    def test_eviction_context(self):
        callcount = [0]
        callcount2 = [0]

        class A(object):
            @cached(max_entries=2)
            def func(self, key):
                callcount[0] += 1
                return key

            @cached(cache_context=True)
            def func2(self, key, cache_context):
                callcount2[0] += 1
                return self.func(key, on_invalidate=cache_context.invalidate)

        a = A()
        yield a.func2("foo")
        yield a.func2("foo2")

        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 2)

        yield a.func2("foo")
        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 2)

        yield a.func("foo3")

        self.assertEquals(callcount[0], 3)
        self.assertEquals(callcount2[0], 2)

        yield a.func2("foo")

        self.assertEquals(callcount[0], 4)
        self.assertEquals(callcount2[0], 3)

    @defer.inlineCallbacks
    def test_double_get(self):
        callcount = [0]
        callcount2 = [0]

        class A(object):
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

            @cached(cache_context=True)
            def func2(self, key, cache_context):
                callcount2[0] += 1
                return self.func(key, on_invalidate=cache_context.invalidate)

        a = A()
        a.func2.cache.cache = Mock(wraps=a.func2.cache.cache)

        yield a.func2("foo")

        self.assertEquals(callcount[0], 1)
        self.assertEquals(callcount2[0], 1)

        a.func2.invalidate(("foo",))
        self.assertEquals(a.func2.cache.cache.pop.call_count, 1)

        yield a.func2("foo")
        a.func2.invalidate(("foo",))
        self.assertEquals(a.func2.cache.cache.pop.call_count, 2)

        self.assertEquals(callcount[0], 1)
        self.assertEquals(callcount2[0], 2)

        a.func.invalidate(("foo",))
        self.assertEquals(a.func2.cache.cache.pop.call_count, 3)
        yield a.func("foo")

        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 2)

        yield a.func2("foo")

        self.assertEquals(callcount[0], 2)
        self.assertEquals(callcount2[0], 3)


class UpsertManyTests(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.storage = hs.get_datastore()

        self.table_name = "table_" + hs.get_secrets().token_hex(6)
        self.get_success(
            self.storage.db.runInteraction(
                "create",
                lambda x, *a: x.execute(*a),
                "CREATE TABLE %s (id INTEGER, username TEXT, value TEXT)"
                % (self.table_name,),
            )
        )
        self.get_success(
            self.storage.db.runInteraction(
                "index",
                lambda x, *a: x.execute(*a),
                "CREATE UNIQUE INDEX %sindex ON %s(id, username)"
                % (self.table_name, self.table_name),
            )
        )

    def _dump_to_tuple(self, res):
        for i in res:
            yield (i["id"], i["username"], i["value"])

    def test_upsert_many(self):
        """
        Upsert_many will perform the upsert operation across a batch of data.
        """
        # Add some data to an empty table
        key_names = ["id", "username"]
        value_names = ["value"]
        key_values = [[1, "user1"], [2, "user2"]]
        value_values = [["hello"], ["there"]]

        self.get_success(
            self.storage.db.runInteraction(
                "test",
                self.storage.db.simple_upsert_many_txn,
                self.table_name,
                key_names,
                key_values,
                value_names,
                value_values,
            )
        )

        # Check results are what we expect
        res = self.get_success(
            self.storage.db.simple_select_list(
                self.table_name, None, ["id, username, value"]
            )
        )
        self.assertEqual(
            set(self._dump_to_tuple(res)),
            {(1, "user1", "hello"), (2, "user2", "there")},
        )

        # Update only user2
        key_values = [[2, "user2"]]
        value_values = [["bleb"]]

        self.get_success(
            self.storage.db.runInteraction(
                "test",
                self.storage.db.simple_upsert_many_txn,
                self.table_name,
                key_names,
                key_values,
                value_names,
                value_values,
            )
        )

        # Check results are what we expect
        res = self.get_success(
            self.storage.db.simple_select_list(
                self.table_name, None, ["id, username, value"]
            )
        )
        self.assertEqual(
            set(self._dump_to_tuple(res)),
            {(1, "user1", "hello"), (2, "user2", "bleb")},
        )
