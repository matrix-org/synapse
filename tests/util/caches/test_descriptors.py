# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
import logging
from functools import partial

import mock

from twisted.internet import defer, reactor

from synapse.api.errors import SynapseError
from synapse.util import logcontext
from synapse.util.caches import descriptors

from tests import unittest

logger = logging.getLogger(__name__)


def run_on_reactor():
    d = defer.Deferred()
    reactor.callLater(0, d.callback, 0)
    return logcontext.make_deferred_yieldable(d)


class CacheTestCase(unittest.TestCase):
    def test_invalidate_all(self):
        cache = descriptors.Cache("testcache")

        callback_record = [False, False]

        def record_callback(idx):
            callback_record[idx] = True

        # add a couple of pending entries
        d1 = defer.Deferred()
        cache.set("key1", d1, partial(record_callback, 0))

        d2 = defer.Deferred()
        cache.set("key2", d2, partial(record_callback, 1))

        # lookup should return the deferreds
        self.assertIs(cache.get("key1"), d1)
        self.assertIs(cache.get("key2"), d2)

        # let one of the lookups complete
        d2.callback("result2")
        self.assertEqual(cache.get("key2"), "result2")

        # now do the invalidation
        cache.invalidate_all()

        # lookup should return none
        self.assertIsNone(cache.get("key1", None))
        self.assertIsNone(cache.get("key2", None))

        # both callbacks should have been callbacked
        self.assertTrue(callback_record[0], "Invalidation callback for key1 not called")
        self.assertTrue(callback_record[1], "Invalidation callback for key2 not called")

        # letting the other lookup complete should do nothing
        d1.callback("result1")
        self.assertIsNone(cache.get("key1", None))


class DescriptorTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_cache(self):
        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()

        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(1, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(1, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(1, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()

    @defer.inlineCallbacks
    def test_cache_num_args(self):
        """Only the first num_args arguments should matter to the cache"""

        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached(num_args=1)
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()
        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(2, 3)
        obj.mock.reset_mock()

        # the two values should now be cached; we should be able to vary
        # the second argument and still get the cached result.
        r = yield obj.fn(1, 4)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(2, 5)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()

    def test_cache_logcontexts(self):
        """Check that logcontexts are set and restored correctly when
        using the cache."""

        complete_lookup = defer.Deferred()

        class Cls(object):
            @descriptors.cached()
            def fn(self, arg1):
                @defer.inlineCallbacks
                def inner_fn():
                    with logcontext.PreserveLoggingContext():
                        yield complete_lookup
                    defer.returnValue(1)

                return inner_fn()

        @defer.inlineCallbacks
        def do_lookup():
            with logcontext.LoggingContext() as c1:
                c1.name = "c1"
                r = yield obj.fn(1)
                self.assertEqual(logcontext.LoggingContext.current_context(), c1)
            defer.returnValue(r)

        def check_result(r):
            self.assertEqual(r, 1)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(
            logcontext.LoggingContext.current_context(),
            logcontext.LoggingContext.sentinel,
        )
        d1.addCallback(check_result)

        # and another
        d2 = do_lookup()
        self.assertEqual(
            logcontext.LoggingContext.current_context(),
            logcontext.LoggingContext.sentinel,
        )
        d2.addCallback(check_result)

        # let the lookup complete
        complete_lookup.callback(None)

        return defer.gatherResults([d1, d2])

    def test_cache_logcontexts_with_exception(self):
        """Check that the cache sets and restores logcontexts correctly when
        the lookup function throws an exception"""

        class Cls(object):
            @descriptors.cached()
            def fn(self, arg1):
                @defer.inlineCallbacks
                def inner_fn():
                    # we want this to behave like an asynchronous function
                    yield run_on_reactor()
                    raise SynapseError(400, "blah")

                return inner_fn()

        @defer.inlineCallbacks
        def do_lookup():
            with logcontext.LoggingContext() as c1:
                c1.name = "c1"
                try:
                    d = obj.fn(1)
                    self.assertEqual(
                        logcontext.LoggingContext.current_context(),
                        logcontext.LoggingContext.sentinel,
                    )
                    yield d
                    self.fail("No exception thrown")
                except SynapseError:
                    pass

                self.assertEqual(logcontext.LoggingContext.current_context(), c1)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(
            logcontext.LoggingContext.current_context(),
            logcontext.LoggingContext.sentinel,
        )

        return d1

    @defer.inlineCallbacks
    def test_cache_default_args(self):
        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2=2, arg3=3):
                return self.mock(arg1, arg2, arg3)

        obj = Cls()

        obj.mock.return_value = 'fish'
        r = yield obj.fn(1, 2, 3)
        self.assertEqual(r, 'fish')
        obj.mock.assert_called_once_with(1, 2, 3)
        obj.mock.reset_mock()

        # a call with same params shouldn't call the mock again
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        obj.mock.assert_not_called()
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = 'chips'
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_called_once_with(2, 3, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, 'fish')
        r = yield obj.fn(2, 3)
        self.assertEqual(r, 'chips')
        obj.mock.assert_not_called()


class CachedListDescriptorTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_cache(self):
        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                pass

            @descriptors.cachedList("fn", "args1", inlineCallbacks=True)
            def list_fn(self, args1, arg2):
                assert logcontext.LoggingContext.current_context().request == "c1"
                # we want this to behave like an asynchronous function
                yield run_on_reactor()
                assert logcontext.LoggingContext.current_context().request == "c1"
                defer.returnValue(self.mock(args1, arg2))

        with logcontext.LoggingContext() as c1:
            c1.request = "c1"
            obj = Cls()
            obj.mock.return_value = {10: 'fish', 20: 'chips'}
            d1 = obj.list_fn([10, 20], 2)
            self.assertEqual(
                logcontext.LoggingContext.current_context(),
                logcontext.LoggingContext.sentinel,
            )
            r = yield d1
            self.assertEqual(logcontext.LoggingContext.current_context(), c1)
            obj.mock.assert_called_once_with([10, 20], 2)
            self.assertEqual(r, {10: 'fish', 20: 'chips'})
            obj.mock.reset_mock()

            # a call with different params should call the mock again
            obj.mock.return_value = {30: 'peas'}
            r = yield obj.list_fn([20, 30], 2)
            obj.mock.assert_called_once_with([30], 2)
            self.assertEqual(r, {20: 'chips', 30: 'peas'})
            obj.mock.reset_mock()

            # all the values should now be cached
            r = yield obj.fn(10, 2)
            self.assertEqual(r, 'fish')
            r = yield obj.fn(20, 2)
            self.assertEqual(r, 'chips')
            r = yield obj.fn(30, 2)
            self.assertEqual(r, 'peas')
            r = yield obj.list_fn([10, 20, 30], 2)
            obj.mock.assert_not_called()
            self.assertEqual(r, {10: 'fish', 20: 'chips', 30: 'peas'})

    @defer.inlineCallbacks
    def test_invalidate(self):
        """Make sure that invalidation callbacks are called."""

        class Cls(object):
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                pass

            @descriptors.cachedList("fn", "args1", inlineCallbacks=True)
            def list_fn(self, args1, arg2):
                # we want this to behave like an asynchronous function
                yield run_on_reactor()
                defer.returnValue(self.mock(args1, arg2))

        obj = Cls()
        invalidate0 = mock.Mock()
        invalidate1 = mock.Mock()

        # cache miss
        obj.mock.return_value = {10: 'fish', 20: 'chips'}
        r1 = yield obj.list_fn([10, 20], 2, on_invalidate=invalidate0)
        obj.mock.assert_called_once_with([10, 20], 2)
        self.assertEqual(r1, {10: 'fish', 20: 'chips'})
        obj.mock.reset_mock()

        # cache hit
        r2 = yield obj.list_fn([10, 20], 2, on_invalidate=invalidate1)
        obj.mock.assert_not_called()
        self.assertEqual(r2, {10: 'fish', 20: 'chips'})

        invalidate0.assert_not_called()
        invalidate1.assert_not_called()

        # now if we invalidate the keys, both invalidations should get called
        obj.fn.invalidate((10, 2))
        invalidate0.assert_called_once()
        invalidate1.assert_called_once()
