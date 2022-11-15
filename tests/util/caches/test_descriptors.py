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
from typing import Iterable, Set, Tuple
from unittest import mock

from twisted.internet import defer, reactor
from twisted.internet.defer import CancelledError, Deferred

from synapse.api.errors import SynapseError
from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    PreserveLoggingContext,
    current_context,
    make_deferred_yieldable,
)
from synapse.util.caches import descriptors
from synapse.util.caches.descriptors import cached, cachedList

from tests import unittest
from tests.test_utils import get_awaitable_result

logger = logging.getLogger(__name__)


def run_on_reactor():
    d = defer.Deferred()
    reactor.callLater(0, d.callback, 0)
    return make_deferred_yieldable(d)


class DescriptorTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_cache(self):
        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()

        obj.mock.return_value = "fish"
        r = yield obj.fn(1, 2)
        self.assertEqual(r, "fish")
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = "chips"
        r = yield obj.fn(1, 3)
        self.assertEqual(r, "chips")
        obj.mock.assert_called_once_with(1, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, "fish")
        r = yield obj.fn(1, 3)
        self.assertEqual(r, "chips")
        obj.mock.assert_not_called()

    @defer.inlineCallbacks
    def test_cache_num_args(self):
        """Only the first num_args arguments should matter to the cache"""

        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached(num_args=1)
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()
        obj.mock.return_value = "fish"
        r = yield obj.fn(1, 2)
        self.assertEqual(r, "fish")
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = "chips"
        r = yield obj.fn(2, 3)
        self.assertEqual(r, "chips")
        obj.mock.assert_called_once_with(2, 3)
        obj.mock.reset_mock()

        # the two values should now be cached; we should be able to vary
        # the second argument and still get the cached result.
        r = yield obj.fn(1, 4)
        self.assertEqual(r, "fish")
        r = yield obj.fn(2, 5)
        self.assertEqual(r, "chips")
        obj.mock.assert_not_called()

    @defer.inlineCallbacks
    def test_cache_uncached_args(self):
        """
        Only the arguments not named in uncached_args should matter to the cache

        Note that this is identical to test_cache_num_args, but provides the
        arguments differently.
        """

        class Cls:
            # Note that it is important that this is not the last argument to
            # test behaviour of skipping arguments properly.
            @descriptors.cached(uncached_args=("arg2",))
            def fn(self, arg1, arg2, arg3):
                return self.mock(arg1, arg2, arg3)

            def __init__(self):
                self.mock = mock.Mock()

        obj = Cls()
        obj.mock.return_value = "fish"
        r = yield obj.fn(1, 2, 3)
        self.assertEqual(r, "fish")
        obj.mock.assert_called_once_with(1, 2, 3)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = "chips"
        r = yield obj.fn(2, 3, 4)
        self.assertEqual(r, "chips")
        obj.mock.assert_called_once_with(2, 3, 4)
        obj.mock.reset_mock()

        # the two values should now be cached; we should be able to vary
        # the second argument and still get the cached result.
        r = yield obj.fn(1, 4, 3)
        self.assertEqual(r, "fish")
        r = yield obj.fn(2, 5, 4)
        self.assertEqual(r, "chips")
        obj.mock.assert_not_called()

    @defer.inlineCallbacks
    def test_cache_kwargs(self):
        """Test that keyword arguments are treated properly"""

        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, kwarg1=2):
                return self.mock(arg1, kwarg1=kwarg1)

        obj = Cls()
        obj.mock.return_value = "fish"
        r = yield obj.fn(1, kwarg1=2)
        self.assertEqual(r, "fish")
        obj.mock.assert_called_once_with(1, kwarg1=2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = "chips"
        r = yield obj.fn(1, kwarg1=3)
        self.assertEqual(r, "chips")
        obj.mock.assert_called_once_with(1, kwarg1=3)
        obj.mock.reset_mock()

        # the values should now be cached.
        r = yield obj.fn(1, kwarg1=2)
        self.assertEqual(r, "fish")
        # We should be able to not provide kwarg1 and get the cached value back.
        r = yield obj.fn(1)
        self.assertEqual(r, "fish")
        # Keyword arguments can be in any order.
        r = yield obj.fn(kwarg1=2, arg1=1)
        self.assertEqual(r, "fish")
        obj.mock.assert_not_called()

    def test_cache_with_sync_exception(self):
        """If the wrapped function throws synchronously, things should continue to work"""

        class Cls:
            @cached()
            def fn(self, arg1):
                raise SynapseError(100, "mai spoon iz too big!!1")

        obj = Cls()

        # this should fail immediately
        d = obj.fn(1)
        self.failureResultOf(d, SynapseError)

        # ... leaving the cache empty
        self.assertEqual(len(obj.fn.cache.cache), 0)

        # and a second call should result in a second exception
        d = obj.fn(1)
        self.failureResultOf(d, SynapseError)

    def test_cache_with_async_exception(self):
        """The wrapped function returns a failure"""

        class Cls:
            result = None
            call_count = 0

            @cached()
            def fn(self, arg1):
                self.call_count += 1
                return self.result

        obj = Cls()
        callbacks: Set[str] = set()

        # set off an asynchronous request
        obj.result = origin_d = defer.Deferred()

        d1 = obj.fn(1, on_invalidate=lambda: callbacks.add("d1"))
        self.assertFalse(d1.called)

        # a second request should also return a deferred, but should not call the
        # function itself.
        d2 = obj.fn(1, on_invalidate=lambda: callbacks.add("d2"))
        self.assertFalse(d2.called)
        self.assertEqual(obj.call_count, 1)

        # no callbacks yet
        self.assertEqual(callbacks, set())

        # the original request fails
        e = Exception("bzz")
        origin_d.errback(e)

        # ... which should cause the lookups to fail similarly
        self.assertIs(self.failureResultOf(d1, Exception).value, e)
        self.assertIs(self.failureResultOf(d2, Exception).value, e)

        # ... and the callbacks to have been, uh, called.
        self.assertEqual(callbacks, {"d1", "d2"})

        # ... leaving the cache empty
        self.assertEqual(len(obj.fn.cache.cache), 0)

        # and a second call should work as normal
        obj.result = defer.succeed(100)
        d3 = obj.fn(1)
        self.assertEqual(self.successResultOf(d3), 100)
        self.assertEqual(obj.call_count, 2)

    def test_cache_logcontexts(self):
        """Check that logcontexts are set and restored correctly when
        using the cache."""

        complete_lookup = defer.Deferred()

        class Cls:
            @descriptors.cached()
            def fn(self, arg1):
                @defer.inlineCallbacks
                def inner_fn():
                    with PreserveLoggingContext():
                        yield complete_lookup
                    return 1

                return inner_fn()

        @defer.inlineCallbacks
        def do_lookup():
            with LoggingContext("c1") as c1:
                r = yield obj.fn(1)
                self.assertEqual(current_context(), c1)
            return r

        def check_result(r):
            self.assertEqual(r, 1)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(current_context(), SENTINEL_CONTEXT)
        d1.addCallback(check_result)

        # and another
        d2 = do_lookup()
        self.assertEqual(current_context(), SENTINEL_CONTEXT)
        d2.addCallback(check_result)

        # let the lookup complete
        complete_lookup.callback(None)

        return defer.gatherResults([d1, d2])

    def test_cache_logcontexts_with_exception(self):
        """Check that the cache sets and restores logcontexts correctly when
        the lookup function throws an exception"""

        class Cls:
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
            with LoggingContext("c1") as c1:
                try:
                    d = obj.fn(1)
                    self.assertEqual(
                        current_context(),
                        SENTINEL_CONTEXT,
                    )
                    yield d
                    self.fail("No exception thrown")
                except SynapseError:
                    pass

                self.assertEqual(current_context(), c1)

            # the cache should now be empty
            self.assertEqual(len(obj.fn.cache.cache), 0)

        obj = Cls()

        # set off a deferred which will do a cache lookup
        d1 = do_lookup()
        self.assertEqual(current_context(), SENTINEL_CONTEXT)

        return d1

    @defer.inlineCallbacks
    def test_cache_default_args(self):
        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2=2, arg3=3):
                return self.mock(arg1, arg2, arg3)

        obj = Cls()

        obj.mock.return_value = "fish"
        r = yield obj.fn(1, 2, 3)
        self.assertEqual(r, "fish")
        obj.mock.assert_called_once_with(1, 2, 3)
        obj.mock.reset_mock()

        # a call with same params shouldn't call the mock again
        r = yield obj.fn(1, 2)
        self.assertEqual(r, "fish")
        obj.mock.assert_not_called()
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = "chips"
        r = yield obj.fn(2, 3)
        self.assertEqual(r, "chips")
        obj.mock.assert_called_once_with(2, 3, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        r = yield obj.fn(1, 2)
        self.assertEqual(r, "fish")
        r = yield obj.fn(2, 3)
        self.assertEqual(r, "chips")
        obj.mock.assert_not_called()

    def test_cache_iterable(self):
        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached(iterable=True)
            def fn(self, arg1, arg2):
                return self.mock(arg1, arg2)

        obj = Cls()

        obj.mock.return_value = ["spam", "eggs"]
        r = obj.fn(1, 2)
        self.assertEqual(r.result, ["spam", "eggs"])
        obj.mock.assert_called_once_with(1, 2)
        obj.mock.reset_mock()

        # a call with different params should call the mock again
        obj.mock.return_value = ["chips"]
        r = obj.fn(1, 3)
        self.assertEqual(r.result, ["chips"])
        obj.mock.assert_called_once_with(1, 3)
        obj.mock.reset_mock()

        # the two values should now be cached
        self.assertEqual(len(obj.fn.cache.cache), 3)

        r = obj.fn(1, 2)
        self.assertEqual(r.result, ["spam", "eggs"])
        r = obj.fn(1, 3)
        self.assertEqual(r.result, ["chips"])
        obj.mock.assert_not_called()

    def test_cache_iterable_with_sync_exception(self):
        """If the wrapped function throws synchronously, things should continue to work"""

        class Cls:
            @descriptors.cached(iterable=True)
            def fn(self, arg1):
                raise SynapseError(100, "mai spoon iz too big!!1")

        obj = Cls()

        # this should fail immediately
        d = obj.fn(1)
        self.failureResultOf(d, SynapseError)

        # ... leaving the cache empty
        self.assertEqual(len(obj.fn.cache.cache), 0)

        # and a second call should result in a second exception
        d = obj.fn(1)
        self.failureResultOf(d, SynapseError)

    def test_invalidate_cascade(self):
        """Invalidations should cascade up through cache contexts"""

        class Cls:
            @cached(cache_context=True)
            async def func1(self, key, cache_context):
                return await self.func2(key, on_invalidate=cache_context.invalidate)

            @cached(cache_context=True)
            async def func2(self, key, cache_context):
                return await self.func3(key, on_invalidate=cache_context.invalidate)

            @cached(cache_context=True)
            async def func3(self, key, cache_context):
                self.invalidate = cache_context.invalidate
                return 42

        obj = Cls()

        top_invalidate = mock.Mock()
        r = get_awaitable_result(obj.func1("k1", on_invalidate=top_invalidate))
        self.assertEqual(r, 42)
        obj.invalidate()
        top_invalidate.assert_called_once()

    def test_cancel(self):
        """Test that cancelling a lookup does not cancel other lookups"""
        complete_lookup: "Deferred[None]" = Deferred()

        class Cls:
            @cached()
            async def fn(self, arg1):
                await complete_lookup
                return str(arg1)

        obj = Cls()

        d1 = obj.fn(123)
        d2 = obj.fn(123)
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)

        # Cancel `d1`, which is the lookup that caused `fn` to run.
        d1.cancel()

        # `d2` should complete normally.
        complete_lookup.callback(None)
        self.failureResultOf(d1, CancelledError)
        self.assertEqual(d2.result, "123")

    def test_cancel_logcontexts(self):
        """Test that cancellation does not break logcontexts.

        * The `CancelledError` must be raised with the correct logcontext.
        * The inner lookup must not resume with a finished logcontext.
        * The inner lookup must not restore a finished logcontext when done.
        """
        complete_lookup: "Deferred[None]" = Deferred()

        class Cls:
            inner_context_was_finished = False

            @cached()
            async def fn(self, arg1):
                await make_deferred_yieldable(complete_lookup)
                self.inner_context_was_finished = current_context().finished
                return str(arg1)

        obj = Cls()

        async def do_lookup():
            with LoggingContext("c1") as c1:
                try:
                    await obj.fn(123)
                    self.fail("No CancelledError thrown")
                except CancelledError:
                    self.assertEqual(
                        current_context(),
                        c1,
                        "CancelledError was not raised with the correct logcontext",
                    )
                    # suppress the error and succeed

        d = defer.ensureDeferred(do_lookup())
        d.cancel()

        complete_lookup.callback(None)
        self.successResultOf(d)
        self.assertFalse(
            obj.inner_context_was_finished, "Tried to restart a finished logcontext"
        )
        self.assertEqual(current_context(), SENTINEL_CONTEXT)


class CacheDecoratorTestCase(unittest.HomeserverTestCase):
    """More tests for @cached

    The following is a set of tests that got lost in a different file for a while.

    There are probably duplicates of the tests in DescriptorTestCase. Ideally the
    duplicates would be removed and the two sets of classes combined.
    """

    @defer.inlineCallbacks
    def test_passthrough(self):
        class A:
            @cached()
            def func(self, key):
                return key

        a = A()

        self.assertEqual((yield a.func("foo")), "foo")
        self.assertEqual((yield a.func("bar")), "bar")

    @defer.inlineCallbacks
    def test_hit(self):
        callcount = [0]

        class A:
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()
        yield a.func("foo")

        self.assertEqual(callcount[0], 1)

        self.assertEqual((yield a.func("foo")), "foo")
        self.assertEqual(callcount[0], 1)

    @defer.inlineCallbacks
    def test_invalidate(self):
        callcount = [0]

        class A:
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()
        yield a.func("foo")

        self.assertEqual(callcount[0], 1)

        a.func.invalidate(("foo",))

        yield a.func("foo")

        self.assertEqual(callcount[0], 2)

    def test_invalidate_missing(self):
        class A:
            @cached()
            def func(self, key):
                return key

        A().func.invalidate(("what",))

    @defer.inlineCallbacks
    def test_max_entries(self):
        callcount = [0]

        class A:
            @cached(max_entries=10)
            def func(self, key):
                callcount[0] += 1
                return key

        a = A()

        for k in range(0, 12):
            yield a.func(k)

        self.assertEqual(callcount[0], 12)

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

        class A:
            @cached()
            def func(self, key):
                callcount[0] += 1
                return d

        a = A()

        a.func.prefill(("foo",), 456)

        self.assertEqual(a.func("foo").result, 456)
        self.assertEqual(callcount[0], 0)

    @defer.inlineCallbacks
    def test_invalidate_context(self):
        callcount = [0]
        callcount2 = [0]

        class A:
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

        self.assertEqual(callcount[0], 1)
        self.assertEqual(callcount2[0], 1)

        a.func.invalidate(("foo",))
        yield a.func("foo")

        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 1)

        yield a.func2("foo")

        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 2)

    @defer.inlineCallbacks
    def test_eviction_context(self):
        callcount = [0]
        callcount2 = [0]

        class A:
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

        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 2)

        yield a.func2("foo")
        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 2)

        yield a.func("foo3")

        self.assertEqual(callcount[0], 3)
        self.assertEqual(callcount2[0], 2)

        yield a.func2("foo")

        self.assertEqual(callcount[0], 4)
        self.assertEqual(callcount2[0], 3)

    @defer.inlineCallbacks
    def test_double_get(self):
        callcount = [0]
        callcount2 = [0]

        class A:
            @cached()
            def func(self, key):
                callcount[0] += 1
                return key

            @cached(cache_context=True)
            def func2(self, key, cache_context):
                callcount2[0] += 1
                return self.func(key, on_invalidate=cache_context.invalidate)

        a = A()
        a.func2.cache.cache = mock.Mock(wraps=a.func2.cache.cache)

        yield a.func2("foo")

        self.assertEqual(callcount[0], 1)
        self.assertEqual(callcount2[0], 1)

        a.func2.invalidate(("foo",))
        self.assertEqual(a.func2.cache.cache.del_multi.call_count, 1)

        yield a.func2("foo")
        a.func2.invalidate(("foo",))
        self.assertEqual(a.func2.cache.cache.del_multi.call_count, 2)

        self.assertEqual(callcount[0], 1)
        self.assertEqual(callcount2[0], 2)

        a.func.invalidate(("foo",))
        self.assertEqual(a.func2.cache.cache.del_multi.call_count, 3)
        yield a.func("foo")

        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 2)

        yield a.func2("foo")

        self.assertEqual(callcount[0], 2)
        self.assertEqual(callcount2[0], 3)


class CachedListDescriptorTestCase(unittest.TestCase):
    @defer.inlineCallbacks
    def test_cache(self):
        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                pass

            @descriptors.cachedList(cached_method_name="fn", list_name="args1")
            async def list_fn(self, args1, arg2):
                assert current_context().name == "c1"
                # we want this to behave like an asynchronous function
                await run_on_reactor()
                assert current_context().name == "c1"
                return self.mock(args1, arg2)

        with LoggingContext("c1") as c1:
            obj = Cls()
            obj.mock.return_value = {10: "fish", 20: "chips"}

            # start the lookup off
            d1 = obj.list_fn([10, 20], 2)
            self.assertEqual(current_context(), SENTINEL_CONTEXT)
            r = yield d1
            self.assertEqual(current_context(), c1)
            obj.mock.assert_called_once_with({10, 20}, 2)
            self.assertEqual(r, {10: "fish", 20: "chips"})
            obj.mock.reset_mock()

            # a call with different params should call the mock again
            obj.mock.return_value = {30: "peas"}
            r = yield obj.list_fn([20, 30], 2)
            obj.mock.assert_called_once_with({30}, 2)
            self.assertEqual(r, {20: "chips", 30: "peas"})
            obj.mock.reset_mock()

            # all the values should now be cached
            r = yield obj.fn(10, 2)
            self.assertEqual(r, "fish")
            r = yield obj.fn(20, 2)
            self.assertEqual(r, "chips")
            r = yield obj.fn(30, 2)
            self.assertEqual(r, "peas")
            r = yield obj.list_fn([10, 20, 30], 2)
            obj.mock.assert_not_called()
            self.assertEqual(r, {10: "fish", 20: "chips", 30: "peas"})

            # we should also be able to use a (single-use) iterable, and should
            # deduplicate the keys
            obj.mock.reset_mock()
            obj.mock.return_value = {40: "gravy"}
            iterable = (x for x in [10, 40, 40])
            r = yield obj.list_fn(iterable, 2)
            obj.mock.assert_called_once_with({40}, 2)
            self.assertEqual(r, {10: "fish", 40: "gravy"})

    def test_concurrent_lookups(self):
        """All concurrent lookups should get the same result"""

        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1):
                pass

            @descriptors.cachedList(cached_method_name="fn", list_name="args1")
            def list_fn(self, args1) -> "Deferred[dict]":
                return self.mock(args1)

        obj = Cls()
        deferred_result = Deferred()
        obj.mock.return_value = deferred_result

        # start off several concurrent lookups of the same key
        d1 = obj.list_fn([10])
        d2 = obj.list_fn([10])
        d3 = obj.list_fn([10])

        # the mock should have been called exactly once
        obj.mock.assert_called_once_with({10})
        obj.mock.reset_mock()

        # ... and none of the calls should yet be complete
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)
        self.assertFalse(d3.called)

        # complete the lookup. @cachedList functions need to complete with a map
        # of input->result
        deferred_result.callback({10: "peas"})

        # ... which should give the right result to all the callers
        self.assertEqual(self.successResultOf(d1), {10: "peas"})
        self.assertEqual(self.successResultOf(d2), {10: "peas"})
        self.assertEqual(self.successResultOf(d3), {10: "peas"})

    @defer.inlineCallbacks
    def test_invalidate(self):
        """Make sure that invalidation callbacks are called."""

        class Cls:
            def __init__(self):
                self.mock = mock.Mock()

            @descriptors.cached()
            def fn(self, arg1, arg2):
                pass

            @descriptors.cachedList(cached_method_name="fn", list_name="args1")
            async def list_fn(self, args1, arg2):
                # we want this to behave like an asynchronous function
                await run_on_reactor()
                return self.mock(args1, arg2)

        obj = Cls()
        invalidate0 = mock.Mock()
        invalidate1 = mock.Mock()

        # cache miss
        obj.mock.return_value = {10: "fish", 20: "chips"}
        r1 = yield obj.list_fn([10, 20], 2, on_invalidate=invalidate0)
        obj.mock.assert_called_once_with({10, 20}, 2)
        self.assertEqual(r1, {10: "fish", 20: "chips"})
        obj.mock.reset_mock()

        # cache hit
        r2 = yield obj.list_fn([10, 20], 2, on_invalidate=invalidate1)
        obj.mock.assert_not_called()
        self.assertEqual(r2, {10: "fish", 20: "chips"})

        invalidate0.assert_not_called()
        invalidate1.assert_not_called()

        # now if we invalidate the keys, both invalidations should get called
        obj.fn.invalidate((10, 2))
        invalidate0.assert_called_once()
        invalidate1.assert_called_once()

    def test_cancel(self):
        """Test that cancelling a lookup does not cancel other lookups"""
        complete_lookup: "Deferred[None]" = Deferred()

        class Cls:
            @cached()
            def fn(self, arg1):
                pass

            @cachedList(cached_method_name="fn", list_name="args")
            async def list_fn(self, args):
                await complete_lookup
                return {arg: str(arg) for arg in args}

        obj = Cls()

        d1 = obj.list_fn([123, 456])
        d2 = obj.list_fn([123, 456, 789])
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)

        d1.cancel()

        # `d2` should complete normally.
        complete_lookup.callback(None)
        self.failureResultOf(d1, CancelledError)
        self.assertEqual(d2.result, {123: "123", 456: "456", 789: "789"})

    def test_cancel_logcontexts(self):
        """Test that cancellation does not break logcontexts.

        * The `CancelledError` must be raised with the correct logcontext.
        * The inner lookup must not resume with a finished logcontext.
        * The inner lookup must not restore a finished logcontext when done.
        """
        complete_lookup: "Deferred[None]" = Deferred()

        class Cls:
            inner_context_was_finished = False

            @cached()
            def fn(self, arg1):
                pass

            @cachedList(cached_method_name="fn", list_name="args")
            async def list_fn(self, args):
                await make_deferred_yieldable(complete_lookup)
                self.inner_context_was_finished = current_context().finished
                return {arg: str(arg) for arg in args}

        obj = Cls()

        async def do_lookup():
            with LoggingContext("c1") as c1:
                try:
                    await obj.list_fn([123])
                    self.fail("No CancelledError thrown")
                except CancelledError:
                    self.assertEqual(
                        current_context(),
                        c1,
                        "CancelledError was not raised with the correct logcontext",
                    )
                    # suppress the error and succeed

        d = defer.ensureDeferred(do_lookup())
        d.cancel()

        complete_lookup.callback(None)
        self.successResultOf(d)
        self.assertFalse(
            obj.inner_context_was_finished, "Tried to restart a finished logcontext"
        )
        self.assertEqual(current_context(), SENTINEL_CONTEXT)

    def test_num_args_mismatch(self):
        """
        Make sure someone does not accidentally use @cachedList on a method with
        a mismatch in the number args to the underlying single cache method.
        """

        class Cls:
            @descriptors.cached(tree=True)
            def fn(self, room_id, event_id):
                pass

            # This is wrong ❌. `@cachedList` expects to be given the same number
            # of arguments as the underlying cached function, just with one of
            # the arguments being an iterable
            @descriptors.cachedList(cached_method_name="fn", list_name="keys")
            def list_fn(self, keys: Iterable[Tuple[str, str]]):
                pass

            # Corrected syntax ✅
            #
            # @cachedList(cached_method_name="fn", list_name="event_ids")
            # async def list_fn(
            #     self, room_id: str, event_ids: Collection[str],
            # )

        obj = Cls()

        # Make sure this raises an error about the arg mismatch
        with self.assertRaises(TypeError):
            obj.list_fn([("foo", "bar")])
