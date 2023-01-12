# Copyright 2014-2022 The Matrix.org Foundation C.I.C.
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

from typing import Callable, Generator, cast

import twisted.python.failure
from twisted.internet import defer, reactor as _reactor

from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    PreserveLoggingContext,
    current_context,
    make_deferred_yieldable,
    nested_logging_context,
    run_in_background,
)
from synapse.types import ISynapseReactor
from synapse.util import Clock

from .. import unittest

reactor = cast(ISynapseReactor, _reactor)


class LoggingContextTestCase(unittest.TestCase):
    def _check_test_key(self, value: str) -> None:
        context = current_context()
        assert isinstance(context, LoggingContext)
        self.assertEqual(context.name, value)

    def test_with_context(self) -> None:
        with LoggingContext("test"):
            self._check_test_key("test")

    @defer.inlineCallbacks
    def test_sleep(self) -> Generator["defer.Deferred[object]", object, None]:
        clock = Clock(reactor)

        @defer.inlineCallbacks
        def competing_callback() -> Generator["defer.Deferred[object]", object, None]:
            with LoggingContext("competing"):
                yield clock.sleep(0)
                self._check_test_key("competing")

        reactor.callLater(0, competing_callback)

        with LoggingContext("one"):
            yield clock.sleep(0)
            self._check_test_key("one")

    def _test_run_in_background(self, function: Callable[[], object]) -> defer.Deferred:
        sentinel_context = current_context()

        callback_completed = False

        with LoggingContext("one"):
            # fire off function, but don't wait on it.
            d2 = run_in_background(function)

            def cb(res: object) -> object:
                nonlocal callback_completed
                callback_completed = True
                return res

            d2.addCallback(cb)

            self._check_test_key("one")

        # now wait for the function under test to have run, and check that
        # the logcontext is left in a sane state.
        d2 = defer.Deferred()

        def check_logcontext() -> None:
            if not callback_completed:
                reactor.callLater(0.01, check_logcontext)
                return

            # make sure that the context was reset before it got thrown back
            # into the reactor
            try:
                self.assertIs(current_context(), sentinel_context)
                d2.callback(None)
            except BaseException:
                d2.errback(twisted.python.failure.Failure())

        reactor.callLater(0.01, check_logcontext)

        # test is done once d2 finishes
        return d2

    def test_run_in_background_with_blocking_fn(self) -> defer.Deferred:
        @defer.inlineCallbacks
        def blocking_function() -> Generator["defer.Deferred[object]", object, None]:
            yield Clock(reactor).sleep(0)

        return self._test_run_in_background(blocking_function)

    def test_run_in_background_with_non_blocking_fn(self) -> defer.Deferred:
        @defer.inlineCallbacks
        def nonblocking_function() -> Generator["defer.Deferred[object]", object, None]:
            with PreserveLoggingContext():
                yield defer.succeed(None)

        return self._test_run_in_background(nonblocking_function)

    def test_run_in_background_with_chained_deferred(self) -> defer.Deferred:
        # a function which returns a deferred which looks like it has been
        # called, but is actually paused
        def testfunc() -> defer.Deferred:
            return make_deferred_yieldable(_chained_deferred_function())

        return self._test_run_in_background(testfunc)

    def test_run_in_background_with_coroutine(self) -> defer.Deferred:
        async def testfunc() -> None:
            self._check_test_key("one")
            d = Clock(reactor).sleep(0)
            self.assertIs(current_context(), SENTINEL_CONTEXT)
            await d
            self._check_test_key("one")

        return self._test_run_in_background(testfunc)

    def test_run_in_background_with_nonblocking_coroutine(self) -> defer.Deferred:
        async def testfunc() -> None:
            self._check_test_key("one")

        return self._test_run_in_background(testfunc)

    @defer.inlineCallbacks
    def test_make_deferred_yieldable(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        # a function which returns an incomplete deferred, but doesn't follow
        # the synapse rules.
        def blocking_function() -> defer.Deferred:
            d: defer.Deferred = defer.Deferred()
            reactor.callLater(0, d.callback, None)
            return d

        sentinel_context = current_context()

        with LoggingContext("one"):
            d1 = make_deferred_yieldable(blocking_function())
            # make sure that the context was reset by make_deferred_yieldable
            self.assertIs(current_context(), sentinel_context)

            yield d1

            # now it should be restored
            self._check_test_key("one")

    @defer.inlineCallbacks
    def test_make_deferred_yieldable_with_chained_deferreds(
        self,
    ) -> Generator["defer.Deferred[object]", object, None]:
        sentinel_context = current_context()

        with LoggingContext("one"):
            d1 = make_deferred_yieldable(_chained_deferred_function())
            # make sure that the context was reset by make_deferred_yieldable
            self.assertIs(current_context(), sentinel_context)

            yield d1

            # now it should be restored
            self._check_test_key("one")

    def test_nested_logging_context(self) -> None:
        with LoggingContext("foo"):
            nested_context = nested_logging_context(suffix="bar")
            self.assertEqual(nested_context.name, "foo-bar")


# a function which returns a deferred which has been "called", but
# which had a function which returned another incomplete deferred on
# its callback list, so won't yet call any other new callbacks.
def _chained_deferred_function() -> defer.Deferred:
    d = defer.succeed(None)

    def cb(res: object) -> defer.Deferred:
        d2: defer.Deferred = defer.Deferred()
        reactor.callLater(0, d2.callback, res)
        return d2

    d.addCallback(cb)
    return d
