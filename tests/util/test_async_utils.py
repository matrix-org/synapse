# -*- coding: utf-8 -*-
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
from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred
from twisted.internet.task import Clock

from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    PreserveLoggingContext,
    current_context,
)
from synapse.util.async_helpers import timeout_deferred, Smoother

from tests.unittest import TestCase


class TimeoutDeferredTest(TestCase):
    def setUp(self):
        self.clock = Clock()

    def test_times_out(self):
        """Basic test case that checks that the original deferred is cancelled and that
        the timing-out deferred is errbacked
        """
        cancelled = [False]

        def canceller(_d):
            cancelled[0] = True

        non_completing_d = Deferred(canceller)
        timing_out_d = timeout_deferred(non_completing_d, 1.0, self.clock)

        self.assertNoResult(timing_out_d)
        self.assertFalse(cancelled[0], "deferred was cancelled prematurely")

        self.clock.pump((1.0,))

        self.assertTrue(cancelled[0], "deferred was not cancelled by timeout")
        self.failureResultOf(timing_out_d, defer.TimeoutError)

    def test_times_out_when_canceller_throws(self):
        """Test that we have successfully worked around
        https://twistedmatrix.com/trac/ticket/9534"""

        def canceller(_d):
            raise Exception("can't cancel this deferred")

        non_completing_d = Deferred(canceller)
        timing_out_d = timeout_deferred(non_completing_d, 1.0, self.clock)

        self.assertNoResult(timing_out_d)

        self.clock.pump((1.0,))

        self.failureResultOf(timing_out_d, defer.TimeoutError)

    def test_logcontext_is_preserved_on_cancellation(self):
        blocking_was_cancelled = [False]

        @defer.inlineCallbacks
        def blocking():
            non_completing_d = Deferred()
            with PreserveLoggingContext():
                try:
                    yield non_completing_d
                except CancelledError:
                    blocking_was_cancelled[0] = True
                    raise

        with LoggingContext("one") as context_one:
            # the errbacks should be run in the test logcontext
            def errback(res, deferred_name):
                self.assertIs(
                    current_context(),
                    context_one,
                    "errback %s run in unexpected logcontext %s"
                    % (deferred_name, current_context()),
                )
                return res

            original_deferred = blocking()
            original_deferred.addErrback(errback, "orig")
            timing_out_d = timeout_deferred(original_deferred, 1.0, self.clock)
            self.assertNoResult(timing_out_d)
            self.assertIs(current_context(), SENTINEL_CONTEXT)
            timing_out_d.addErrback(errback, "timingout")

            self.clock.pump((1.0,))

            self.assertTrue(
                blocking_was_cancelled[0], "non-completing deferred was not cancelled"
            )
            self.failureResultOf(timing_out_d, defer.TimeoutError)
            self.assertIs(current_context(), context_one)


class TestSmoother(TestCase):
    def setUp(self):
        self.clock = Clock()

        self.smoother = Smoother(self.clock, 10 * 1000)

    def test_first(self):
        self.clock.advance(100)

        d = self.smoother.smooth()
        self.successResultOf(d)

    def test_multiple_at_same_time(self):
        self.clock.advance(100)

        d1 = defer.ensureDeferred(self.smoother.smooth())
        self.successResultOf(d1)

        d2 = defer.ensureDeferred(self.smoother.smooth())
        self.assertNoResult(d2)
        self.assertAlmostEqual(
            self.smoother._queue[0].scheduled_for_ms,
            self.clock.seconds() * 1000 + self.smoother._target_ms / 2,
        )

        d3 = defer.ensureDeferred(self.smoother.smooth())
        self.assertNoResult(d3)
        self.assertAlmostEqual(
            self.smoother._queue[0].scheduled_for_ms,
            self.clock.seconds() * 1000 + self.smoother._target_ms / 3,
        )
        self.assertAlmostEqual(
            self.smoother._queue[1].scheduled_for_ms,
            self.clock.seconds() * 1000 + 2 * self.smoother._target_ms / 3,
        )

        self.clock.advance(4)
        self.successResultOf(d2)
        self.assertNoResult(d3)

        self.clock.advance(0)
        self.assertNoResult(d3)

        self.clock.advance(4)
        self.successResultOf(d3)

        self.clock.advance(100)

        self.assertNot(self.smoother._queue)
