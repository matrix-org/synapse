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
from synapse.util.async_helpers import (
    ObservableDeferred,
    stop_cancellation,
    timeout_deferred,
)

from tests.unittest import TestCase


class ObservableDeferredTest(TestCase):
    def test_succeed(self):
        origin_d = Deferred()
        observable = ObservableDeferred(origin_d)

        observer1 = observable.observe()
        observer2 = observable.observe()

        self.assertFalse(observer1.called)
        self.assertFalse(observer2.called)

        # check the first observer is called first
        def check_called_first(res):
            self.assertFalse(observer2.called)
            return res

        observer1.addBoth(check_called_first)

        # store the results
        results = [None, None]

        def check_val(res, idx):
            results[idx] = res
            return res

        observer1.addCallback(check_val, 0)
        observer2.addCallback(check_val, 1)

        origin_d.callback(123)
        self.assertEqual(results[0], 123, "observer 1 callback result")
        self.assertEqual(results[1], 123, "observer 2 callback result")

    def test_failure(self):
        origin_d = Deferred()
        observable = ObservableDeferred(origin_d, consumeErrors=True)

        observer1 = observable.observe()
        observer2 = observable.observe()

        self.assertFalse(observer1.called)
        self.assertFalse(observer2.called)

        # check the first observer is called first
        def check_called_first(res):
            self.assertFalse(observer2.called)
            return res

        observer1.addBoth(check_called_first)

        # store the results
        results = [None, None]

        def check_val(res, idx):
            results[idx] = res
            return None

        observer1.addErrback(check_val, 0)
        observer2.addErrback(check_val, 1)

        try:
            raise Exception("gah!")
        except Exception as e:
            origin_d.errback(e)
        self.assertEqual(str(results[0].value), "gah!", "observer 1 errback result")
        self.assertEqual(str(results[1].value), "gah!", "observer 2 errback result")


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


class StopCancellationTests(TestCase):
    """Tests for the `stop_cancellation` function."""

    def test_succeed(self):
        """Test that the new `Deferred` receives the result."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = stop_cancellation(deferred)

        # Success should propagate through.
        deferred.callback("success")
        self.assertTrue(wrapper_deferred.called)
        self.assertEqual("success", self.successResultOf(wrapper_deferred))

    def test_failure(self):
        """Test that the new `Deferred` receives the `Failure`."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = stop_cancellation(deferred)

        # Failure should propagate through.
        deferred.errback(ValueError("abc"))
        self.assertTrue(wrapper_deferred.called)
        self.failureResultOf(wrapper_deferred, ValueError)
        self.assertIsNone(deferred.result, "`Failure` was not consumed")

    def test_cancellation(self):
        """Test that cancellation of the new `Deferred` leaves the original running."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = stop_cancellation(deferred)

        # Cancel the new `Deferred`.
        wrapper_deferred.cancel()
        self.assertTrue(wrapper_deferred.called)
        self.failureResultOf(wrapper_deferred, CancelledError)
        self.assertFalse(
            deferred.called, "Original `Deferred` was unexpectedly cancelled."
        )

        # Now make the inner `Deferred` fail.
        # The `Failure` must be consumed, otherwise unwanted tracebacks will be printed
        # in logs.
        deferred.errback(ValueError("abc"))
        self.assertIsNone(deferred.result, "`Failure` was not consumed")
