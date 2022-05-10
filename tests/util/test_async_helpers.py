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
import traceback

from parameterized import parameterized_class

from twisted.internet import defer
from twisted.internet.defer import CancelledError, Deferred, ensureDeferred
from twisted.internet.task import Clock
from twisted.python.failure import Failure

from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    PreserveLoggingContext,
    current_context,
    make_deferred_yieldable,
)
from synapse.util.async_helpers import (
    AwakenableSleeper,
    ObservableDeferred,
    concurrently_execute,
    delay_cancellation,
    stop_cancellation,
    timeout_deferred,
)

from tests.server import get_clock
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

    def test_cancellation(self):
        """Test that cancelling an observer does not affect other observers."""
        origin_d: "Deferred[int]" = Deferred()
        observable = ObservableDeferred(origin_d, consumeErrors=True)

        observer1 = observable.observe()
        observer2 = observable.observe()
        observer3 = observable.observe()

        self.assertFalse(observer1.called)
        self.assertFalse(observer2.called)
        self.assertFalse(observer3.called)

        # cancel the second observer
        observer2.cancel()
        self.assertFalse(observer1.called)
        self.failureResultOf(observer2, CancelledError)
        self.assertFalse(observer3.called)

        # other observers resolve as normal
        origin_d.callback(123)
        self.assertEqual(observer1.result, 123, "observer 1 callback result")
        self.assertEqual(observer3.result, 123, "observer 3 callback result")

        # additional observers resolve as normal
        observer4 = observable.observe()
        self.assertEqual(observer4.result, 123, "observer 4 callback result")


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


class _TestException(Exception):
    pass


class ConcurrentlyExecuteTest(TestCase):
    def test_limits_runners(self):
        """If we have more tasks than runners, we should get the limit of runners"""
        started = 0
        waiters = []
        processed = []

        async def callback(v):
            # when we first enter, bump the start count
            nonlocal started
            started += 1

            # record the fact we got an item
            processed.append(v)

            # wait for the goahead before returning
            d2 = Deferred()
            waiters.append(d2)
            await d2

        # set it going
        d2 = ensureDeferred(concurrently_execute(callback, [1, 2, 3, 4, 5], 3))

        # check we got exactly 3 processes
        self.assertEqual(started, 3)
        self.assertEqual(len(waiters), 3)

        # let one finish
        waiters.pop().callback(0)

        # ... which should start another
        self.assertEqual(started, 4)
        self.assertEqual(len(waiters), 3)

        # we still shouldn't be done
        self.assertNoResult(d2)

        # finish the job
        while waiters:
            waiters.pop().callback(0)

        # check everything got done
        self.assertEqual(started, 5)
        self.assertCountEqual(processed, [1, 2, 3, 4, 5])
        self.successResultOf(d2)

    def test_preserves_stacktraces(self):
        """Test that the stacktrace from an exception thrown in the callback is preserved"""
        d1 = Deferred()

        async def callback(v):
            # alas, this doesn't work at all without an await here
            await d1
            raise _TestException("bah")

        async def caller():
            try:
                await concurrently_execute(callback, [1], 2)
            except _TestException as e:
                tb = traceback.extract_tb(e.__traceback__)
                # we expect to see "caller", "concurrently_execute" and "callback".
                self.assertEqual(tb[0].name, "caller")
                self.assertEqual(tb[1].name, "concurrently_execute")
                self.assertEqual(tb[-1].name, "callback")
            else:
                self.fail("No exception thrown")

        d2 = ensureDeferred(caller())
        d1.callback(0)
        self.successResultOf(d2)

    def test_preserves_stacktraces_on_preformed_failure(self):
        """Test that the stacktrace on a Failure returned by the callback is preserved"""
        d1 = Deferred()
        f = Failure(_TestException("bah"))

        async def callback(v):
            # alas, this doesn't work at all without an await here
            await d1
            await defer.fail(f)

        async def caller():
            try:
                await concurrently_execute(callback, [1], 2)
            except _TestException as e:
                tb = traceback.extract_tb(e.__traceback__)
                # we expect to see "caller", "concurrently_execute", "callback",
                # and some magic from inside ensureDeferred that happens when .fail
                # is called.
                self.assertEqual(tb[0].name, "caller")
                self.assertEqual(tb[1].name, "concurrently_execute")
                self.assertEqual(tb[-2].name, "callback")
            else:
                self.fail("No exception thrown")

        d2 = ensureDeferred(caller())
        d1.callback(0)
        self.successResultOf(d2)


@parameterized_class(
    ("wrapper",),
    [("stop_cancellation",), ("delay_cancellation",)],
)
class CancellationWrapperTests(TestCase):
    """Common tests for the `stop_cancellation` and `delay_cancellation` functions."""

    wrapper: str

    def wrap_deferred(self, deferred: "Deferred[str]") -> "Deferred[str]":
        if self.wrapper == "stop_cancellation":
            return stop_cancellation(deferred)
        elif self.wrapper == "delay_cancellation":
            return delay_cancellation(deferred)
        else:
            raise ValueError(f"Unsupported wrapper type: {self.wrapper}")

    def test_succeed(self):
        """Test that the new `Deferred` receives the result."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = self.wrap_deferred(deferred)

        # Success should propagate through.
        deferred.callback("success")
        self.assertTrue(wrapper_deferred.called)
        self.assertEqual("success", self.successResultOf(wrapper_deferred))

    def test_failure(self):
        """Test that the new `Deferred` receives the `Failure`."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = self.wrap_deferred(deferred)

        # Failure should propagate through.
        deferred.errback(ValueError("abc"))
        self.assertTrue(wrapper_deferred.called)
        self.failureResultOf(wrapper_deferred, ValueError)
        self.assertIsNone(deferred.result, "`Failure` was not consumed")


class StopCancellationTests(TestCase):
    """Tests for the `stop_cancellation` function."""

    def test_cancellation(self):
        """Test that cancellation of the new `Deferred` leaves the original running."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = stop_cancellation(deferred)

        # Cancel the new `Deferred`.
        wrapper_deferred.cancel()
        self.assertTrue(wrapper_deferred.called)
        self.failureResultOf(wrapper_deferred, CancelledError)
        self.assertFalse(
            deferred.called, "Original `Deferred` was unexpectedly cancelled"
        )

        # Now make the original `Deferred` fail.
        # The `Failure` must be consumed, otherwise unwanted tracebacks will be printed
        # in logs.
        deferred.errback(ValueError("abc"))
        self.assertIsNone(deferred.result, "`Failure` was not consumed")


class DelayCancellationTests(TestCase):
    """Tests for the `delay_cancellation` function."""

    def test_deferred_cancellation(self):
        """Test that cancellation of the new `Deferred` waits for the original."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = delay_cancellation(deferred)

        # Cancel the new `Deferred`.
        wrapper_deferred.cancel()
        self.assertNoResult(wrapper_deferred)
        self.assertFalse(
            deferred.called, "Original `Deferred` was unexpectedly cancelled"
        )

        # Now make the original `Deferred` fail.
        # The `Failure` must be consumed, otherwise unwanted tracebacks will be printed
        # in logs.
        deferred.errback(ValueError("abc"))
        self.assertIsNone(deferred.result, "`Failure` was not consumed")

        # Now that the original `Deferred` has failed, we should get a `CancelledError`.
        self.failureResultOf(wrapper_deferred, CancelledError)

    def test_coroutine_cancellation(self):
        """Test that cancellation of the new `Deferred` waits for the original."""
        blocking_deferred: "Deferred[None]" = Deferred()
        completion_deferred: "Deferred[None]" = Deferred()

        async def task():
            await blocking_deferred
            completion_deferred.callback(None)
            # Raise an exception. Twisted should consume it, otherwise unwanted
            # tracebacks will be printed in logs.
            raise ValueError("abc")

        wrapper_deferred = delay_cancellation(task())

        # Cancel the new `Deferred`.
        wrapper_deferred.cancel()
        self.assertNoResult(wrapper_deferred)
        self.assertFalse(
            blocking_deferred.called, "Cancellation was propagated too deep"
        )
        self.assertFalse(completion_deferred.called)

        # Unblock the task.
        blocking_deferred.callback(None)
        self.assertTrue(completion_deferred.called)

        # Now that the original coroutine has failed, we should get a `CancelledError`.
        self.failureResultOf(wrapper_deferred, CancelledError)

    def test_suppresses_second_cancellation(self):
        """Test that a second cancellation is suppressed.

        Identical to `test_cancellation` except the new `Deferred` is cancelled twice.
        """
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = delay_cancellation(deferred)

        # Cancel the new `Deferred`, twice.
        wrapper_deferred.cancel()
        wrapper_deferred.cancel()
        self.assertNoResult(wrapper_deferred)
        self.assertFalse(
            deferred.called, "Original `Deferred` was unexpectedly cancelled"
        )

        # Now make the original `Deferred` fail.
        # The `Failure` must be consumed, otherwise unwanted tracebacks will be printed
        # in logs.
        deferred.errback(ValueError("abc"))
        self.assertIsNone(deferred.result, "`Failure` was not consumed")

        # Now that the original `Deferred` has failed, we should get a `CancelledError`.
        self.failureResultOf(wrapper_deferred, CancelledError)

    def test_propagates_cancelled_error(self):
        """Test that a `CancelledError` from the original `Deferred` gets propagated."""
        deferred: "Deferred[str]" = Deferred()
        wrapper_deferred = delay_cancellation(deferred)

        # Fail the original `Deferred` with a `CancelledError`.
        cancelled_error = CancelledError()
        deferred.errback(cancelled_error)

        # The new `Deferred` should fail with exactly the same `CancelledError`.
        self.assertTrue(wrapper_deferred.called)
        self.assertIs(cancelled_error, self.failureResultOf(wrapper_deferred).value)

    def test_preserves_logcontext(self):
        """Test that logging contexts are preserved."""
        blocking_d: "Deferred[None]" = Deferred()

        async def inner():
            await make_deferred_yieldable(blocking_d)

        async def outer():
            with LoggingContext("c") as c:
                try:
                    await delay_cancellation(inner())
                    self.fail("`CancelledError` was not raised")
                except CancelledError:
                    self.assertEqual(c, current_context())
                    # Succeed with no error, unless the logging context is wrong.

        # Run and block inside `inner()`.
        d = defer.ensureDeferred(outer())
        self.assertEqual(SENTINEL_CONTEXT, current_context())

        d.cancel()

        # Now unblock. `outer()` will consume the `CancelledError` and check the
        # logging context.
        blocking_d.callback(None)
        self.successResultOf(d)


class AwakenableSleeperTests(TestCase):
    "Tests AwakenableSleeper"

    def test_sleep(self):
        reactor, _ = get_clock()
        sleeper = AwakenableSleeper(reactor)

        d = defer.ensureDeferred(sleeper.sleep("name", 1000))

        reactor.pump([0.0])
        self.assertFalse(d.called)

        reactor.advance(0.5)
        self.assertFalse(d.called)

        reactor.advance(0.6)
        self.assertTrue(d.called)

    def test_explicit_wake(self):
        reactor, _ = get_clock()
        sleeper = AwakenableSleeper(reactor)

        d = defer.ensureDeferred(sleeper.sleep("name", 1000))

        reactor.pump([0.0])
        self.assertFalse(d.called)

        reactor.advance(0.5)
        self.assertFalse(d.called)

        sleeper.wake("name")
        self.assertTrue(d.called)

        reactor.advance(0.6)

    def test_multiple_sleepers_timeout(self):
        reactor, _ = get_clock()
        sleeper = AwakenableSleeper(reactor)

        d1 = defer.ensureDeferred(sleeper.sleep("name", 1000))

        reactor.advance(0.6)
        self.assertFalse(d1.called)

        # Add another sleeper
        d2 = defer.ensureDeferred(sleeper.sleep("name", 1000))

        # Only the first sleep should time out now.
        reactor.advance(0.6)
        self.assertTrue(d1.called)
        self.assertFalse(d2.called)

        reactor.advance(0.6)
        self.assertTrue(d2.called)

    def test_multiple_sleepers_wake(self):
        reactor, _ = get_clock()
        sleeper = AwakenableSleeper(reactor)

        d1 = defer.ensureDeferred(sleeper.sleep("name", 1000))

        reactor.advance(0.5)
        self.assertFalse(d1.called)

        # Add another sleeper
        d2 = defer.ensureDeferred(sleeper.sleep("name", 1000))

        # Neither should fire yet
        reactor.advance(0.3)
        self.assertFalse(d1.called)
        self.assertFalse(d2.called)

        # Explicitly waking both up works
        sleeper.wake("name")
        self.assertTrue(d1.called)
        self.assertTrue(d2.called)
