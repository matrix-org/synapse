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

from typing import Callable, Hashable, Tuple

from twisted.internet import defer, reactor
from twisted.internet.base import ReactorBase
from twisted.internet.defer import CancelledError, Deferred

from synapse.logging.context import LoggingContext, current_context
from synapse.util import Clock
from synapse.util.async_helpers import Linearizer

from tests import unittest


class LinearizerTestCase(unittest.TestCase):
    def _start_task(
        self, linearizer: Linearizer, key: Hashable
    ) -> Tuple["Deferred[None]", "Deferred[None]", Callable[[], None]]:
        """Starts a task which acquires the linearizer lock, blocks, then completes.

        Args:
            linearizer: The `Linearizer`.
            key: The `Linearizer` key.

        Returns:
            A tuple containing:
             * A cancellable `Deferred` for the entire task.
             * A `Deferred` that resolves once the task acquires the lock.
             * A function that unblocks the task. Must be called by the caller
               to allow the task to release the lock and complete.
        """
        acquired_d: "Deferred[None]" = Deferred()
        unblock_d: "Deferred[None]" = Deferred()

        async def task() -> None:
            with await linearizer.queue(key):
                acquired_d.callback(None)
                await unblock_d

        d = defer.ensureDeferred(task())

        def unblock() -> None:
            unblock_d.callback(None)
            # The next task, if it exists, will acquire the lock and require a kick of
            # the reactor to advance.
            self._pump()

        return d, acquired_d, unblock

    def _pump(self) -> None:
        """Pump the reactor to advance `Linearizer`s."""
        assert isinstance(reactor, ReactorBase)
        while reactor.getDelayedCalls():
            reactor.runUntilCurrent()

    @defer.inlineCallbacks
    def test_linearizer(self):
        """Tests that a task is queued up behind an earlier task."""
        linearizer = Linearizer()

        key = object()

        d1 = linearizer.queue(key)
        cm1 = yield d1

        d2 = linearizer.queue(key)
        self.assertFalse(d2.called)

        # Once the first task is done, the second task can continue.
        with cm1:
            self.assertFalse(d2.called)

        with (yield d2):
            pass

    @defer.inlineCallbacks
    def test_linearizer_is_queued(self):
        """Tests `Linearizer.is_queued`.

        Runs through the same scenario as `test_linearizer`.
        """
        linearizer = Linearizer()

        key = object()

        d1 = linearizer.queue(key)
        cm1 = yield d1

        # Since the first task acquires the lock immediately, "is_queued" should return
        # false.
        self.assertFalse(linearizer.is_queued(key))

        d2 = linearizer.queue(key)
        self.assertFalse(d2.called)

        # Now the second task is queued up behind the first.
        self.assertTrue(linearizer.is_queued(key))

        with cm1:
            self.assertFalse(d2.called)

            # cm1 still not done, so d2 still queued.
            self.assertTrue(linearizer.is_queued(key))

        # And now the second task acquires the lock and nothing is in the queue again.
        self.assertFalse(linearizer.is_queued(key))

        with (yield d2):
            self.assertFalse(linearizer.is_queued(key))

        self.assertFalse(linearizer.is_queued(key))

    def test_lots_of_queued_things(self):
        """Tests lots of fast things queued up behind a slow thing.

        The stack should *not* explode when the fast thing completes.
        """
        linearizer = Linearizer()

        @defer.inlineCallbacks
        def func(i, sleep=False):
            with LoggingContext("func(%s)" % i) as lc:
                with (yield linearizer.queue("")):
                    self.assertEqual(current_context(), lc)
                    if sleep:
                        yield Clock(reactor).sleep(0)

                self.assertEqual(current_context(), lc)

        func(0, sleep=True)
        for i in range(1, 100):
            func(i)

        return func(1000)

    @defer.inlineCallbacks
    def test_multiple_entries(self):
        """Tests a `Linearizer` with a concurrency above 1."""
        limiter = Linearizer(max_count=3)

        key = object()

        d1 = limiter.queue(key)
        cm1 = yield d1

        d2 = limiter.queue(key)
        cm2 = yield d2

        d3 = limiter.queue(key)
        cm3 = yield d3

        # These next two tasks have to wait.
        d4 = limiter.queue(key)
        self.assertFalse(d4.called)

        d5 = limiter.queue(key)
        self.assertFalse(d5.called)

        # Once the first task completes, the fourth task can continue.
        with cm1:
            self.assertFalse(d4.called)
            self.assertFalse(d5.called)

        cm4 = yield d4
        self.assertFalse(d5.called)

        # Once the third task completes, the fifth task can continue.
        with cm3:
            self.assertFalse(d5.called)

        cm5 = yield d5

        # Make all tasks finish.
        with cm2:
            pass

        with cm4:
            pass

        with cm5:
            pass

        # The next task shouldn't have to wait.
        d6 = limiter.queue(key)
        with (yield d6):
            pass

    @defer.inlineCallbacks
    def test_cancellation(self):
        """Tests cancellation while waiting for a `Linearizer`."""
        linearizer = Linearizer()

        key = object()

        d1 = linearizer.queue(key)
        cm1 = yield d1

        # Create a second task, waiting for the first task.
        d2 = linearizer.queue(key)
        self.assertFalse(d2.called)

        # Create a third task, waiting for the second task.
        d3 = linearizer.queue(key)
        self.assertFalse(d3.called)

        # Cancel the waiting second task.
        d2.cancel()

        with cm1:
            pass

        self.assertTrue(d2.called)
        try:
            yield d2
            self.fail("Expected d2 to raise CancelledError")
        except CancelledError:
            pass

        # The third task should continue running.
        with (yield d3):
            pass
