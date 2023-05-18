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

from typing import Hashable, Tuple

from typing_extensions import Protocol

from twisted.internet import defer, reactor
from twisted.internet.base import ReactorBase
from twisted.internet.defer import CancelledError, Deferred

from synapse.logging.context import LoggingContext, current_context
from synapse.util.async_helpers import Linearizer

from tests import unittest


class UnblockFunction(Protocol):
    def __call__(self, pump_reactor: bool = True) -> None:
        ...


class LinearizerTestCase(unittest.TestCase):
    def _start_task(
        self, linearizer: Linearizer, key: Hashable
    ) -> Tuple["Deferred[None]", "Deferred[None]", UnblockFunction]:
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
            async with linearizer.queue(key):
                acquired_d.callback(None)
                await unblock_d

        d = defer.ensureDeferred(task())

        def unblock(pump_reactor: bool = True) -> None:
            unblock_d.callback(None)
            # The next task, if it exists, will acquire the lock and require a kick of
            # the reactor to advance.
            if pump_reactor:
                self._pump()

        return d, acquired_d, unblock

    def _pump(self) -> None:
        """Pump the reactor to advance `Linearizer`s."""
        assert isinstance(reactor, ReactorBase)
        while reactor.getDelayedCalls():
            reactor.runUntilCurrent()

    def test_linearizer(self) -> None:
        """Tests that a task is queued up behind an earlier task."""
        linearizer = Linearizer()

        key = object()

        _, acquired_d1, unblock1 = self._start_task(linearizer, key)
        self.assertTrue(acquired_d1.called)

        _, acquired_d2, unblock2 = self._start_task(linearizer, key)
        self.assertFalse(acquired_d2.called)

        # Once the first task is done, the second task can continue.
        unblock1()
        self.assertTrue(acquired_d2.called)

        unblock2()

    def test_linearizer_is_queued(self) -> None:
        """Tests `Linearizer.is_queued`.

        Runs through the same scenario as `test_linearizer`.
        """
        linearizer = Linearizer()

        key = object()

        _, acquired_d1, unblock1 = self._start_task(linearizer, key)
        self.assertTrue(acquired_d1.called)

        # Since the first task acquires the lock immediately, "is_queued" should return
        # false.
        self.assertFalse(linearizer.is_queued(key))

        _, acquired_d2, unblock2 = self._start_task(linearizer, key)
        self.assertFalse(acquired_d2.called)

        # Now the second task is queued up behind the first.
        self.assertTrue(linearizer.is_queued(key))

        unblock1()

        # And now the second task acquires the lock and nothing is in the queue again.
        self.assertTrue(acquired_d2.called)
        self.assertFalse(linearizer.is_queued(key))

        unblock2()
        self.assertFalse(linearizer.is_queued(key))

    def test_lots_of_queued_things(self) -> None:
        """Tests lots of fast things queued up behind a slow thing.

        The stack should *not* explode when the slow thing completes.
        """
        linearizer = Linearizer()
        key = ""

        async def func(i: int) -> None:
            with LoggingContext("func(%s)" % i) as lc:
                async with linearizer.queue(key):
                    self.assertEqual(current_context(), lc)

                self.assertEqual(current_context(), lc)

        _, _, unblock = self._start_task(linearizer, key)
        for i in range(1, 100):
            defer.ensureDeferred(func(i))

        d = defer.ensureDeferred(func(1000))
        unblock()
        self.successResultOf(d)

    def test_multiple_entries(self) -> None:
        """Tests a `Linearizer` with a concurrency above 1."""
        limiter = Linearizer(max_count=3)

        key = object()

        _, acquired_d1, unblock1 = self._start_task(limiter, key)
        self.assertTrue(acquired_d1.called)

        _, acquired_d2, unblock2 = self._start_task(limiter, key)
        self.assertTrue(acquired_d2.called)

        _, acquired_d3, unblock3 = self._start_task(limiter, key)
        self.assertTrue(acquired_d3.called)

        # These next two tasks have to wait.
        _, acquired_d4, unblock4 = self._start_task(limiter, key)
        self.assertFalse(acquired_d4.called)

        _, acquired_d5, unblock5 = self._start_task(limiter, key)
        self.assertFalse(acquired_d5.called)

        # Once the first task completes, the fourth task can continue.
        unblock1()
        self.assertTrue(acquired_d4.called)
        self.assertFalse(acquired_d5.called)

        # Once the third task completes, the fifth task can continue.
        unblock3()
        self.assertTrue(acquired_d5.called)

        # Make all tasks finish.
        unblock2()
        unblock4()
        unblock5()

        # The next task shouldn't have to wait.
        _, acquired_d6, unblock6 = self._start_task(limiter, key)
        self.assertTrue(acquired_d6)
        unblock6()

    def test_cancellation(self) -> None:
        """Tests cancellation while waiting for a `Linearizer`."""
        linearizer = Linearizer()

        key = object()

        d1, acquired_d1, unblock1 = self._start_task(linearizer, key)
        self.assertTrue(acquired_d1.called)

        # Create a second task, waiting for the first task.
        d2, acquired_d2, _ = self._start_task(linearizer, key)
        self.assertFalse(acquired_d2.called)

        # Create a third task, waiting for the second task.
        d3, acquired_d3, unblock3 = self._start_task(linearizer, key)
        self.assertFalse(acquired_d3.called)

        # Cancel the waiting second task.
        d2.cancel()

        unblock1()
        self.successResultOf(d1)

        self.assertTrue(d2.called)
        self.failureResultOf(d2, CancelledError)

        # The third task should continue running.
        self.assertTrue(
            acquired_d3.called,
            "Third task did not get the lock after the second task was cancelled",
        )
        unblock3()
        self.successResultOf(d3)

    def test_cancellation_during_sleep(self) -> None:
        """Tests cancellation during the sleep just after waiting for a `Linearizer`."""
        linearizer = Linearizer()

        key = object()

        d1, acquired_d1, unblock1 = self._start_task(linearizer, key)
        self.assertTrue(acquired_d1.called)

        # Create a second task, waiting for the first task.
        d2, acquired_d2, _ = self._start_task(linearizer, key)
        self.assertFalse(acquired_d2.called)

        # Create a third task, waiting for the second task.
        d3, acquired_d3, unblock3 = self._start_task(linearizer, key)
        self.assertFalse(acquired_d3.called)

        # Once the first task completes, cancel the waiting second task while it is
        # sleeping just after acquiring the lock.
        unblock1(pump_reactor=False)
        self.successResultOf(d1)
        d2.cancel()
        self._pump()

        self.assertTrue(d2.called)
        self.failureResultOf(d2, CancelledError)

        # The third task should continue running.
        self.assertTrue(
            acquired_d3.called,
            "Third task did not get the lock after the second task was cancelled",
        )
        unblock3()
        self.successResultOf(d3)
