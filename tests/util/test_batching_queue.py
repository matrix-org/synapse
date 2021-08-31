# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.logging.context import make_deferred_yieldable
from synapse.util.batching_queue import BatchingQueue

from tests.server import get_clock
from tests.unittest import TestCase


class BatchingQueueTestCase(TestCase):
    def setUp(self):
        self.clock, hs_clock = get_clock()

        self._pending_calls = []
        self.queue = BatchingQueue("test_queue", hs_clock, self._process_queue)

    async def _process_queue(self, values):
        d = defer.Deferred()
        self._pending_calls.append((values, d))
        return await make_deferred_yieldable(d)

    def test_simple(self):
        """Tests the basic case of calling `add_to_queue` once and having
        `_process_queue` return.
        """

        self.assertFalse(self._pending_calls)

        queue_d = defer.ensureDeferred(self.queue.add_to_queue("foo"))

        # The queue should wait a reactor tick before calling the processing
        # function.
        self.assertFalse(self._pending_calls)
        self.assertFalse(queue_d.called)

        # We should see a call to `_process_queue` after a reactor tick.
        self.clock.pump([0])

        self.assertEqual(len(self._pending_calls), 1)
        self.assertEqual(self._pending_calls[0][0], ["foo"])
        self.assertFalse(queue_d.called)

        # Return value of the `_process_queue` should be propagated back.
        self._pending_calls.pop()[1].callback("bar")

        self.assertEqual(self.successResultOf(queue_d), "bar")

    def test_batching(self):
        """Test that multiple calls at the same time get batched up into one
        call to `_process_queue`.
        """

        self.assertFalse(self._pending_calls)

        queue_d1 = defer.ensureDeferred(self.queue.add_to_queue("foo1"))
        queue_d2 = defer.ensureDeferred(self.queue.add_to_queue("foo2"))

        self.clock.pump([0])

        # We should see only *one* call to `_process_queue`
        self.assertEqual(len(self._pending_calls), 1)
        self.assertEqual(self._pending_calls[0][0], ["foo1", "foo2"])
        self.assertFalse(queue_d1.called)
        self.assertFalse(queue_d2.called)

        # Return value of the `_process_queue` should be propagated back to both.
        self._pending_calls.pop()[1].callback("bar")

        self.assertEqual(self.successResultOf(queue_d1), "bar")
        self.assertEqual(self.successResultOf(queue_d2), "bar")

    def test_queuing(self):
        """Test that we queue up requests while a `_process_queue` is being
        called.
        """

        self.assertFalse(self._pending_calls)

        queue_d1 = defer.ensureDeferred(self.queue.add_to_queue("foo1"))
        self.clock.pump([0])

        queue_d2 = defer.ensureDeferred(self.queue.add_to_queue("foo2"))

        # We should see only *one* call to `_process_queue`
        self.assertEqual(len(self._pending_calls), 1)
        self.assertEqual(self._pending_calls[0][0], ["foo1"])
        self.assertFalse(queue_d1.called)
        self.assertFalse(queue_d2.called)

        # Return value of the `_process_queue` should be propagated back to the
        # first.
        self._pending_calls.pop()[1].callback("bar1")

        self.assertEqual(self.successResultOf(queue_d1), "bar1")
        self.assertFalse(queue_d2.called)

        # We should now see a second call to `_process_queue`
        self.clock.pump([0])
        self.assertEqual(len(self._pending_calls), 1)
        self.assertEqual(self._pending_calls[0][0], ["foo2"])
        self.assertFalse(queue_d2.called)

        # Return value of the `_process_queue` should be propagated back to the
        # second.
        self._pending_calls.pop()[1].callback("bar2")

        self.assertEqual(self.successResultOf(queue_d2), "bar2")

    def test_different_keys(self):
        """Test that calls to different keys get processed in parallel."""

        self.assertFalse(self._pending_calls)

        queue_d1 = defer.ensureDeferred(self.queue.add_to_queue("foo1", key=1))
        self.clock.pump([0])
        queue_d2 = defer.ensureDeferred(self.queue.add_to_queue("foo2", key=2))
        self.clock.pump([0])

        # We queue up another item with key=2 to check that we will keep taking
        # things off the queue.
        queue_d3 = defer.ensureDeferred(self.queue.add_to_queue("foo3", key=2))

        # We should see two calls to `_process_queue`
        self.assertEqual(len(self._pending_calls), 2)
        self.assertEqual(self._pending_calls[0][0], ["foo1"])
        self.assertEqual(self._pending_calls[1][0], ["foo2"])
        self.assertFalse(queue_d1.called)
        self.assertFalse(queue_d2.called)
        self.assertFalse(queue_d3.called)

        # Return value of the `_process_queue` should be propagated back to the
        # first.
        self._pending_calls.pop(0)[1].callback("bar1")

        self.assertEqual(self.successResultOf(queue_d1), "bar1")
        self.assertFalse(queue_d2.called)
        self.assertFalse(queue_d3.called)

        # Return value of the `_process_queue` should be propagated back to the
        # second.
        self._pending_calls.pop()[1].callback("bar2")

        self.assertEqual(self.successResultOf(queue_d2), "bar2")
        self.assertFalse(queue_d3.called)

        # We should now see a call `_pending_calls` for `foo3`
        self.clock.pump([0])
        self.assertEqual(len(self._pending_calls), 1)
        self.assertEqual(self._pending_calls[0][0], ["foo3"])
        self.assertFalse(queue_d3.called)

        # Return value of the `_process_queue` should be propagated back to the
        # third deferred.
        self._pending_calls.pop()[1].callback("bar4")

        self.assertEqual(self.successResultOf(queue_d3), "bar4")
