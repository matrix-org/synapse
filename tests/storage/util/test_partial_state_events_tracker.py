# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from typing import Dict
from unittest import mock

from twisted.internet.defer import CancelledError, ensureDeferred

from synapse.storage.util.partial_state_events_tracker import (
    PartialCurrentStateTracker,
    PartialStateEventsTracker,
)

from tests.test_utils import make_awaitable
from tests.unittest import TestCase


class PartialStateEventsTrackerTestCase(TestCase):
    def setUp(self) -> None:
        # the results to be returned by the mocked get_partial_state_events
        self._events_dict: Dict[str, bool] = {}

        async def get_partial_state_events(events):
            return {e: self._events_dict[e] for e in events}

        self.mock_store = mock.Mock(spec_set=["get_partial_state_events"])
        self.mock_store.get_partial_state_events.side_effect = get_partial_state_events

        self.tracker = PartialStateEventsTracker(self.mock_store)

    def test_does_not_block_for_full_state_events(self):
        self._events_dict = {"event1": False, "event2": False}

        self.successResultOf(
            ensureDeferred(self.tracker.await_full_state(["event1", "event2"]))
        )

        self.mock_store.get_partial_state_events.assert_called_once_with(
            ["event1", "event2"]
        )

    def test_blocks_for_partial_state_events(self):
        self._events_dict = {"event1": True, "event2": False}

        d = ensureDeferred(self.tracker.await_full_state(["event1", "event2"]))

        # there should be no result yet
        self.assertNoResult(d)

        # notifying that the event has been de-partial-stated should unblock
        self.tracker.notify_un_partial_stated("event1")
        self.successResultOf(d)

    def test_un_partial_state_race(self):
        # if the event is un-partial-stated between the initial check and the
        # registration of the listener, it should not block.
        self._events_dict = {"event1": True, "event2": False}

        async def get_partial_state_events(events):
            res = {e: self._events_dict[e] for e in events}
            # change the result for next time
            self._events_dict = {"event1": False, "event2": False}
            return res

        self.mock_store.get_partial_state_events.side_effect = get_partial_state_events

        self.successResultOf(
            ensureDeferred(self.tracker.await_full_state(["event1", "event2"]))
        )

    def test_un_partial_state_during_get_partial_state_events(self):
        # we should correctly handle a call to notify_un_partial_stated during the
        # second call to get_partial_state_events.

        self._events_dict = {"event1": True, "event2": False}

        async def get_partial_state_events1(events):
            self.mock_store.get_partial_state_events.side_effect = (
                get_partial_state_events2
            )
            return {e: self._events_dict[e] for e in events}

        async def get_partial_state_events2(events):
            self.tracker.notify_un_partial_stated("event1")
            self._events_dict["event1"] = False
            return {e: self._events_dict[e] for e in events}

        self.mock_store.get_partial_state_events.side_effect = get_partial_state_events1

        self.successResultOf(
            ensureDeferred(self.tracker.await_full_state(["event1", "event2"]))
        )

    def test_cancellation(self):
        self._events_dict = {"event1": True, "event2": False}

        d1 = ensureDeferred(self.tracker.await_full_state(["event1", "event2"]))
        self.assertNoResult(d1)

        d2 = ensureDeferred(self.tracker.await_full_state(["event1"]))
        self.assertNoResult(d2)

        d1.cancel()
        self.assertFailure(d1, CancelledError)

        # d2 should still be waiting!
        self.assertNoResult(d2)

        self.tracker.notify_un_partial_stated("event1")
        self.successResultOf(d2)


class PartialCurrentStateTrackerTestCase(TestCase):
    def setUp(self) -> None:
        self.mock_store = mock.Mock(spec_set=["is_partial_state_room"])

        self.tracker = PartialCurrentStateTracker(self.mock_store)

    def test_does_not_block_for_full_state_rooms(self):
        self.mock_store.is_partial_state_room.return_value = make_awaitable(False)

        self.successResultOf(ensureDeferred(self.tracker.await_full_state("room_id")))

    def test_blocks_for_partial_room_state(self):
        self.mock_store.is_partial_state_room.return_value = make_awaitable(True)

        d = ensureDeferred(self.tracker.await_full_state("room_id"))

        # there should be no result yet
        self.assertNoResult(d)

        # notifying that the room has been de-partial-stated should unblock
        self.tracker.notify_un_partial_stated("room_id")
        self.successResultOf(d)

    def test_un_partial_state_race(self):
        # We should correctly handle race between awaiting the state and us
        # un-partialling the state
        async def is_partial_state_room(events):
            self.tracker.notify_un_partial_stated("room_id")
            return True

        self.mock_store.is_partial_state_room.side_effect = is_partial_state_room

        self.successResultOf(ensureDeferred(self.tracker.await_full_state("room_id")))

    def test_cancellation(self):
        self.mock_store.is_partial_state_room.return_value = make_awaitable(True)

        d1 = ensureDeferred(self.tracker.await_full_state("room_id"))
        self.assertNoResult(d1)

        d2 = ensureDeferred(self.tracker.await_full_state("room_id"))
        self.assertNoResult(d2)

        d1.cancel()
        self.assertFailure(d1, CancelledError)

        # d2 should still be waiting!
        self.assertNoResult(d2)

        self.tracker.notify_un_partial_stated("room_id")
        self.successResultOf(d2)
