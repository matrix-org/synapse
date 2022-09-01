# Copyright 2016-2021 The Matrix.org Foundation C.I.C.
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

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.databases.main.event_push_actions import NotifCounts
from synapse.util import Clock

from tests.unittest import HomeserverTestCase

USER_ID = "@user:example.com"


class EventPushActionsStoreTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        persist_events_store = hs.get_datastores().persist_events
        assert persist_events_store is not None
        self.persist_events_store = persist_events_store

    def test_get_unread_push_actions_for_user_in_range_for_http(self) -> None:
        self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_http(
                USER_ID, 0, 1000, 20
            )
        )

    def test_get_unread_push_actions_for_user_in_range_for_email(self) -> None:
        self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_email(
                USER_ID, 0, 1000, 20
            )
        )

    def test_count_aggregation(self) -> None:
        # Create a user to receive notifications and send receipts.
        user_id = self.register_user("user1235", "pass")
        token = self.login("user1235", "pass")

        # And another users to send events.
        other_id = self.register_user("other", "pass")
        other_token = self.login("other", "pass")

        # Create a room and put both users in it.
        room_id = self.helper.create_room_as(user_id, tok=token)
        self.helper.join(room_id, other_id, tok=other_token)

        last_event_id: str

        def _assert_counts(
            noitf_count: int, unread_count: int, highlight_count: int
        ) -> None:
            counts = self.get_success(
                self.store.db_pool.runInteraction(
                    "get-unread-counts",
                    self.store._get_unread_counts_by_receipt_txn,
                    room_id,
                    user_id,
                )
            )
            self.assertEqual(
                counts,
                NotifCounts(
                    notify_count=noitf_count,
                    unread_count=unread_count,
                    highlight_count=highlight_count,
                ),
            )

        def _create_event(highlight: bool = False) -> str:
            result = self.helper.send_event(
                room_id,
                type="m.room.message",
                content={"msgtype": "m.text", "body": user_id if highlight else "msg"},
                tok=other_token,
            )
            nonlocal last_event_id
            last_event_id = result["event_id"]
            return last_event_id

        def _rotate() -> None:
            self.get_success(self.store._rotate_notifs())

        def _mark_read(event_id: str) -> None:
            self.get_success(
                self.store.insert_receipt(
                    room_id,
                    "m.read",
                    user_id=user_id,
                    event_ids=[event_id],
                    data={},
                )
            )

        _assert_counts(0, 0, 0)
        _create_event()
        _assert_counts(1, 1, 0)
        _rotate()
        _assert_counts(1, 1, 0)

        event_id = _create_event()
        _assert_counts(2, 2, 0)
        _rotate()
        _assert_counts(2, 2, 0)

        _create_event()
        _mark_read(event_id)
        _assert_counts(1, 1, 0)

        _mark_read(last_event_id)
        _assert_counts(0, 0, 0)

        _create_event()
        _rotate()
        _assert_counts(1, 1, 0)

        # Delete old event push actions, this should not affect the (summarised) count.
        #
        # All event push actions are kept for 24 hours, so need to move forward
        # in time.
        self.pump(60 * 60 * 24)
        self.get_success(self.store._remove_old_push_actions_that_have_rotated())
        # Double check that the event push actions have been cleared (i.e. that
        # any results *must* come from the summary).
        result = self.get_success(
            self.store.db_pool.simple_select_list(
                table="event_push_actions",
                keyvalues={"1": 1},
                retcols=("event_id",),
                desc="",
            )
        )
        self.assertEqual(result, [])
        _assert_counts(1, 1, 0)

        _mark_read(last_event_id)
        _assert_counts(0, 0, 0)

        event_id = _create_event(True)
        _assert_counts(1, 1, 1)
        _rotate()
        _assert_counts(1, 1, 1)

        # Check that adding another notification and rotating after highlight
        # works.
        _create_event()
        _rotate()
        _assert_counts(2, 2, 1)

        # Check that sending read receipts at different points results in the
        # right counts.
        _mark_read(event_id)
        _assert_counts(1, 1, 0)
        _mark_read(last_event_id)
        _assert_counts(0, 0, 0)

        _create_event(True)
        _assert_counts(1, 1, 1)
        _mark_read(last_event_id)
        _assert_counts(0, 0, 0)
        _rotate()
        _assert_counts(0, 0, 0)

    def test_find_first_stream_ordering_after_ts(self) -> None:
        def add_event(so: int, ts: int) -> None:
            self.get_success(
                self.store.db_pool.simple_insert(
                    "events",
                    {
                        "stream_ordering": so,
                        "received_ts": ts,
                        "event_id": "event%i" % so,
                        "type": "",
                        "room_id": "",
                        "content": "",
                        "processed": True,
                        "outlier": False,
                        "topological_ordering": 0,
                        "depth": 0,
                    },
                )
            )

        # start with the base case where there are no events in the table
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(11))
        self.assertEqual(r, 0)

        # now with one event
        add_event(2, 10)
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(9))
        self.assertEqual(r, 2)
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(10))
        self.assertEqual(r, 2)
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(11))
        self.assertEqual(r, 3)

        # add a bunch of dummy events to the events table
        for (stream_ordering, ts) in (
            (3, 110),
            (4, 120),
            (5, 120),
            (10, 130),
            (20, 140),
        ):
            add_event(stream_ordering, ts)

        r = self.get_success(self.store.find_first_stream_ordering_after_ts(110))
        self.assertEqual(r, 3, "First event after 110ms should be 3, was %i" % r)

        # 4 and 5 are both after 120: we want 4 rather than 5
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(120))
        self.assertEqual(r, 4, "First event after 120ms should be 4, was %i" % r)

        r = self.get_success(self.store.find_first_stream_ordering_after_ts(129))
        self.assertEqual(r, 10, "First event after 129ms should be 10, was %i" % r)

        # check we can get the last event
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(140))
        self.assertEqual(r, 20, "First event after 14ms should be 20, was %i" % r)

        # off the end
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(160))
        self.assertEqual(r, 21)

        # check we can find an event at ordering zero
        add_event(0, 5)
        r = self.get_success(self.store.find_first_stream_ordering_after_ts(1))
        self.assertEqual(r, 0)
