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

from typing import Optional, Tuple

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import MAIN_TIMELINE, RelationTypes
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.databases.main.event_push_actions import NotifCounts
from synapse.types import JsonDict
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


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

    def _create_users_and_room(self) -> Tuple[str, str, str, str, str]:
        """
        Creates two users and a shared room.

        Returns:
            Tuple of (user 1 ID, user 1 token, user 2 ID, user 2 token, room ID).
        """
        # Create a user to receive notifications and send receipts.
        user_id = self.register_user("user1235", "pass")
        token = self.login("user1235", "pass")

        # And another users to send events.
        other_id = self.register_user("other", "pass")
        other_token = self.login("other", "pass")

        # Create a room and put both users in it.
        room_id = self.helper.create_room_as(user_id, tok=token)
        self.helper.join(room_id, other_id, tok=other_token)

        return user_id, token, other_id, other_token, room_id

    def test_get_unread_push_actions_for_user_in_range(self) -> None:
        """Test getting unread push actions for HTTP and email pushers."""
        user_id, token, _, other_token, room_id = self._create_users_and_room()

        # Create two events, one of which is a highlight.
        first_event_id = self.helper.send_event(
            room_id,
            type="m.room.message",
            content={"msgtype": "m.text", "body": "msg"},
            tok=other_token,
        )["event_id"]
        second_event_id = self.helper.send_event(
            room_id,
            type="m.room.message",
            content={
                "msgtype": "m.text",
                "body": user_id,
                "m.relates_to": {
                    "rel_type": RelationTypes.THREAD,
                    "event_id": first_event_id,
                },
            },
            tok=other_token,
        )["event_id"]

        # Fetch unread actions for HTTP pushers.
        http_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_http(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual(2, len(http_actions))

        # Fetch unread actions for email pushers.
        email_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_email(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual(2, len(email_actions))

        # Send a receipt, which should clear the first action.
        self.get_success(
            self.store.insert_receipt(
                room_id,
                "m.read",
                user_id=user_id,
                event_ids=[first_event_id],
                thread_id=None,
                data={},
            )
        )
        http_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_http(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual(1, len(http_actions))
        email_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_email(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual(1, len(email_actions))

        # Send a thread receipt to clear the thread action.
        self.get_success(
            self.store.insert_receipt(
                room_id,
                "m.read",
                user_id=user_id,
                event_ids=[second_event_id],
                thread_id=first_event_id,
                data={},
            )
        )
        http_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_http(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual([], http_actions)
        email_actions = self.get_success(
            self.store.get_unread_push_actions_for_user_in_range_for_email(
                user_id, 0, 1000, 20
            )
        )
        self.assertEqual([], email_actions)

    def test_count_aggregation(self) -> None:
        # Create a user to receive notifications and send receipts.
        user_id, token, _, other_token, room_id = self._create_users_and_room()

        last_event_id: str

        def _assert_counts(noitf_count: int, highlight_count: int) -> None:
            counts = self.get_success(
                self.store.db_pool.runInteraction(
                    "get-unread-counts",
                    self.store._get_unread_counts_by_receipt_txn,
                    room_id,
                    user_id,
                )
            )
            self.assertEqual(
                counts.main_timeline,
                NotifCounts(
                    notify_count=noitf_count,
                    unread_count=0,
                    highlight_count=highlight_count,
                ),
            )
            self.assertEqual(counts.threads, {})

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
                    thread_id=None,
                    data={},
                )
            )

        _assert_counts(0, 0)
        _create_event()
        _assert_counts(1, 0)
        _rotate()
        _assert_counts(1, 0)

        event_id = _create_event()
        _assert_counts(2, 0)
        _rotate()
        _assert_counts(2, 0)

        _create_event()
        _mark_read(event_id)
        _assert_counts(1, 0)

        _mark_read(last_event_id)
        _assert_counts(0, 0)

        _create_event()
        _assert_counts(1, 0)
        _rotate()
        _assert_counts(1, 0)

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
        _assert_counts(1, 0)

        _mark_read(last_event_id)
        _assert_counts(0, 0)

        event_id = _create_event(True)
        _assert_counts(1, 1)
        _rotate()
        _assert_counts(1, 1)

        # Check that adding another notification and rotating after highlight
        # works.
        _create_event()
        _rotate()
        _assert_counts(2, 1)

        # Check that sending read receipts at different points results in the
        # right counts.
        _mark_read(event_id)
        _assert_counts(1, 0)
        _mark_read(last_event_id)
        _assert_counts(0, 0)

        _create_event(True)
        _assert_counts(1, 1)
        _mark_read(last_event_id)
        _assert_counts(0, 0)
        _rotate()
        _assert_counts(0, 0)

    def test_count_aggregation_threads(self) -> None:
        """
        This is essentially the same test as test_count_aggregation, but adds
        events to the main timeline and to a thread.
        """

        user_id, token, _, other_token, room_id = self._create_users_and_room()
        thread_id: str

        last_event_id: str

        def _assert_counts(
            noitf_count: int,
            highlight_count: int,
            thread_notif_count: int,
            thread_highlight_count: int,
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
                counts.main_timeline,
                NotifCounts(
                    notify_count=noitf_count,
                    unread_count=0,
                    highlight_count=highlight_count,
                ),
            )
            if thread_notif_count or thread_highlight_count:
                self.assertEqual(
                    counts.threads,
                    {
                        thread_id: NotifCounts(
                            notify_count=thread_notif_count,
                            unread_count=0,
                            highlight_count=thread_highlight_count,
                        ),
                    },
                )
            else:
                self.assertEqual(counts.threads, {})

        def _create_event(
            highlight: bool = False, thread_id: Optional[str] = None
        ) -> str:
            content: JsonDict = {
                "msgtype": "m.text",
                "body": user_id if highlight else "msg",
            }
            if thread_id:
                content["m.relates_to"] = {
                    "rel_type": "m.thread",
                    "event_id": thread_id,
                }

            result = self.helper.send_event(
                room_id,
                type="m.room.message",
                content=content,
                tok=other_token,
            )
            nonlocal last_event_id
            last_event_id = result["event_id"]
            return last_event_id

        def _rotate() -> None:
            self.get_success(self.store._rotate_notifs())

        def _mark_read(event_id: str, thread_id: str = MAIN_TIMELINE) -> None:
            self.get_success(
                self.store.insert_receipt(
                    room_id,
                    "m.read",
                    user_id=user_id,
                    event_ids=[event_id],
                    thread_id=thread_id,
                    data={},
                )
            )

        _assert_counts(0, 0, 0, 0)
        thread_id = _create_event()
        _assert_counts(1, 0, 0, 0)
        _rotate()
        _assert_counts(1, 0, 0, 0)

        _create_event(thread_id=thread_id)
        _assert_counts(1, 0, 1, 0)
        _rotate()
        _assert_counts(1, 0, 1, 0)

        _create_event()
        _assert_counts(2, 0, 1, 0)
        _rotate()
        _assert_counts(2, 0, 1, 0)

        event_id = _create_event(thread_id=thread_id)
        _assert_counts(2, 0, 2, 0)
        _rotate()
        _assert_counts(2, 0, 2, 0)

        _create_event()
        _create_event(thread_id=thread_id)
        _mark_read(event_id)
        _assert_counts(1, 0, 3, 0)
        _mark_read(event_id, thread_id)
        _assert_counts(1, 0, 1, 0)

        _mark_read(last_event_id)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)

        _create_event()
        _create_event(thread_id=thread_id)
        _assert_counts(1, 0, 1, 0)
        _rotate()
        _assert_counts(1, 0, 1, 0)

        # Delete old event push actions, this should not affect the (summarised) count.
        self.get_success(self.store._remove_old_push_actions_that_have_rotated())
        _assert_counts(1, 0, 1, 0)

        _mark_read(last_event_id)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)

        _create_event(True)
        _assert_counts(1, 1, 0, 0)
        _rotate()
        _assert_counts(1, 1, 0, 0)

        event_id = _create_event(True, thread_id)
        _assert_counts(1, 1, 1, 1)
        _rotate()
        _assert_counts(1, 1, 1, 1)

        # Check that adding another notification and rotating after highlight
        # works.
        _create_event()
        _rotate()
        _assert_counts(2, 1, 1, 1)

        _create_event(thread_id=thread_id)
        _rotate()
        _assert_counts(2, 1, 2, 1)

        # Check that sending read receipts at different points results in the
        # right counts.
        _mark_read(event_id)
        _assert_counts(1, 0, 2, 1)
        _mark_read(event_id, thread_id)
        _assert_counts(1, 0, 1, 0)
        _mark_read(last_event_id)
        _assert_counts(0, 0, 1, 0)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)

        _create_event(True)
        _create_event(True, thread_id)
        _assert_counts(1, 1, 1, 1)
        _mark_read(last_event_id)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)
        _rotate()
        _assert_counts(0, 0, 0, 0)

    def test_count_aggregation_mixed(self) -> None:
        """
        This is essentially the same test as test_count_aggregation_threads, but
        sends both unthreaded and threaded receipts.
        """

        user_id, token, _, other_token, room_id = self._create_users_and_room()
        thread_id: str

        last_event_id: str

        def _assert_counts(
            noitf_count: int,
            highlight_count: int,
            thread_notif_count: int,
            thread_highlight_count: int,
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
                counts.main_timeline,
                NotifCounts(
                    notify_count=noitf_count,
                    unread_count=0,
                    highlight_count=highlight_count,
                ),
            )
            if thread_notif_count or thread_highlight_count:
                self.assertEqual(
                    counts.threads,
                    {
                        thread_id: NotifCounts(
                            notify_count=thread_notif_count,
                            unread_count=0,
                            highlight_count=thread_highlight_count,
                        ),
                    },
                )
            else:
                self.assertEqual(counts.threads, {})

        def _create_event(
            highlight: bool = False, thread_id: Optional[str] = None
        ) -> str:
            content: JsonDict = {
                "msgtype": "m.text",
                "body": user_id if highlight else "msg",
            }
            if thread_id:
                content["m.relates_to"] = {
                    "rel_type": "m.thread",
                    "event_id": thread_id,
                }

            result = self.helper.send_event(
                room_id,
                type="m.room.message",
                content=content,
                tok=other_token,
            )
            nonlocal last_event_id
            last_event_id = result["event_id"]
            return last_event_id

        def _rotate() -> None:
            self.get_success(self.store._rotate_notifs())

        def _mark_read(event_id: str, thread_id: Optional[str] = None) -> None:
            self.get_success(
                self.store.insert_receipt(
                    room_id,
                    "m.read",
                    user_id=user_id,
                    event_ids=[event_id],
                    thread_id=thread_id,
                    data={},
                )
            )

        _assert_counts(0, 0, 0, 0)
        thread_id = _create_event()
        _assert_counts(1, 0, 0, 0)
        _rotate()
        _assert_counts(1, 0, 0, 0)

        _create_event(thread_id=thread_id)
        _assert_counts(1, 0, 1, 0)
        _rotate()
        _assert_counts(1, 0, 1, 0)

        _create_event()
        _assert_counts(2, 0, 1, 0)
        _rotate()
        _assert_counts(2, 0, 1, 0)

        event_id = _create_event(thread_id=thread_id)
        _assert_counts(2, 0, 2, 0)
        _rotate()
        _assert_counts(2, 0, 2, 0)

        _create_event()
        _create_event(thread_id=thread_id)
        _mark_read(event_id)
        _assert_counts(1, 0, 1, 0)

        _mark_read(last_event_id, MAIN_TIMELINE)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)

        _create_event()
        _create_event(thread_id=thread_id)
        _assert_counts(1, 0, 1, 0)
        _rotate()
        _assert_counts(1, 0, 1, 0)

        # Delete old event push actions, this should not affect the (summarised) count.
        self.get_success(self.store._remove_old_push_actions_that_have_rotated())
        _assert_counts(1, 0, 1, 0)

        _mark_read(last_event_id)
        _assert_counts(0, 0, 0, 0)

        _create_event(True)
        _assert_counts(1, 1, 0, 0)
        _rotate()
        _assert_counts(1, 1, 0, 0)

        event_id = _create_event(True, thread_id)
        _assert_counts(1, 1, 1, 1)
        _rotate()
        _assert_counts(1, 1, 1, 1)

        # Check that adding another notification and rotating after highlight
        # works.
        _create_event()
        _rotate()
        _assert_counts(2, 1, 1, 1)

        _create_event(thread_id=thread_id)
        _rotate()
        _assert_counts(2, 1, 2, 1)

        # Check that sending read receipts at different points results in the
        # right counts.
        _mark_read(event_id)
        _assert_counts(1, 0, 1, 0)
        _mark_read(event_id, MAIN_TIMELINE)
        _assert_counts(1, 0, 1, 0)
        _mark_read(last_event_id, MAIN_TIMELINE)
        _assert_counts(0, 0, 1, 0)
        _mark_read(last_event_id, thread_id)
        _assert_counts(0, 0, 0, 0)

        _create_event(True)
        _create_event(True, thread_id)
        _assert_counts(1, 1, 1, 1)
        _mark_read(last_event_id)
        _assert_counts(0, 0, 0, 0)
        _rotate()
        _assert_counts(0, 0, 0, 0)

    def test_recursive_thread(self) -> None:
        """
        Events related to events in a thread should still be considered part of
        that thread.
        """

        # Create a user to receive notifications and send receipts.
        user_id = self.register_user("user1235", "pass")
        token = self.login("user1235", "pass")

        # And another users to send events.
        other_id = self.register_user("other", "pass")
        other_token = self.login("other", "pass")

        # Create a room and put both users in it.
        room_id = self.helper.create_room_as(user_id, tok=token)
        self.helper.join(room_id, other_id, tok=other_token)

        # Update the user's push rules to care about reaction events.
        self.get_success(
            self.store.add_push_rule(
                user_id,
                "related_events",
                priority_class=5,
                conditions=[
                    {"kind": "event_match", "key": "type", "pattern": "m.reaction"}
                ],
                actions=["notify"],
            )
        )

        def _create_event(type: str, content: JsonDict) -> str:
            result = self.helper.send_event(
                room_id, type=type, content=content, tok=other_token
            )
            return result["event_id"]

        def _assert_counts(noitf_count: int, thread_notif_count: int) -> None:
            counts = self.get_success(
                self.store.db_pool.runInteraction(
                    "get-unread-counts",
                    self.store._get_unread_counts_by_receipt_txn,
                    room_id,
                    user_id,
                )
            )
            self.assertEqual(
                counts.main_timeline,
                NotifCounts(
                    notify_count=noitf_count, unread_count=0, highlight_count=0
                ),
            )
            if thread_notif_count:
                self.assertEqual(
                    counts.threads,
                    {
                        thread_id: NotifCounts(
                            notify_count=thread_notif_count,
                            unread_count=0,
                            highlight_count=0,
                        ),
                    },
                )
            else:
                self.assertEqual(counts.threads, {})

        # Create a root event.
        thread_id = _create_event(
            "m.room.message", {"msgtype": "m.text", "body": "msg"}
        )
        _assert_counts(1, 0)

        # Reply, creating a thread.
        reply_id = _create_event(
            "m.room.message",
            {
                "msgtype": "m.text",
                "body": "msg",
                "m.relates_to": {
                    "rel_type": "m.thread",
                    "event_id": thread_id,
                },
            },
        )
        _assert_counts(1, 1)

        # Create an event related to a thread event, this should still appear in
        # the thread.
        _create_event(
            type="m.reaction",
            content={
                "m.relates_to": {
                    "rel_type": "m.annotation",
                    "event_id": reply_id,
                    "key": "A",
                }
            },
        )
        _assert_counts(1, 2)

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
