# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from mock import Mock

from twisted.internet import defer

import tests.unittest
import tests.utils

USER_ID = "@user:example.com"

PlAIN_NOTIF = ["notify", {"set_tweak": "highlight", "value": False}]
HIGHLIGHT = [
    "notify",
    {"set_tweak": "sound", "value": "default"},
    {"set_tweak": "highlight"},
]


class EventPushActionsStoreTestCase(tests.unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver(self.addCleanup)
        self.store = hs.get_datastore()
        self.persist_events_store = hs.get_datastores().persist_events

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_http(self):
        yield defer.ensureDeferred(
            self.store.get_unread_push_actions_for_user_in_range_for_http(
                USER_ID, 0, 1000, 20
            )
        )

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_email(self):
        yield defer.ensureDeferred(
            self.store.get_unread_push_actions_for_user_in_range_for_email(
                USER_ID, 0, 1000, 20
            )
        )

    @defer.inlineCallbacks
    def test_count_aggregation(self):
        room_id = "!foo:example.com"
        user_id = "@user1235:example.com"

        @defer.inlineCallbacks
        def _assert_counts(noitf_count, highlight_count):
            counts = yield defer.ensureDeferred(
                self.store.db_pool.runInteraction(
                    "", self.store._get_unread_counts_by_pos_txn, room_id, user_id, 0
                )
            )
            self.assertEquals(
                counts,
                {
                    "notify_count": noitf_count,
                    "unread_count": 0,  # Unread counts are tested in the sync tests.
                    "highlight_count": highlight_count,
                },
            )

        @defer.inlineCallbacks
        def _inject_actions(stream, action):
            event = Mock()
            event.room_id = room_id
            event.event_id = "$test:example.com"
            event.internal_metadata.stream_ordering = stream
            event.depth = stream

            yield defer.ensureDeferred(
                self.store.add_push_actions_to_staging(
                    event.event_id, {user_id: action}, False,
                )
            )
            yield defer.ensureDeferred(
                self.store.db_pool.runInteraction(
                    "",
                    self.persist_events_store._set_push_actions_for_event_and_users_txn,
                    [(event, None)],
                    [(event, None)],
                )
            )

        def _rotate(stream):
            return defer.ensureDeferred(
                self.store.db_pool.runInteraction(
                    "", self.store._rotate_notifs_before_txn, stream
                )
            )

        def _mark_read(stream, depth):
            return defer.ensureDeferred(
                self.store.db_pool.runInteraction(
                    "",
                    self.store._remove_old_push_actions_before_txn,
                    room_id,
                    user_id,
                    stream,
                )
            )

        yield _assert_counts(0, 0)
        yield _inject_actions(1, PlAIN_NOTIF)
        yield _assert_counts(1, 0)
        yield _rotate(2)
        yield _assert_counts(1, 0)

        yield _inject_actions(3, PlAIN_NOTIF)
        yield _assert_counts(2, 0)
        yield _rotate(4)
        yield _assert_counts(2, 0)

        yield _inject_actions(5, PlAIN_NOTIF)
        yield _mark_read(3, 3)
        yield _assert_counts(1, 0)

        yield _mark_read(5, 5)
        yield _assert_counts(0, 0)

        yield _inject_actions(6, PlAIN_NOTIF)
        yield _rotate(7)

        yield defer.ensureDeferred(
            self.store.db_pool.simple_delete(
                table="event_push_actions", keyvalues={"1": 1}, desc=""
            )
        )

        yield _assert_counts(1, 0)

        yield _mark_read(7, 7)
        yield _assert_counts(0, 0)

        yield _inject_actions(8, HIGHLIGHT)
        yield _assert_counts(1, 1)
        yield _rotate(9)
        yield _assert_counts(1, 1)
        yield _rotate(10)
        yield _assert_counts(1, 1)

    @defer.inlineCallbacks
    def test_find_first_stream_ordering_after_ts(self):
        def add_event(so, ts):
            return defer.ensureDeferred(
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
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(11)
        )
        self.assertEqual(r, 0)

        # now with one event
        yield add_event(2, 10)
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(9)
        )
        self.assertEqual(r, 2)
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(10)
        )
        self.assertEqual(r, 2)
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(11)
        )
        self.assertEqual(r, 3)

        # add a bunch of dummy events to the events table
        for (stream_ordering, ts) in (
            (3, 110),
            (4, 120),
            (5, 120),
            (10, 130),
            (20, 140),
        ):
            yield add_event(stream_ordering, ts)

        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(110)
        )
        self.assertEqual(r, 3, "First event after 110ms should be 3, was %i" % r)

        # 4 and 5 are both after 120: we want 4 rather than 5
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(120)
        )
        self.assertEqual(r, 4, "First event after 120ms should be 4, was %i" % r)

        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(129)
        )
        self.assertEqual(r, 10, "First event after 129ms should be 10, was %i" % r)

        # check we can get the last event
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(140)
        )
        self.assertEqual(r, 20, "First event after 14ms should be 20, was %i" % r)

        # off the end
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(160)
        )
        self.assertEqual(r, 21)

        # check we can find an event at ordering zero
        yield add_event(0, 5)
        r = yield defer.ensureDeferred(
            self.store.find_first_stream_ordering_after_ts(1)
        )
        self.assertEqual(r, 0)
