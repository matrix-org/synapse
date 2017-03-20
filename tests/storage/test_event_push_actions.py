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

from twisted.internet import defer

import tests.unittest
import tests.utils
from mock import Mock

USER_ID = "@user:example.com"

PlAIN_NOTIF = ["notify", {"set_tweak": "highlight", "value": False}]
HIGHLIGHT = [
    "notify", {"set_tweak": "sound", "value": "default"}, {"set_tweak": "highlight"}
]


class EventPushActionsStoreTestCase(tests.unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_http(self):
        yield self.store.get_unread_push_actions_for_user_in_range_for_http(
            USER_ID, 0, 1000, 20
        )

    @defer.inlineCallbacks
    def test_get_unread_push_actions_for_user_in_range_for_email(self):
        yield self.store.get_unread_push_actions_for_user_in_range_for_email(
            USER_ID, 0, 1000, 20
        )

    @defer.inlineCallbacks
    def test_count_aggregation(self):
        room_id = "!foo:example.com"
        user_id = "@user1235:example.com"

        @defer.inlineCallbacks
        def _assert_counts(noitf_count, highlight_count):
            counts = yield self.store.runInteraction(
                "", self.store._get_unread_counts_by_pos_txn,
                room_id, user_id, 0, 0
            )
            self.assertEquals(
                counts,
                {"notify_count": noitf_count, "highlight_count": highlight_count}
            )

        def _inject_actions(stream, action):
            event = Mock()
            event.room_id = room_id
            event.event_id = "$test:example.com"
            event.internal_metadata.stream_ordering = stream
            event.depth = stream

            tuples = [(user_id, action)]

            return self.store.runInteraction(
                "", self.store._set_push_actions_for_event_and_users_txn,
                event, tuples
            )

        def _rotate(stream):
            return self.store.runInteraction(
                "", self.store._rotate_notifs_before_txn, stream
            )

        def _mark_read(stream, depth):
            return self.store.runInteraction(
                "", self.store._remove_old_push_actions_before_txn,
                room_id, user_id, depth, stream
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

        yield self.store._simple_delete(
            table="event_push_actions",
            keyvalues={"1": 1},
            desc="",
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
