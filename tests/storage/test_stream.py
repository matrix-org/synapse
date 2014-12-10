# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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


from tests import unittest
from twisted.internet import defer

from synapse.server import HomeServer
from synapse.api.constants import Membership
from synapse.api.events.room import RoomMemberEvent, MessageEvent

from tests.utils import SQLiteMemoryDbPool, MockKey

from mock import Mock


class StreamStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        self.mock_config = Mock()
        self.mock_config.signing_key = [MockKey()]

        hs = HomeServer(
            "test",
            db_pool=db_pool,
            config=self.mock_config,
            resource_for_federation=Mock(),
            http_client=None,
        )

        self.store = hs.get_datastore()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.handlers = hs.get_handlers()
        self.message_handler = self.handlers.message_handler

        self.u_alice = hs.parse_userid("@alice:test")
        self.u_bob = hs.parse_userid("@bob:test")

        self.room1 = hs.parse_roomid("!abc123:test")
        self.room2 = hs.parse_roomid("!xyx987:test")

        self.depth = 1

    @defer.inlineCallbacks
    def inject_room_member(self, room, user, membership, replaces_state=None):
        self.depth += 1

        builder = self.event_builder_factory.new({
            "type": RoomMemberEvent.TYPE,
            "sender": user.to_string(),
            "state_key": user.to_string(),
            "room_id": room.to_string(),
            "content": {"membership": membership},
        })

        event, context = yield self.message_handler._create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

        defer.returnValue(event)

    @defer.inlineCallbacks
    def inject_message(self, room, user, body):
        self.depth += 1

        builder = self.event_builder_factory.new({
            "type": MessageEvent.TYPE,
            "sender": user.to_string(),
            "state_key": user.to_string(),
            "room_id": room.to_string(),
            "content": {"body": body, "msgtype": u"message"},
        })

        event, context = yield self.message_handler._create_new_client_event(
            builder
        )

        yield self.store.persist_event(event, context)

    @defer.inlineCallbacks
    def test_event_stream_get_other(self):
        # Both bob and alice joins the room
        yield self.inject_room_member(
            self.room1, self.u_alice, Membership.JOIN
        )
        yield self.inject_room_member(
            self.room1, self.u_bob, Membership.JOIN
        )

        # Initial stream key:
        start = yield self.store.get_room_events_max_id()

        yield self.inject_message(self.room1, self.u_alice, u"test")

        end = yield self.store.get_room_events_max_id()

        results, _ = yield self.store.get_room_events_stream(
            self.u_bob.to_string(),
            start,
            end,
            None,  # Is currently ignored
        )

        self.assertEqual(1, len(results))

        event = results[0]

        self.assertObjectHasAttributes(
            {
                "type": MessageEvent.TYPE,
                "user_id": self.u_alice.to_string(),
                "content": {"body": "test", "msgtype": "message"},
            },
            event,
        )

    @defer.inlineCallbacks
    def test_event_stream_get_own(self):
        # Both bob and alice joins the room
        yield self.inject_room_member(
            self.room1, self.u_alice, Membership.JOIN
        )
        yield self.inject_room_member(
            self.room1, self.u_bob, Membership.JOIN
        )

        # Initial stream key:
        start = yield self.store.get_room_events_max_id()

        yield self.inject_message(self.room1, self.u_alice, u"test")

        end = yield self.store.get_room_events_max_id()

        results, _ = yield self.store.get_room_events_stream(
            self.u_alice.to_string(),
            start,
            end,
            None,  # Is currently ignored
        )

        self.assertEqual(1, len(results))

        event = results[0]

        self.assertObjectHasAttributes(
            {
                "type": MessageEvent.TYPE,
                "user_id": self.u_alice.to_string(),
                "content": {"body": "test", "msgtype": "message"},
            },
            event,
        )

    @defer.inlineCallbacks
    def test_event_stream_join_leave(self):
        # Both bob and alice joins the room
        yield self.inject_room_member(
            self.room1, self.u_alice, Membership.JOIN
        )
        yield self.inject_room_member(
            self.room1, self.u_bob, Membership.JOIN
        )

        # Then bob leaves again.
        yield self.inject_room_member(
            self.room1, self.u_bob, Membership.LEAVE
        )

        # Initial stream key:
        start = yield self.store.get_room_events_max_id()

        yield self.inject_message(self.room1, self.u_alice, u"test")

        end = yield self.store.get_room_events_max_id()

        results, _ = yield self.store.get_room_events_stream(
            self.u_bob.to_string(),
            start,
            end,
            None,  # Is currently ignored
        )

        # We should not get the message, as it happened *after* bob left.
        self.assertEqual(0, len(results))

    @defer.inlineCallbacks
    def test_event_stream_prev_content(self):
        yield self.inject_room_member(
            self.room1, self.u_bob, Membership.JOIN
        )

        event1 = yield self.inject_room_member(
            self.room1, self.u_alice, Membership.JOIN
        )

        start = yield self.store.get_room_events_max_id()

        event2 = yield self.inject_room_member(
            self.room1, self.u_alice, Membership.JOIN,
            replaces_state=event1.event_id,
        )

        end = yield self.store.get_room_events_max_id()

        results, _ = yield self.store.get_room_events_stream(
            self.u_bob.to_string(),
            start,
            end,
            None,  # Is currently ignored
        )

        # We should not get the message, as it happened *after* bob left.
        self.assertEqual(1, len(results))

        event = results[0]

        self.assertTrue(
            hasattr(event, "prev_content"),
            msg="No prev_content key"
        )
