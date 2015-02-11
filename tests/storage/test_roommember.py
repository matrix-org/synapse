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

from synapse.api.constants import EventTypes, Membership
from synapse.types import UserID, RoomID

from tests.utils import setup_test_homeserver

from mock import Mock


class RoomMemberStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield setup_test_homeserver(
            resource_for_federation=Mock(),
            http_client=None,
        )
        # We can't test the RoomMemberStore on its own without the other event
        # storage logic
        self.store = hs.get_datastore()
        self.event_builder_factory = hs.get_event_builder_factory()
        self.handlers = hs.get_handlers()
        self.message_handler = self.handlers.message_handler

        self.u_alice = UserID.from_string("@alice:test")
        self.u_bob = UserID.from_string("@bob:test")

        # User elsewhere on another host
        self.u_charlie = UserID.from_string("@charlie:elsewhere")

        self.room = RoomID.from_string("!abc123:test")

    @defer.inlineCallbacks
    def inject_room_member(self, room, user, membership, replaces_state=None):
        builder = self.event_builder_factory.new({
            "type": EventTypes.Member,
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
    def test_one_member(self):
        yield self.inject_room_member(self.room, self.u_alice, Membership.JOIN)

        self.assertEquals(
            Membership.JOIN,
            (yield self.store.get_room_member(
                user_id=self.u_alice.to_string(),
                room_id=self.room.to_string(),
            )).membership
        )
        self.assertEquals(
            [self.u_alice.to_string()],
            [m.user_id for m in (
                yield self.store.get_room_members(self.room.to_string())
            )]
        )
        self.assertEquals(
            [self.room.to_string()],
            [m.room_id for m in (
                yield self.store.get_rooms_for_user_where_membership_is(
                    self.u_alice.to_string(), [Membership.JOIN]
                ))
            ]
        )
        self.assertFalse(
            (yield self.store.user_rooms_intersect(
                [self.u_alice.to_string(), self.u_bob.to_string()]
            ))
        )

    @defer.inlineCallbacks
    def test_two_members(self):
        yield self.inject_room_member(self.room, self.u_alice, Membership.JOIN)
        yield self.inject_room_member(self.room, self.u_bob, Membership.JOIN)

        self.assertEquals(
            {self.u_alice.to_string(), self.u_bob.to_string()},
            {m.user_id for m in (
                yield self.store.get_room_members(self.room.to_string())
            )}
        )
        self.assertTrue(
            (yield self.store.user_rooms_intersect(
                [self.u_alice.to_string(), self.u_bob.to_string()]
            ))
        )

    @defer.inlineCallbacks
    def test_room_hosts(self):
        yield self.inject_room_member(self.room, self.u_alice, Membership.JOIN)

        self.assertEquals(
            ["test"],
            (yield self.store.get_joined_hosts_for_room(self.room.to_string()))
        )

        # Should still have just one host after second join from it
        yield self.inject_room_member(self.room, self.u_bob, Membership.JOIN)

        self.assertEquals(
            ["test"],
            (yield self.store.get_joined_hosts_for_room(self.room.to_string()))
        )

        # Should now have two hosts after join from other host
        yield self.inject_room_member(self.room, self.u_charlie, Membership.JOIN)

        self.assertEquals(
            {"test", "elsewhere"},
            set((yield
                self.store.get_joined_hosts_for_room(self.room.to_string())
            ))
        )

        # Should still have both hosts
        yield self.inject_room_member(self.room, self.u_alice, Membership.LEAVE)

        self.assertEquals(
            {"test", "elsewhere"},
            set((yield
                self.store.get_joined_hosts_for_room(self.room.to_string())
            ))
        )

        # Should have only one host after other leaves
        yield self.inject_room_member(self.room, self.u_charlie, Membership.LEAVE)

        self.assertEquals(
            ["test"],
            (yield self.store.get_joined_hosts_for_room(self.room.to_string()))
        )
