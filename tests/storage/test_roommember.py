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
from synapse.api.events.room import RoomMemberEvent

from tests.utils import SQLiteMemoryDbPool


class RoomMemberStoreTestCase(unittest.TestCase):

    @defer.inlineCallbacks
    def setUp(self):
        db_pool = SQLiteMemoryDbPool()
        yield db_pool.prepare()

        hs = HomeServer("test",
            db_pool=db_pool,
        )

        # We can't test the RoomMemberStore on its own without the other event
        # storage logic
        self.store = hs.get_datastore()
        self.event_factory = hs.get_event_factory()

        self.u_alice = hs.parse_userid("@alice:test")
        self.u_bob = hs.parse_userid("@bob:test")

        # User elsewhere on another host
        self.u_charlie = hs.parse_userid("@charlie:elsewhere")

        self.room = hs.parse_roomid("!abc123:test")

    @defer.inlineCallbacks
    def inject_room_member(self, room, user, membership):
        # Have to create a join event using the eventfactory
        yield self.store.persist_event(
            self.event_factory.create_event(
                etype=RoomMemberEvent.TYPE,
                user_id=user.to_string(),
                state_key=user.to_string(),
                room_id=room.to_string(),
                membership=membership,
                content={"membership": membership},
                depth=1,
            )
        )

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
