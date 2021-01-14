# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import Membership
from synapse.rest.admin import register_servlets_for_client_rest_resource
from synapse.rest.client.v1 import login, room
from synapse.types import UserID, create_requester

from tests import unittest
from tests.test_utils import event_injection
from tests.utils import TestHomeServer


class RoomMemberStoreTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
        register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: TestHomeServer):

        # We can't test the RoomMemberStore on its own without the other event
        # storage logic
        self.store = hs.get_datastore()

        self.u_alice = self.register_user("alice", "pass")
        self.t_alice = self.login("alice", "pass")
        self.u_bob = self.register_user("bob", "pass")

        # User elsewhere on another host
        self.u_charlie = UserID.from_string("@charlie:elsewhere")

    def test_one_member(self):

        # Alice creates the room, and is automatically joined
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)

        rooms_for_user = self.get_success(
            self.store.get_rooms_for_local_user_where_membership_is(
                self.u_alice, [Membership.JOIN]
            )
        )

        self.assertEquals([self.room], [m.room_id for m in rooms_for_user])

    def test_count_known_servers(self):
        """
        _count_known_servers will calculate how many servers are in a room.
        """
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.inject_room_member(self.room, self.u_bob, Membership.JOIN)
        self.inject_room_member(self.room, self.u_charlie.to_string(), Membership.JOIN)

        servers = self.get_success(self.store._count_known_servers())
        self.assertEqual(servers, 2)

    def test_count_known_servers_stat_counter_disabled(self):
        """
        If enabled, the metrics for how many servers are known will be counted.
        """
        self.assertTrue("_known_servers_count" not in self.store.__dict__.keys())

        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.inject_room_member(self.room, self.u_bob, Membership.JOIN)
        self.inject_room_member(self.room, self.u_charlie.to_string(), Membership.JOIN)

        self.pump()

        self.assertTrue("_known_servers_count" not in self.store.__dict__.keys())

    @unittest.override_config(
        {"enable_metrics": True, "metrics_flags": {"known_servers": True}}
    )
    def test_count_known_servers_stat_counter_enabled(self):
        """
        If enabled, the metrics for how many servers are known will be counted.
        """
        # Initialises to 1 -- itself
        self.assertEqual(self.store._known_servers_count, 1)

        self.pump()

        # No rooms have been joined, so technically the SQL returns 0, but it
        # will still say it knows about itself.
        self.assertEqual(self.store._known_servers_count, 1)

        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.inject_room_member(self.room, self.u_bob, Membership.JOIN)
        self.inject_room_member(self.room, self.u_charlie.to_string(), Membership.JOIN)

        self.pump(1)

        # It now knows about Charlie's server.
        self.assertEqual(self.store._known_servers_count, 2)

    def test_get_joined_users_from_context(self):
        room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        bob_event = self.get_success(
            event_injection.inject_member_event(
                self.hs, room, self.u_bob, Membership.JOIN
            )
        )

        # first, create a regular event
        event, context = self.get_success(
            event_injection.create_event(
                self.hs,
                room_id=room,
                sender=self.u_alice,
                prev_event_ids=[bob_event.event_id],
                type="m.test.1",
                content={},
            )
        )

        users = self.get_success(
            self.store.get_joined_users_from_context(event, context)
        )
        self.assertEqual(users.keys(), {self.u_alice, self.u_bob})

        # Regression test for #7376: create a state event whose key matches bob's
        # user_id, but which is *not* a membership event, and persist that; then check
        # that `get_joined_users_from_context` returns the correct users for the next event.
        non_member_event = self.get_success(
            event_injection.inject_event(
                self.hs,
                room_id=room,
                sender=self.u_bob,
                prev_event_ids=[bob_event.event_id],
                type="m.test.2",
                state_key=self.u_bob,
                content={},
            )
        )
        event, context = self.get_success(
            event_injection.create_event(
                self.hs,
                room_id=room,
                sender=self.u_alice,
                prev_event_ids=[non_member_event.event_id],
                type="m.test.3",
                content={},
            )
        )
        users = self.get_success(
            self.store.get_joined_users_from_context(event, context)
        )
        self.assertEqual(users.keys(), {self.u_alice, self.u_bob})


class CurrentStateMembershipUpdateTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.room_creator = homeserver.get_room_creation_handler()

    def test_can_rerun_update(self):
        # First make sure we have completed all updates.
        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        # Now let's create a room, which will insert a membership
        user = UserID("alice", "test")
        requester = create_requester(user)
        self.get_success(self.room_creator.create_room(requester, {}))

        # Register the background update to run again.
        self.get_success(
            self.store.db_pool.simple_insert(
                table="background_updates",
                values={
                    "update_name": "current_state_events_membership",
                    "progress_json": "{}",
                    "depends_on": None,
                },
            )
        )

        # ... and tell the DataStore that it hasn't finished all updates yet
        self.store.db_pool.updates._all_done = False

        # Now let's actually drive the updates to completion
        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )
