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
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import Membership
from synapse.rest.admin import register_servlets_for_client_rest_resource
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import UserID, create_requester
from synapse.util import Clock

from tests import unittest
from tests.server import TestHomeServer
from tests.test_utils import event_injection


class RoomMemberStoreTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
        register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: TestHomeServer) -> None:  # type: ignore[override]

        # We can't test the RoomMemberStore on its own without the other event
        # storage logic
        self.store = hs.get_datastores().main

        self.u_alice = self.register_user("alice", "pass")
        self.t_alice = self.login("alice", "pass")
        self.u_bob = self.register_user("bob", "pass")

        # User elsewhere on another host
        self.u_charlie = UserID.from_string("@charlie:elsewhere")

    def test_one_member(self) -> None:

        # Alice creates the room, and is automatically joined
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)

        rooms_for_user = self.get_success(
            self.store.get_rooms_for_local_user_where_membership_is(
                self.u_alice, [Membership.JOIN]
            )
        )

        self.assertEqual([self.room], [m.room_id for m in rooms_for_user])

    def test_count_known_servers(self) -> None:
        """
        _count_known_servers will calculate how many servers are in a room.
        """
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.inject_room_member(self.room, self.u_bob, Membership.JOIN)
        self.inject_room_member(self.room, self.u_charlie.to_string(), Membership.JOIN)

        servers = self.get_success(self.store._count_known_servers())
        self.assertEqual(servers, 2)

    def test_count_known_servers_stat_counter_disabled(self) -> None:
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
    def test_count_known_servers_stat_counter_enabled(self) -> None:
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

    def test__null_byte_in_display_name_properly_handled(self) -> None:
        room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)

        res = self.get_success(
            self.store.db_pool.simple_select_list(
                "room_memberships",
                {"user_id": "@alice:test"},
                ["display_name", "event_id"],
            )
        )
        # Check that we only got one result back
        self.assertEqual(len(res), 1)

        # Check that alice's display name is "alice"
        self.assertEqual(res[0]["display_name"], "alice")

        # Grab the event_id to use later
        event_id = res[0]["event_id"]

        # Create a profile with the offending null byte in the display name
        new_profile = {"displayname": "ali\u0000ce"}

        # Ensure that the change goes smoothly and does not fail due to the null byte
        self.helper.change_membership(
            room,
            self.u_alice,
            self.u_alice,
            "join",
            extra_data=new_profile,
            tok=self.t_alice,
        )

        res2 = self.get_success(
            self.store.db_pool.simple_select_list(
                "room_memberships",
                {"user_id": "@alice:test"},
                ["display_name", "event_id"],
            )
        )
        # Check that we only have two results
        self.assertEqual(len(res2), 2)

        # Filter out the previous event using the event_id we grabbed above
        row = [row for row in res2 if row["event_id"] != event_id]

        # Check that alice's display name is now None
        self.assertEqual(row[0]["display_name"], None)

    def test_room_is_locally_forgotten(self) -> None:
        """Test that when the last local user has forgotten a room it is known as forgotten."""
        # join two local and one remote user
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.get_success(
            event_injection.inject_member_event(self.hs, self.room, self.u_bob, "join")
        )
        self.get_success(
            event_injection.inject_member_event(
                self.hs, self.room, self.u_charlie.to_string(), "join"
            )
        )
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

        # local users leave the room and the room is not forgotten
        self.get_success(
            event_injection.inject_member_event(
                self.hs, self.room, self.u_alice, "leave"
            )
        )
        self.get_success(
            event_injection.inject_member_event(self.hs, self.room, self.u_bob, "leave")
        )
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

        # first user forgets the room, room is not forgotten
        self.get_success(self.store.forget(self.u_alice, self.room))
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

        # second (last local) user forgets the room and the room is forgotten
        self.get_success(self.store.forget(self.u_bob, self.room))
        self.assertTrue(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

    def test_join_locally_forgotten_room(self) -> None:
        """Tests if a user joins a forgotten room the room is not forgotten anymore."""
        self.room = self.helper.create_room_as(self.u_alice, tok=self.t_alice)
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

        # after leaving and forget the room, it is forgotten
        self.get_success(
            event_injection.inject_member_event(
                self.hs, self.room, self.u_alice, "leave"
            )
        )
        self.get_success(self.store.forget(self.u_alice, self.room))
        self.assertTrue(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )

        # after rejoin the room is not forgotten anymore
        self.get_success(
            event_injection.inject_member_event(
                self.hs, self.room, self.u_alice, "join"
            )
        )
        self.assertFalse(
            self.get_success(self.store.is_locally_forgotten_room(self.room))
        )


class CurrentStateMembershipUpdateTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.room_creator = hs.get_room_creation_handler()

    def test_can_rerun_update(self) -> None:
        # First make sure we have completed all updates.
        self.wait_for_background_updates()

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
        self.wait_for_background_updates()
