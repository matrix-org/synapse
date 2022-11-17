# Copyright 2020 Half-Shot
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

import synapse.rest.admin
from synapse.rest.client import login, mutual_rooms, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.server import FakeChannel


class UserMutualRoomsTest(unittest.HomeserverTestCase):
    """
    Tests the UserMutualRoomsServlet.
    """

    servlets = [
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        mutual_rooms.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def _get_mutual_rooms(self, token: str, other_user: str) -> FakeChannel:
        return self.make_request(
            "GET",
            "/_matrix/client/unstable/uk.half-shot.msc2666/user/mutual_rooms/%s"
            % other_user,
            access_token=token,
        )

    def test_shared_room_list_public(self) -> None:
        """
        A room should show up in the shared list of rooms between two users
        if it is public.
        """
        self._check_mutual_rooms_with(room_one_is_public=True, room_two_is_public=True)

    def test_shared_room_list_private(self) -> None:
        """
        A room should show up in the shared list of rooms between two users
        if it is private.
        """
        self._check_mutual_rooms_with(
            room_one_is_public=False, room_two_is_public=False
        )

    def test_shared_room_list_mixed(self) -> None:
        """
        The shared room list between two users should contain both public and private
        rooms.
        """
        self._check_mutual_rooms_with(room_one_is_public=True, room_two_is_public=False)

    def _check_mutual_rooms_with(
        self, room_one_is_public: bool, room_two_is_public: bool
    ) -> None:
        """Checks that shared public or private rooms between two users appear in
        their shared room lists
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        # Create a room. user1 invites user2, who joins
        room_id_one = self.helper.create_room_as(
            u1, is_public=room_one_is_public, tok=u1_token
        )
        self.helper.invite(room_id_one, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room_id_one, user=u2, tok=u2_token)

        # Check shared rooms from user1's perspective.
        # We should see the one room in common
        channel = self._get_mutual_rooms(u1_token, u2)
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(len(channel.json_body["joined"]), 1)
        self.assertEqual(channel.json_body["joined"][0], room_id_one)

        # Create another room and invite user2 to it
        room_id_two = self.helper.create_room_as(
            u1, is_public=room_two_is_public, tok=u1_token
        )
        self.helper.invite(room_id_two, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room_id_two, user=u2, tok=u2_token)

        # Check shared rooms again. We should now see both rooms.
        channel = self._get_mutual_rooms(u1_token, u2)
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(len(channel.json_body["joined"]), 2)
        for room_id_id in channel.json_body["joined"]:
            self.assertIn(room_id_id, [room_id_one, room_id_two])

    def test_shared_room_list_after_leave(self) -> None:
        """
        A room should no longer be considered shared if the other
        user has left it.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        room = self.helper.create_room_as(u1, is_public=True, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        # Assert user directory is not empty
        channel = self._get_mutual_rooms(u1_token, u2)
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(len(channel.json_body["joined"]), 1)
        self.assertEqual(channel.json_body["joined"][0], room)

        self.helper.leave(room, user=u1, tok=u1_token)

        # Check user1's view of shared rooms with user2
        channel = self._get_mutual_rooms(u1_token, u2)
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(len(channel.json_body["joined"]), 0)

        # Check user2's view of shared rooms with user1
        channel = self._get_mutual_rooms(u2_token, u1)
        self.assertEqual(200, channel.code, channel.result)
        self.assertEqual(len(channel.json_body["joined"]), 0)
