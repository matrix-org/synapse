# -*- coding: utf-8 -*-
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
import synapse.rest.admin
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import shared_rooms

from tests import unittest


class UserSharedRoomsTest(unittest.HomeserverTestCase):
    """
    Tests the UserSharedRoomsServlet.
    """

    servlets = [
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        shared_rooms.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["update_user_directory"] = True
        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.handler = hs.get_user_directory_handler()

    def _get_shared_rooms(self, token, other_user):
        request, channel = self.make_request(
            "GET",
            "/_matrix/client/unstable/uk.half-shot.msc2666/user/shared_rooms/%s"
            % other_user,
            access_token=token,
        )
        self.render(request)
        return request, channel

    def test_shared_room_list_public(self):
        """
        A room should show up in the shared list of rooms between two users
        if it is public.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        room = self.helper.create_room_as(u1, is_public=True, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        request, channel = self._get_shared_rooms(u1_token, u2)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body["joined"]), 1)
        self.assertEquals(channel.json_body["joined"][0], room)

    def test_shared_room_list_private(self):
        """
        A room should show up in the shared list of rooms between two users
        if it is private.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        room = self.helper.create_room_as(u1, is_public=False, tok=u1_token)
        self.helper.invite(room, src=u1, targ=u2, tok=u1_token)
        self.helper.join(room, user=u2, tok=u2_token)

        request, channel = self._get_shared_rooms(u1_token, u2)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body["joined"]), 1)
        self.assertEquals(channel.json_body["joined"][0], room)

    def test_shared_room_list_mixed(self):
        """
        The shared room list between two users should contain both public and private
        rooms.
        """
        u1 = self.register_user("user1", "pass")
        u1_token = self.login(u1, "pass")
        u2 = self.register_user("user2", "pass")
        u2_token = self.login(u2, "pass")

        room_public = self.helper.create_room_as(u1, is_public=True, tok=u1_token)
        room_private = self.helper.create_room_as(u2, is_public=False, tok=u2_token)
        self.helper.invite(room_public, src=u1, targ=u2, tok=u1_token)
        self.helper.invite(room_private, src=u2, targ=u1, tok=u2_token)
        self.helper.join(room_public, user=u2, tok=u2_token)
        self.helper.join(room_private, user=u1, tok=u1_token)

        request, channel = self._get_shared_rooms(u1_token, u2)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body["joined"]), 2)
        self.assertTrue(room_public in channel.json_body["joined"])
        self.assertTrue(room_private in channel.json_body["joined"])

    def test_shared_room_list_after_leave(self):
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
        request, channel = self._get_shared_rooms(u1_token, u2)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body["joined"]), 1)
        self.assertEquals(channel.json_body["joined"][0], room)

        self.helper.leave(room, user=u1, tok=u1_token)

        request, channel = self._get_shared_rooms(u2_token, u1)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body["joined"]), 0)
