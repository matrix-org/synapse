# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from synapse.module_api import ModuleApi
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase


class ModuleApiTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.module_api = ModuleApi(homeserver, homeserver.get_auth_handler())

    def test_can_register_user(self):
        """Tests that an external module can register a user"""
        # Register a new user
        user_id, access_token = self.get_success(
            self.module_api.register(
                "bob", displayname="Bobberino", emails=["bob@bobinator.bob"]
            )
        )

        # Check that the new user exists with all provided attributes
        self.assertEqual(user_id, "@bob:test")
        self.assertTrue(access_token)
        self.assertTrue(self.store.get_user_by_id(user_id))

        # Check that the email was assigned
        emails = self.get_success(self.store.user_get_threepids(user_id))
        self.assertEqual(len(emails), 1)

        email = emails[0]
        self.assertEqual(email["medium"], "email")
        self.assertEqual(email["address"], "bob@bobinator.bob")

        # Should these be 0?
        self.assertEqual(email["validated_at"], 0)
        self.assertEqual(email["added_at"], 0)

        # Check that the displayname was assigned
        displayname = self.get_success(self.store.get_profile_displayname("bob"))
        self.assertEqual(displayname, "Bobberino")

    def test_public_rooms(self):
        """Tests that a room can be added and removed from the public rooms list,
        as well as have its public rooms directory state queried.
        """
        # Create a user and room to play with
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")
        room_id = self.helper.create_room_as(user_id, tok=tok)

        # The room should not currently be in the public rooms directory
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertFalse(is_in_public_rooms)

        # Let's try adding it to the public rooms directory
        self.get_success(
            self.module_api.public_room_list_manager.add_room_to_public_room_list(
                room_id
            )
        )

        # And checking whether it's in there...
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertTrue(is_in_public_rooms)

        # Let's remove it again
        self.get_success(
            self.module_api.public_room_list_manager.remove_room_from_public_room_list(
                room_id
            )
        )

        # Should be gone
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertFalse(is_in_public_rooms)
