# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

import json

from synapse.rest import admin
from synapse.rest.client.v1 import directory, login, room
from synapse.types import RoomAlias
from synapse.util.stringutils import random_string

from tests import unittest
from tests.unittest import override_config


class DirectoryTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        directory.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        config["require_membership_for_aliases"] = True

        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, homeserver):
        self.room_owner = self.register_user("room_owner", "test")
        self.room_owner_tok = self.login("room_owner", "test")

        self.room_id = self.helper.create_room_as(
            self.room_owner, tok=self.room_owner_tok
        )

        self.user = self.register_user("user", "test")
        self.user_tok = self.login("user", "test")

    def test_state_event_not_in_room(self):
        self.ensure_user_left_room()
        self.set_alias_via_state_event(403)

    def test_directory_endpoint_not_in_room(self):
        self.ensure_user_left_room()
        self.set_alias_via_directory(403)

    def test_state_event_in_room_too_long(self):
        self.ensure_user_joined_room()
        self.set_alias_via_state_event(400, alias_length=256)

    def test_directory_in_room_too_long(self):
        self.ensure_user_joined_room()
        self.set_alias_via_directory(400, alias_length=256)

    @override_config({"default_room_version": 5})
    def test_state_event_user_in_v5_room(self):
        """Test that a regular user can add alias events before room v6"""
        self.ensure_user_joined_room()
        self.set_alias_via_state_event(200)

    @override_config({"default_room_version": 6})
    def test_state_event_v6_room(self):
        """Test that a regular user can *not* add alias events from room v6"""
        self.ensure_user_joined_room()
        self.set_alias_via_state_event(403)

    def test_directory_in_room(self):
        self.ensure_user_joined_room()
        self.set_alias_via_directory(200)

    def test_room_creation_too_long(self):
        url = "/_matrix/client/r0/createRoom"

        # We use deliberately a localpart under the length threshold so
        # that we can make sure that the check is done on the whole alias.
        data = {"room_alias_name": random_string(256 - len(self.hs.hostname))}
        request_data = json.dumps(data)
        channel = self.make_request(
            "POST", url, request_data, access_token=self.user_tok
        )
        self.assertEqual(channel.code, 400, channel.result)

    def test_room_creation(self):
        url = "/_matrix/client/r0/createRoom"

        # Check with an alias of allowed length. There should already be
        # a test that ensures it works in test_register.py, but let's be
        # as cautious as possible here.
        data = {"room_alias_name": random_string(5)}
        request_data = json.dumps(data)
        channel = self.make_request(
            "POST", url, request_data, access_token=self.user_tok
        )
        self.assertEqual(channel.code, 200, channel.result)

    def set_alias_via_state_event(self, expected_code, alias_length=5):
        url = "/_matrix/client/r0/rooms/%s/state/m.room.aliases/%s" % (
            self.room_id,
            self.hs.hostname,
        )

        data = {"aliases": [self.random_alias(alias_length)]}
        request_data = json.dumps(data)

        channel = self.make_request(
            "PUT", url, request_data, access_token=self.user_tok
        )
        self.assertEqual(channel.code, expected_code, channel.result)

    def set_alias_via_directory(self, expected_code, alias_length=5):
        url = "/_matrix/client/r0/directory/room/%s" % self.random_alias(alias_length)
        data = {"room_id": self.room_id}
        request_data = json.dumps(data)

        channel = self.make_request(
            "PUT", url, request_data, access_token=self.user_tok
        )
        self.assertEqual(channel.code, expected_code, channel.result)

    def random_alias(self, length):
        return RoomAlias(random_string(length), self.hs.hostname).to_string()

    def ensure_user_left_room(self):
        self.ensure_membership("leave")

    def ensure_user_joined_room(self):
        self.ensure_membership("join")

    def ensure_membership(self, membership):
        try:
            if membership == "leave":
                self.helper.leave(room=self.room_id, user=self.user, tok=self.user_tok)
            if membership == "join":
                self.helper.join(room=self.room_id, user=self.user, tok=self.user_tok)
        except AssertionError:
            # We don't care whether the leave request didn't return a 200 (e.g.
            # if the user isn't already in the room), because we only want to
            # make sure the user isn't in the room.
            pass
