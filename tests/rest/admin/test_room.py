# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login, room

from tests import unittest

"""Tests admin REST events for /rooms paths."""


class JoinAliasRoomTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.creator = self.register_user("creator", "test")
        self.creator_tok = self.login("creator", "test")

        self.second_user_id = self.register_user("second", "test")
        self.second_tok = self.login("second", "test")

        self.public_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=True
        )
        self.url = "/_synapse/admin/v1/join/{}".format(self.public_room_id)

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error 403 is returned.
        """
        body = json.dumps({"user_id": self.second_user_id})

        request, channel = self.make_request(
            "POST",
            self.url,
            content=body.encode(encoding="utf_8"),
            access_token=self.second_tok,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self):
        """
        If a parameter is missing, return an error
        """
        body = json.dumps({"unknown_parameter": "@unknown:test"})

        request, channel = self.make_request(
            "POST",
            self.url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_PARAM, channel.json_body["errcode"])

    def test_local_user_does_not_exist(self):
        """
        Tests that a lookup for a user that does not exist returns a 404
        """
        body = json.dumps({"user_id": "@unknown:test"})

        request, channel = self.make_request(
            "POST",
            self.url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.NOT_FOUND, channel.json_body["errcode"])

    def test_remote_user(self):
        """
        Check that only local user can join rooms.
        """
        body = json.dumps({"user_id": "@not:exist.bla"})

        request, channel = self.make_request(
            "POST",
            self.url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(
            "This endpoint can only be used with local users",
            channel.json_body["error"],
        )

    def test_room_does_not_exist(self):
        """
        Check that unknown rooms/server return error 404.
        """
        body = json.dumps({"user_id": self.second_user_id})
        url = "/_synapse/admin/v1/join/!unknown:test"

        request, channel = self.make_request(
            "POST",
            url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(404, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("No known servers", channel.json_body["error"])

    def test_room_is_not_valid(self):
        """
        Check that invalid room names, return an error 400.
        """
        body = json.dumps({"user_id": self.second_user_id})
        url = "/_synapse/admin/v1/join/invalidroom"

        request, channel = self.make_request(
            "POST",
            url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(
            "invalidroom was not legal room ID or room alias",
            channel.json_body["error"],
        )

    def test_join_public_room(self):
        """
        Test joining a local user to a public room with "JoinRules.PUBLIC"
        """
        body = json.dumps({"user_id": self.second_user_id})

        request, channel = self.make_request(
            "POST",
            self.url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(self.public_room_id, channel.json_body["room_id"])

        # Validate if user is a member of the room

        request, channel = self.make_request(
            "GET", "/_matrix/client/r0/joined_rooms", access_token=self.second_tok,
        )
        self.render(request)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(self.public_room_id, channel.json_body["joined_rooms"][0])

    def test_join_private_room(self):
        """
        Test joining a local user to a private room with "JoinRules.INVITE"
        """
        private_room_id = self.helper.create_room_as(
            self.creator, tok=self.creator_tok, is_public=False
        )
        url = "/_synapse/admin/v1/join/{}".format(private_room_id)
        body = json.dumps({"user_id": self.second_user_id})

        request, channel = self.make_request(
            "POST",
            url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_join_private_room_if_owner(self):
        """
        Test joining a local user to a private room with "JoinRules.INVITE",
        when server admin is owner of this room.

        """
        private_room_id = self.helper.create_room_as(
            self.admin_user, tok=self.admin_user_tok, is_public=False
        )
        url = "/_synapse/admin/v1/join/{}".format(private_room_id)
        body = json.dumps({"user_id": self.second_user_id})

        request, channel = self.make_request(
            "POST",
            url,
            content=body.encode(encoding="utf_8"),
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(private_room_id, channel.json_body["room_id"])

        # Validate if user is a member of the room

        request, channel = self.make_request(
            "GET", "/_matrix/client/r0/joined_rooms", access_token=self.second_tok,
        )
        self.render(request)
        self.assertEquals(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(private_room_id, channel.json_body["joined_rooms"][0])
