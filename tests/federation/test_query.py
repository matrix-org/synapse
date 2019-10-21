# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation C.I.C.
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

from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests.unittest import FederatingHomeserverTestCase


class RoomMemberQueryTestCase(FederatingHomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):

        self.u1 = self.register_user("u1", "pass")
        self.u1_token = self.login("u1", "pass")

        super().prepare(reactor, clock, hs)

    def test_none(self):

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/query/net.maunium.members"
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(channel.json_body, [])

    def test_in_room_pdus(self):
        room_1 = self.helper.create_room_as(self.u1, tok=self.u1_token)
        injected = self.inject_room_member(room_1, "@user:other.example.com", "join")

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/query/net.maunium.members?pdu_ids=1"
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(channel.json_body, [injected.event_id])

    def test_in_room_full(self):
        room_1 = self.helper.create_room_as(self.u1, tok=self.u1_token)
        injected = self.inject_room_member(room_1, "@user:other.example.com", "join")

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/query/net.maunium.members"
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(channel.json_body, [injected.get_pdu_json()])

    def test_in_room_many(self):
        room_1 = self.helper.create_room_as(self.u1, tok=self.u1_token)
        injected_2 = self.inject_room_member(room_1, "@user:other.example.com", "join")
        injected_1 = self.inject_room_member(room_1, "@user2:other.example.com", "join")

        request, channel = self.make_request(
            "GET", "/_matrix/federation/v1/query/net.maunium.members?limit_per_room=1"
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEquals(len(channel.json_body), 1)
        self.assertIn(
            channel.json_body[0], [injected_1.get_pdu_json(), injected_2.get_pdu_json()]
        )
