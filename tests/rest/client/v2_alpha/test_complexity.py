# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation
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

from mock import Mock

from synapse.rest.client.v1 import admin, login, room
from synapse.rest.client.v2_alpha import room_complexity

from tests import unittest


class RoomComplexityTests(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
        room_complexity.register_servlets,
    ]

    def test_complexity_simple(self):

        u1 = self.register_user("u1", "pass")
        u1_token = self.login("u1", "pass")

        room_1 = self.helper.create_room_as(u1, tok=u1_token)
        self.helper.send_state(
            room_1, event_type="m.room.topic", body={"topic": "foo"}, tok=u1_token
        )

        # Get the room complexity
        request, channel = self.make_request(
            "GET", "/_matrix/client/unstable/rooms/%s/complexity" % (room_1,)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        complexity = channel.json_body["v1"]
        self.assertTrue(complexity > 0, complexity)

        # Make more events -- over the threshold
        for i in range(500):
            self.helper.send_state(
                room_1,
                event_type="m.room.topic",
                body={"topic": "foo%s" % (i,)},
                tok=u1_token,
            )

        # Get the room complexity again -- make sure it's above 1
        request, channel = self.make_request(
            "GET", "/_matrix/client/unstable/rooms/%s/complexity" % (room_1,)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        complexity = channel.json_body["v1"]
        self.assertTrue(complexity > 1, complexity)

