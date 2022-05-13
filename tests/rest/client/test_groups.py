# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.rest.client import groups, room

from tests import unittest
from tests.unittest import override_config


class GroupsTestCase(unittest.HomeserverTestCase):
    user_id = "@alice:test"
    room_creator_user_id = "@bob:test"

    servlets = [room.register_servlets, groups.register_servlets]

    @override_config({"enable_group_creation": True})
    def test_rooms_limited_by_visibility(self) -> None:
        group_id = "+spqr:test"

        # Alice creates a group
        channel = self.make_request("POST", "/create_group", {"localpart": "spqr"})
        self.assertEqual(channel.code, 200, msg=channel.text_body)
        self.assertEqual(channel.json_body, {"group_id": group_id})

        # Bob creates a private room
        room_id = self.helper.create_room_as(self.room_creator_user_id, is_public=False)
        self.helper.auth_user_id = self.room_creator_user_id
        self.helper.send_state(
            room_id, "m.room.name", {"name": "bob's secret room"}, tok=None
        )
        self.helper.auth_user_id = self.user_id

        # Alice adds the room to her group.
        channel = self.make_request(
            "PUT", f"/groups/{group_id}/admin/rooms/{room_id}", {}
        )
        self.assertEqual(channel.code, 200, msg=channel.text_body)
        self.assertEqual(channel.json_body, {})

        # Alice now tries to retrieve the room list of the space.
        channel = self.make_request("GET", f"/groups/{group_id}/rooms")
        self.assertEqual(channel.code, 200, msg=channel.text_body)
        self.assertEqual(
            channel.json_body, {"chunk": [], "total_room_count_estimate": 0}
        )
