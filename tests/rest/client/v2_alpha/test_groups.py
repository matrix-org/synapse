from synapse.rest.client.v1 import room
from synapse.rest.client.v2_alpha import groups

from tests import unittest
from tests.unittest import override_config


class GroupsTestCase(unittest.HomeserverTestCase):
    user_id = "@alice:test"
    room_creator_user_id = "@bob:test"

    servlets = [room.register_servlets, groups.register_servlets]

    @override_config({"enable_group_creation": True})
    def test_rooms_limited_by_visibility(self):
        group_id = "+spqr:test"

        # Alice creates a group
        channel = self.make_request("POST", "/create_group", {"localpart": "spqr"})
        self.assertEquals(channel.code, 200, msg=channel.text_body)
        self.assertEquals(channel.json_body, {"group_id": group_id})

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
        self.assertEquals(channel.code, 200, msg=channel.text_body)
        self.assertEquals(channel.json_body, {})

        # Alice now tries to retrieve the room list of the space.
        channel = self.make_request("GET", f"/groups/{group_id}/rooms")
        self.assertEquals(channel.code, 200, msg=channel.text_body)
        self.assertEquals(
            channel.json_body, {"chunk": [], "total_room_count_estimate": 0}
        )
