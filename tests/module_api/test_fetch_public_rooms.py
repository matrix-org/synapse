# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import List, Optional, Tuple

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin, login, room
from synapse.server import HomeServer
from synapse.types import PublicRoom
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class FetchPublicRoomsTestCase(HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["allow_public_rooms_without_auth"] = True
        self.hs = self.setup_test_homeserver(config=config)
        self.url = "/_matrix/client/r0/publicRooms"

        return self.hs

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self._store = homeserver.get_datastores().main
        self._module_api = homeserver.get_module_api()

        async def cb(
            forwards: bool, limit: Optional[int], bounds: Optional[Tuple[int, str]]
        ) -> List[PublicRoom]:
            rooms_db = [
                PublicRoom(
                    room_id="!test1:test",
                    num_joined_members=1,
                    world_readable=True,
                    guest_can_join=False,
                ),
                PublicRoom(
                    room_id="!test3:test",
                    num_joined_members=3,
                    world_readable=True,
                    guest_can_join=False,
                ),
                PublicRoom(
                    room_id="!test3_2:test",
                    num_joined_members=3,
                    world_readable=True,
                    guest_can_join=False,
                ),
            ]

            result = []
            if limit is not None and bounds is not None:
                (last_joined_members, last_room_id) = bounds
                for r in rooms_db:
                    if r.num_joined_members <= last_joined_members:
                        if r.room_id == last_room_id:
                            break
                        result.append(r)
            else:
                result = rooms_db

            if forwards:
                result.reverse()

            if limit is not None:
                result = result[:limit]

            return result

        self._module_api.register_public_rooms_callbacks(fetch_public_rooms=cb)

        user = self.register_user("alice", "pass")
        token = self.login(user, "pass")

        # Create a room
        room_id = self.helper.create_room_as(
            user,
            is_public=True,
            extra_content={"visibility": "public"},
            tok=token,
        )

        user2 = self.register_user("alice2", "pass")
        token2 = self.login(user2, "pass")
        self.helper.join(room_id, user2, tok=token2)

    def test_no_limit(self) -> None:
        channel = self.make_request("GET", self.url)
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)

        self.assertEquals(len(channel.json_body["chunk"]), 4)
        self.assertEquals(channel.json_body["chunk"][0]["num_joined_members"], 3)
        self.assertEquals(channel.json_body["chunk"][1]["num_joined_members"], 3)
        self.assertEquals(channel.json_body["chunk"][2]["num_joined_members"], 2)
        self.assertEquals(channel.json_body["chunk"][3]["num_joined_members"], 1)

    def test_pagination(self) -> None:
        channel = self.make_request("GET", self.url + "?limit=1")
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEquals(channel.json_body["chunk"][0]["num_joined_members"], 3)
        returned_room3_id = channel.json_body["chunk"][0]["room_id"]

        channel = self.make_request(
            "GET", self.url + "?limit=1&since=" + channel.json_body["next_batch"]
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEquals(channel.json_body["chunk"][0]["num_joined_members"], 3)
        self.assertNotEquals(
            returned_room3_id, channel.json_body["chunk"][0]["room_id"]
        )

        channel = self.make_request(
            "GET", self.url + "?limit=1&since=" + channel.json_body["next_batch"]
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEquals(channel.json_body["chunk"][0]["num_joined_members"], 2)

        channel = self.make_request(
            "GET", self.url + "?limit=1&since=" + channel.json_body["next_batch"]
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        self.assertEquals(channel.json_body["chunk"][0]["num_joined_members"], 1)
