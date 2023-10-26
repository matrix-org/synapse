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

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin, login, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests.unittest import HomeserverTestCase


class PublicRoomsTestCase(HomeserverTestCase):
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

        user = self.register_user("alice", "pass")
        token = self.login(user, "pass")
        user2 = self.register_user("alice2", "pass")
        token2 = self.login(user2, "pass")
        user3 = self.register_user("alice3", "pass")
        token3 = self.login(user3, "pass")

        # Create 10 rooms
        for _ in range(3):
            self.helper.create_room_as(
                user,
                is_public=True,
                extra_content={"visibility": "public"},
                tok=token,
            )

        for _ in range(3):
            room_id = self.helper.create_room_as(
                user,
                is_public=True,
                extra_content={"visibility": "public"},
                tok=token,
            )
            self.helper.join(room_id, user2, tok=token2)

        for _ in range(4):
            room_id = self.helper.create_room_as(
                user,
                is_public=True,
                extra_content={"visibility": "public"},
                tok=token,
            )
            self.helper.join(room_id, user2, tok=token2)
            self.helper.join(room_id, user3, tok=token3)

    def test_no_limit(self) -> None:
        channel = self.make_request("GET", self.url)
        chunk = channel.json_body["chunk"]

        self.assertEquals(len(chunk), 10)

    def test_pagination_limit_1(self) -> None:
        returned_rooms = set()

        channel = None
        for i in range(10):
            next_batch = None if i == 0 else channel.json_body["next_batch"]
            since_query_str = f"&since={next_batch}" if next_batch else ""
            channel = self.make_request("GET", f"{self.url}?limit=1{since_query_str}")
            chunk = channel.json_body["chunk"]
            self.assertEquals(len(chunk), 1)
            print(chunk[0]["room_id"])
            self.assertTrue(chunk[0]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[0]["room_id"])

        self.assertNotIn("next_batch", channel.json_body)

        returned_rooms = set()
        returned_rooms.add(chunk[0]["room_id"])

        for i in range(9):
            print(i)
            prev_batch = channel.json_body["prev_batch"]
            channel = self.make_request("GET", f"{self.url}?limit=1&since={prev_batch}")
            chunk = channel.json_body["chunk"]
            self.assertEquals(len(chunk), 1)
            print(chunk[0]["room_id"])
            self.assertTrue(chunk[0]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[0]["room_id"])

    def test_pagination_limit_2(self) -> None:
        returned_rooms = set()

        channel = None
        for i in range(5):
            next_batch = None if i == 0 else channel.json_body["next_batch"]
            since_query_str = f"&since={next_batch}" if next_batch else ""
            channel = self.make_request("GET", f"{self.url}?limit=2{since_query_str}")
            chunk = channel.json_body["chunk"]
            self.assertEquals(len(chunk), 2)
            print(chunk[0]["room_id"])
            self.assertTrue(chunk[0]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[0]["room_id"])
            print(chunk[1]["room_id"])
            self.assertTrue(chunk[1]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[1]["room_id"])

        self.assertNotIn("next_batch", channel.json_body)

        returned_rooms = set()
        returned_rooms.add(chunk[0]["room_id"])
        returned_rooms.add(chunk[1]["room_id"])

        for i in range(4):
            print(i)
            prev_batch = channel.json_body["prev_batch"]
            channel = self.make_request("GET", f"{self.url}?limit=2&since={prev_batch}")
            chunk = channel.json_body["chunk"]
            self.assertEquals(len(chunk), 2)
            print(chunk[0]["room_id"])
            self.assertTrue(chunk[0]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[0]["room_id"])
            print(chunk[1]["room_id"])
            self.assertTrue(chunk[1]["room_id"] not in returned_rooms)
            returned_rooms.add(chunk[1]["room_id"])
