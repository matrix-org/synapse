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
from synapse.types import PublicRoom, ThirdPartyInstanceID
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
            network_tuple: Optional[ThirdPartyInstanceID],
            search_filter: Optional[dict],
            limit: Optional[int],
            bounds: Tuple[Optional[int], Optional[str]],
            forwards: bool,
        ) -> List[PublicRoom]:
            room1 = PublicRoom(
                room_id="!one_members:module1",
                num_joined_members=1,
                world_readable=True,
                guest_can_join=False,
            )
            room3 = PublicRoom(
                room_id="!three_members:module1",
                num_joined_members=3,
                world_readable=True,
                guest_can_join=False,
            )
            room3_2 = PublicRoom(
                room_id="!three_members_2:module1",
                num_joined_members=3,
                world_readable=True,
                guest_can_join=False,
            )

            (last_joined_members, last_room_id) = bounds

            print(f"cb {forwards} {bounds}")

            result = [room1, room3, room3_2]

            if last_joined_members is not None:
                if forwards:
                    result = list(
                        filter(
                            lambda r: r.num_joined_members <= last_joined_members,
                            result,
                        )
                    )
                else:
                    result = list(
                        filter(
                            lambda r: r.num_joined_members >= last_joined_members,
                            result,
                        )
                    )

            print([r.room_id for r in result])

            if last_room_id is not None:
                new_res = []
                for r in result:
                    if r.room_id == last_room_id:
                        break
                    new_res.append(r)
                result = new_res

            if forwards:
                result.reverse()

            if limit is not None:
                result = result[:limit]

            return result

            # if forwards:
            #     if limit == 2:
            #         if last_joined_members is None:
            #             return [room3_2, room3]
            #         elif last_joined_members == 3:
            #             if last_room_id == room3_2.room_id:
            #                 return [room3, room1]
            #             if last_room_id == room3.room_id:
            #                 return [room1]
            #         elif last_joined_members < 3:
            #             return [room1]
            #     return [room3_2, room3, room1]
            # else:
            #     if (
            #         limit == 2
            #         and last_joined_members == 3
            #         and last_room_id == room3.room_id
            #     ):
            #         return [room3_2]
            #     return [room1, room3, room3_2]

        async def cb2(
            network_tuple: Optional[ThirdPartyInstanceID],
            search_filter: Optional[dict],
            limit: Optional[int],
            bounds: Tuple[Optional[int], Optional[str]],
            forwards: bool,
        ) -> List[PublicRoom]:
            room3 = PublicRoom(
                room_id="!three_members:module2",
                num_joined_members=3,
                world_readable=True,
                guest_can_join=False,
            )

            result = [room3]

            (last_joined_members, last_room_id) = bounds

            print(f"cb2 {forwards} {bounds}")

            if last_joined_members is not None:
                if forwards:
                    result = list(
                        filter(
                            lambda r: r.num_joined_members <= last_joined_members,
                            result,
                        )
                    )
                else:
                    result = list(
                        filter(
                            lambda r: r.num_joined_members >= last_joined_members,
                            result,
                        )
                    )

            print([r.room_id for r in result])

            if last_room_id is not None:
                new_res = []
                for r in result:
                    if r.room_id == last_room_id:
                        break
                    new_res.append(r)
                result = new_res

            if forwards:
                result.reverse()

            if limit is not None:
                result = result[:limit]

            return result

        self._module_api.register_public_rooms_callbacks(fetch_public_rooms=cb2)
        self._module_api.register_public_rooms_callbacks(fetch_public_rooms=cb)

        user = self.register_user("alice", "pass")
        token = self.login(user, "pass")

        user2 = self.register_user("alice2", "pass")
        token2 = self.login(user2, "pass")

        user3 = self.register_user("alice3", "pass")
        token3 = self.login(user3, "pass")

        # Create a room with 2 people
        room_id = self.helper.create_room_as(
            user,
            is_public=True,
            extra_content={"visibility": "public"},
            tok=token,
        )
        self.helper.join(room_id, user2, tok=token2)

        # Create a room with 3 people
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

        self.assertEquals(len(chunk), 6)
        for i in range(4):
            self.assertEquals(chunk[i]["num_joined_members"], 3)
        self.assertEquals(chunk[4]["num_joined_members"], 2)
        self.assertEquals(chunk[5]["num_joined_members"], 1)

    def test_pagination(self) -> None:
        returned_three_members_rooms = set()

        next_batch = None
        for i in range(4):
            since_query_str = f"&since={next_batch}" if next_batch else ""
            channel = self.make_request("GET", f"{self.url}?limit=1{since_query_str}")
            chunk = channel.json_body["chunk"]
            self.assertEquals(chunk[0]["num_joined_members"], 3)
            self.assertTrue(chunk[0]["room_id"] not in returned_three_members_rooms)
            returned_three_members_rooms.add(chunk[0]["room_id"])
            next_batch = channel.json_body["next_batch"]

        channel = self.make_request("GET", f"{self.url}?limit=1&since={next_batch}")
        chunk = channel.json_body["chunk"]
        self.assertEquals(chunk[0]["num_joined_members"], 2)
        next_batch = channel.json_body["next_batch"]

        channel = self.make_request("GET", f"{self.url}?limit=1&since={next_batch}")
        chunk = channel.json_body["chunk"]
        self.assertEquals(chunk[0]["num_joined_members"], 1)
        prev_batch = channel.json_body["prev_batch"]

        # channel = self.make_request("GET", f"{self.url}?limit=1&since={prev_batch}")
        # chunk = channel.json_body["chunk"]
        # print(chunk)
        # self.assertEquals(chunk[0]["num_joined_members"], 2)
        # prev_batch = channel.json_body["prev_batch"]

        # returned_three_members_rooms = set()
        # for i in range(4):
        #     channel = self.make_request("GET", f"{self.url}?limit=1&since={prev_batch}")
        #     chunk = channel.json_body["chunk"]
        #     self.assertEquals(chunk[0]["num_joined_members"], 3)
        #     self.assertTrue(chunk[0]["room_id"] not in returned_three_members_rooms)
        #     returned_three_members_rooms.add(chunk[0]["room_id"])
        #     prev_batch = channel.json_body["prev_batch"]
