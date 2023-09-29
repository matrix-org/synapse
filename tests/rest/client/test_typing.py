# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector
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

"""Tests REST events for /rooms paths."""

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EduTypes
from synapse.rest.client import room
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest

PATH_PREFIX = "/_matrix/client/api/v1"


class RoomTypingTestCase(unittest.HomeserverTestCase):
    """Tests /rooms/$room_id/typing/$user_id REST API."""

    user_id = "@sid:red"

    user = UserID.from_string(user_id)
    servlets = [room.register_servlets]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        hs = self.setup_test_homeserver("red")
        self.event_source = hs.get_event_sources().sources.typing
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.room_id = self.helper.create_room_as(self.user_id)
        # Need another user to make notifications actually work
        self.helper.join(self.room_id, user="@jim:red")

    def test_set_typing(self) -> None:
        channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.assertEqual(200, channel.code)

        self.assertEqual(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(
                user=UserID.from_string(self.user_id),
                from_key=0,
                # Limit is unused.
                limit=0,
                room_ids=[self.room_id],
                is_guest=False,
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": self.room_id,
                    "content": {"user_ids": [self.user_id]},
                }
            ],
        )

    def test_set_not_typing(self) -> None:
        channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": false}',
        )
        self.assertEqual(200, channel.code)

    def test_typing_timeout(self) -> None:
        channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.assertEqual(200, channel.code)

        self.assertEqual(self.event_source.get_current_key(), 1)

        self.reactor.advance(36)

        self.assertEqual(self.event_source.get_current_key(), 2)

        channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (self.room_id, self.user_id),
            b'{"typing": true, "timeout": 30000}',
        )
        self.assertEqual(200, channel.code)

        self.assertEqual(self.event_source.get_current_key(), 3)
