# Copyright 2023 Beeper
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

import synapse.rest.admin
from synapse.api.constants import EventTypes
from synapse.rest import admin
from synapse.rest.client import login, read_marker, register, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest

ONE_HOUR_MS = 3600000
ONE_DAY_MS = ONE_HOUR_MS * 24


class ReadMarkerTestCase(unittest.HomeserverTestCase):
    servlets = [
        login.register_servlets,
        register.register_servlets,
        read_marker.register_servlets,
        room.register_servlets,
        synapse.rest.admin.register_servlets,
        admin.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        # merge this default retention config with anything that was specified in
        # @override_config
        retention_config = {
            "enabled": True,
            "allowed_lifetime_min": ONE_DAY_MS,
            "allowed_lifetime_max": ONE_DAY_MS * 3,
        }
        retention_config.update(config.get("retention", {}))
        config["retention"] = retention_config

        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.owner = self.register_user("owner", "pass")
        self.owner_tok = self.login("owner", "pass")
        self.store = self.hs.get_datastores().main
        self.clock = self.hs.get_clock()

    def test_send_read_marker(self) -> None:
        room_id = self.helper.create_room_as(self.owner, tok=self.owner_tok)

        def send_message() -> str:
            res = self.helper.send(room_id=room_id, body="1", tok=self.owner_tok)
            return res["event_id"]

        # Test setting the read marker on the room
        event_id_1 = send_message()

        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/read_markers",
            content={
                "m.fully_read": event_id_1,
            },
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

        # Test moving the read marker to a newer event
        event_id_2 = send_message()
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/read_markers",
            content={
                "m.fully_read": event_id_2,
            },
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)

    def test_send_read_marker_missing_previous_event(self) -> None:
        """
        Test moving a read marker from an event that previously existed but was
        later removed due to retention rules.
        """

        room_id = self.helper.create_room_as(self.owner, tok=self.owner_tok)

        # Set retention rule on the room so we remove old events to test this case
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.Retention,
            body={"max_lifetime": ONE_DAY_MS},
            tok=self.owner_tok,
        )

        def send_message() -> str:
            res = self.helper.send(room_id=room_id, body="1", tok=self.owner_tok)
            return res["event_id"]

        # Test setting the read marker on the room
        event_id_1 = send_message()

        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/read_markers",
            content={
                "m.fully_read": event_id_1,
            },
            access_token=self.owner_tok,
        )

        # Send a second message (retention will not remove the latest event ever)
        send_message()
        # And then advance so retention rules remove the first event (where the marker is)
        self.reactor.advance(ONE_DAY_MS * 2 / 1000)

        event = self.get_success(self.store.get_event(event_id_1, allow_none=True))
        assert event is None

        # Test moving the read marker to a newer event
        event_id_2 = send_message()
        channel = self.make_request(
            "POST",
            "/rooms/!abc:beep/read_markers",
            content={
                "m.fully_read": event_id_2,
            },
            access_token=self.owner_tok,
        )
        self.assertEqual(channel.code, 200, channel.result)
