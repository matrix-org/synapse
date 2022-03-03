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
from typing import Optional

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventContentFields, EventTypes, RoomTypes
from synapse.config.server import DEFAULT_ROOM_VERSION
from synapse.rest import admin
from synapse.rest.client import login, room, room_upgrade_rest_servlet
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.server import FakeChannel


class UpgradeRoomTest(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        room_upgrade_rest_servlet.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.creator = self.register_user("creator", "pass")
        self.creator_token = self.login(self.creator, "pass")

        self.other = self.register_user("user", "pass")
        self.other_token = self.login(self.other, "pass")

        self.room_id = self.helper.create_room_as(self.creator, tok=self.creator_token)
        self.helper.join(self.room_id, self.other, tok=self.other_token)

    def _upgrade_room(
        self, token: Optional[str] = None, room_id: Optional[str] = None
    ) -> FakeChannel:
        # We never want a cached response.
        self.reactor.advance(5 * 60 + 1)

        if room_id is None:
            room_id = self.room_id

        return self.make_request(
            "POST",
            f"/_matrix/client/r0/rooms/{room_id}/upgrade",
            # This will upgrade a room to the same version, but that's fine.
            content={"new_version": DEFAULT_ROOM_VERSION},
            access_token=token or self.creator_token,
        )

    def test_upgrade(self) -> None:
        """
        Upgrading a room should work fine.
        """
        channel = self._upgrade_room()
        self.assertEqual(200, channel.code, channel.result)
        self.assertIn("replacement_room", channel.json_body)

    def test_not_in_room(self) -> None:
        """
        Upgrading a room should work fine.
        """
        # THe user isn't in the room.
        roomless = self.register_user("roomless", "pass")
        roomless_token = self.login(roomless, "pass")

        channel = self._upgrade_room(roomless_token)
        self.assertEqual(403, channel.code, channel.result)

    def test_power_levels(self) -> None:
        """
        Another user can upgrade the room if their power level is increased.
        """
        # The other user doesn't have the proper power level.
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(403, channel.code, channel.result)

        # Increase the power levels so that this user can upgrade.
        power_levels = self.helper.get_state(
            self.room_id,
            "m.room.power_levels",
            tok=self.creator_token,
        )
        power_levels["users"][self.other] = 100
        self.helper.send_state(
            self.room_id,
            "m.room.power_levels",
            body=power_levels,
            tok=self.creator_token,
        )

        # The upgrade should succeed!
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(200, channel.code, channel.result)

    def test_power_levels_user_default(self) -> None:
        """
        Another user can upgrade the room if the default power level for users is increased.
        """
        # The other user doesn't have the proper power level.
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(403, channel.code, channel.result)

        # Increase the power levels so that this user can upgrade.
        power_levels = self.helper.get_state(
            self.room_id,
            "m.room.power_levels",
            tok=self.creator_token,
        )
        power_levels["users_default"] = 100
        self.helper.send_state(
            self.room_id,
            "m.room.power_levels",
            body=power_levels,
            tok=self.creator_token,
        )

        # The upgrade should succeed!
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(200, channel.code, channel.result)

    def test_power_levels_tombstone(self) -> None:
        """
        Another user can upgrade the room if they can send the tombstone event.
        """
        # The other user doesn't have the proper power level.
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(403, channel.code, channel.result)

        # Increase the power levels so that this user can upgrade.
        power_levels = self.helper.get_state(
            self.room_id,
            "m.room.power_levels",
            tok=self.creator_token,
        )
        power_levels["events"]["m.room.tombstone"] = 0
        self.helper.send_state(
            self.room_id,
            "m.room.power_levels",
            body=power_levels,
            tok=self.creator_token,
        )

        # The upgrade should succeed!
        channel = self._upgrade_room(self.other_token)
        self.assertEqual(200, channel.code, channel.result)

        power_levels = self.helper.get_state(
            self.room_id,
            "m.room.power_levels",
            tok=self.creator_token,
        )
        self.assertNotIn(self.other, power_levels["users"])

    def test_space(self) -> None:
        """Test upgrading a space."""

        # Create a space.
        space_id = self.helper.create_room_as(
            self.creator,
            tok=self.creator_token,
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )

        # Add the room as a child room.
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body={"via": [self.hs.hostname]},
            tok=self.creator_token,
            state_key=self.room_id,
        )

        # Also add a room that was removed.
        old_room_id = "!notaroom:" + self.hs.hostname
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body={},
            tok=self.creator_token,
            state_key=old_room_id,
        )

        # Upgrade the room!
        channel = self._upgrade_room(room_id=space_id)
        self.assertEqual(200, channel.code, channel.result)
        self.assertIn("replacement_room", channel.json_body)

        new_space_id = channel.json_body["replacement_room"]

        state_ids = self.get_success(self.store.get_current_state_ids(new_space_id))

        # Ensure the new room is still a space.
        create_event = self.get_success(
            self.store.get_event(state_ids[(EventTypes.Create, "")])
        )
        self.assertEqual(
            create_event.content.get(EventContentFields.ROOM_TYPE), RoomTypes.SPACE
        )

        # The child link should have been copied over.
        self.assertIn((EventTypes.SpaceChild, self.room_id), state_ids)
        # The child that was removed should not be copied over.
        self.assertNotIn((EventTypes.SpaceChild, old_room_id), state_ids)
