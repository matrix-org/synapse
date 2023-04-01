# Copyright 2019 The Matrix.org Foundation C.I.C.
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

from collections import Counter
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
import synapse.storage
from synapse.api.constants import EventTypes, JoinRules
from synapse.api.room_versions import RoomVersions
from synapse.rest.client import knock, login, room
from synapse.server import HomeServer
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest


class ExfiltrateData(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        room.register_servlets,
        knock.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.admin_handler = hs.get_admin_handler()
        self._store = hs.get_datastores().main

        self.user1 = self.register_user("user1", "password")
        self.token1 = self.login("user1", "password")

        self.user2 = self.register_user("user2", "password")
        self.token2 = self.login("user2", "password")

    def test_single_public_joined_room(self) -> None:
        """Test that we write *all* events for a public room"""
        room_id = self.helper.create_room_as(
            self.user1, tok=self.token1, is_public=True
        )
        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.join(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Hello again!", tok=self.token1)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_called()

        # Since we can see all events there shouldn't be any extremities, so no
        # state should be written
        writer.write_state.assert_not_called()

        # Collect all events that were written
        written_events = []
        for (called_room_id, events), _ in writer.write_events.call_args_list:
            self.assertEqual(called_room_id, room_id)
            written_events.extend(events)

        # Check that the right number of events were written
        counter = Counter(
            (event.type, getattr(event, "state_key", None)) for event in written_events
        )
        self.assertEqual(counter[(EventTypes.Message, None)], 2)
        self.assertEqual(counter[(EventTypes.Member, self.user1)], 1)
        self.assertEqual(counter[(EventTypes.Member, self.user2)], 1)

    def test_single_private_joined_room(self) -> None:
        """Tests that we correctly write state when we can't see all events in
        a room.
        """
        room_id = self.helper.create_room_as(self.user1, tok=self.token1)
        self.helper.send_state(
            room_id,
            EventTypes.RoomHistoryVisibility,
            body={"history_visibility": "joined"},
            tok=self.token1,
        )
        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.join(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Hello again!", tok=self.token1)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_called()

        # Since we can't see all events there should be one extremity.
        writer.write_state.assert_called_once()

        # Collect all events that were written
        written_events = []
        for (called_room_id, events), _ in writer.write_events.call_args_list:
            self.assertEqual(called_room_id, room_id)
            written_events.extend(events)

        # Check that the right number of events were written
        counter = Counter(
            (event.type, getattr(event, "state_key", None)) for event in written_events
        )
        self.assertEqual(counter[(EventTypes.Message, None)], 1)
        self.assertEqual(counter[(EventTypes.Member, self.user1)], 1)
        self.assertEqual(counter[(EventTypes.Member, self.user2)], 1)

    def test_single_left_room(self) -> None:
        """Tests that we don't see events in the room after we leave."""
        room_id = self.helper.create_room_as(self.user1, tok=self.token1)
        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.join(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Hello again!", tok=self.token1)
        self.helper.leave(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Helloooooo!", tok=self.token1)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_called()

        # Since we can see all events there shouldn't be any extremities, so no
        # state should be written
        writer.write_state.assert_not_called()

        written_events = []
        for (called_room_id, events), _ in writer.write_events.call_args_list:
            self.assertEqual(called_room_id, room_id)
            written_events.extend(events)

        # Check that the right number of events were written
        counter = Counter(
            (event.type, getattr(event, "state_key", None)) for event in written_events
        )
        self.assertEqual(counter[(EventTypes.Message, None)], 2)
        self.assertEqual(counter[(EventTypes.Member, self.user1)], 1)
        self.assertEqual(counter[(EventTypes.Member, self.user2)], 2)

    def test_single_left_rejoined_private_room(self) -> None:
        """Tests that see the correct events in private rooms when we
        repeatedly join and leave.
        """
        room_id = self.helper.create_room_as(self.user1, tok=self.token1)
        self.helper.send_state(
            room_id,
            EventTypes.RoomHistoryVisibility,
            body={"history_visibility": "joined"},
            tok=self.token1,
        )
        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.join(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Hello again!", tok=self.token1)
        self.helper.leave(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Helloooooo!", tok=self.token1)
        self.helper.join(room_id, self.user2, tok=self.token2)
        self.helper.send(room_id, body="Helloooooo!!", tok=self.token1)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_called_once()

        # Since we joined/left/joined again we expect there to be two gaps.
        self.assertEqual(writer.write_state.call_count, 2)

        written_events = []
        for (called_room_id, events), _ in writer.write_events.call_args_list:
            self.assertEqual(called_room_id, room_id)
            written_events.extend(events)

        # Check that the right number of events were written
        counter = Counter(
            (event.type, getattr(event, "state_key", None)) for event in written_events
        )
        self.assertEqual(counter[(EventTypes.Message, None)], 2)
        self.assertEqual(counter[(EventTypes.Member, self.user1)], 1)
        self.assertEqual(counter[(EventTypes.Member, self.user2)], 3)

    def test_invite(self) -> None:
        """Tests that pending invites get handled correctly."""
        room_id = self.helper.create_room_as(self.user1, tok=self.token1)
        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.invite(room_id, self.user1, self.user2, tok=self.token1)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_not_called()
        writer.write_state.assert_not_called()
        writer.write_invite.assert_called_once()

        args = writer.write_invite.call_args[0]
        self.assertEqual(args[0], room_id)
        self.assertEqual(args[1].content["membership"], "invite")
        self.assertTrue(args[2])  # Assert there is at least one bit of state

    def test_knock(self) -> None:
        """Tests that knock get handled correctly."""
        # create a knockable v7 room
        room_id = self.helper.create_room_as(
            self.user1, room_version=RoomVersions.V7.identifier, tok=self.token1
        )
        self.helper.send_state(
            room_id,
            EventTypes.JoinRules,
            {"join_rule": JoinRules.KNOCK},
            tok=self.token1,
        )

        self.helper.send(room_id, body="Hello!", tok=self.token1)
        self.helper.knock(room_id, self.user2, tok=self.token2)

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_not_called()
        writer.write_state.assert_not_called()
        writer.write_knock.assert_called_once()

        args = writer.write_knock.call_args[0]
        self.assertEqual(args[0], room_id)
        self.assertEqual(args[1].content["membership"], "knock")
        self.assertTrue(args[2])  # Assert there is at least one bit of state

    def test_profile(self) -> None:
        """Tests that user profile get exported."""
        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_not_called()
        writer.write_profile.assert_called_once()

        # check only a few values, not all available
        args = writer.write_profile.call_args[0]
        self.assertEqual(args[0]["name"], self.user2)
        self.assertIn("displayname", args[0])
        self.assertIn("avatar_url", args[0])
        self.assertIn("threepids", args[0])
        self.assertIn("external_ids", args[0])
        self.assertIn("creation_ts", args[0])

    def test_devices(self) -> None:
        """Tests that user devices get exported."""
        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_not_called()
        writer.write_devices.assert_called_once()

        args = writer.write_devices.call_args[0]
        self.assertEqual(len(args[0]), 1)
        self.assertEqual(args[0][0]["user_id"], self.user2)
        self.assertIn("device_id", args[0][0])
        self.assertIsNone(args[0][0]["display_name"])
        self.assertIsNone(args[0][0]["last_seen_user_agent"])
        self.assertIsNone(args[0][0]["last_seen_ts"])
        self.assertIsNone(args[0][0]["last_seen_ip"])

    def test_connections(self) -> None:
        """Tests that user sessions / connections get exported."""
        # Insert a user IP
        self.get_success(
            self._store.insert_client_ip(
                self.user2, "access_token", "ip", "user_agent", "MY_DEVICE"
            )
        )

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_events.assert_not_called()
        writer.write_connections.assert_called_once()

        args = writer.write_connections.call_args[0]
        self.assertEqual(len(args[0]), 1)
        self.assertEqual(args[0][0]["ip"], "ip")
        self.assertEqual(args[0][0]["user_agent"], "user_agent")
        self.assertGreater(args[0][0]["last_seen"], 0)
        self.assertNotIn("access_token", args[0][0])

    def test_account_data(self) -> None:
        """Tests that user account data get exported."""
        # add account data
        self.get_success(
            self._store.add_account_data_for_user(self.user2, "m.global", {"a": 1})
        )
        self.get_success(
            self._store.add_account_data_to_room(
                self.user2, "test_room", "m.per_room", {"b": 2}
            )
        )

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        # two calls, one call for user data and one call for room data
        writer.write_account_data.assert_called()

        args = writer.write_account_data.call_args_list[0][0]
        self.assertEqual(args[0], "global")
        self.assertEqual(args[1]["m.global"]["a"], 1)

        args = writer.write_account_data.call_args_list[1][0]
        self.assertEqual(args[0], "test_room")
        self.assertEqual(args[1]["m.per_room"]["b"], 2)

    def test_media_ids(self) -> None:
        """Tests that media's metadata get exported."""

        self.get_success(
            self._store.store_local_media(
                media_id="media_1",
                media_type="image/png",
                time_now_ms=self.clock.time_msec(),
                upload_name=None,
                media_length=50,
                user_id=UserID.from_string(self.user2),
            )
        )

        writer = Mock()

        self.get_success(self.admin_handler.export_user_data(self.user2, writer))

        writer.write_media_id.assert_called_once()

        args = writer.write_media_id.call_args[0]
        self.assertEqual(args[0], "media_1")
        self.assertEqual(args[1]["media_id"], "media_1")
        self.assertEqual(args[1]["media_length"], 50)
        self.assertGreater(args[1]["created_ts"], 0)
        self.assertIsNone(args[1]["upload_name"])
        self.assertIsNone(args[1]["last_access_ts"])
