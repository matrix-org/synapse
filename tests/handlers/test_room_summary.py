#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from synapse.api.constants import EventTypes, HistoryVisibility, JoinRules
from synapse.api.errors import NotFoundError
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.server import HomeServer

from tests import unittest


class SpaceSummaryTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.hs = hs
        self.handler = self.hs.get_room_summary_handler()

        # Create a user.
        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

        # Create a simple room.
        self.room = self.helper.create_room_as(self.user, tok=self.token)
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )

    def test_own_room(self):
        """Test a simple room created by the requester."""
        result = self.get_success(self.handler.get_room_summary(self.user, self.room))
        self.assertEqual(result.get("room_id"), self.room)

    def test_visibility(self):
        """A user not in a private room cannot get its summary."""
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")

        # The user cannot see the room.
        self.get_failure(self.handler.get_room_summary(user2, self.room), NotFoundError)

        # If the room is made world-readable it should return a result.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.WORLD_READABLE},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)

        # Make it not world-readable again and confirm it results in an error.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.token,
        )
        self.get_failure(self.handler.get_room_summary(user2, self.room), NotFoundError)

        # If the room is made public it should return a result.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.PUBLIC},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)

        # Join the space, make it invite-only again and results should be returned.
        self.helper.join(self.room, user2, tok=token2)
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)
