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
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.rest.client import login, notifications, receipts, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests.test_utils import simple_async_mock
from tests.unittest import HomeserverTestCase


class HTTPPusherTests(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        receipts.register_servlets,
        notifications.register_servlets,
    ]

    def prepare(
        self, reactor: MemoryReactor, clock: Clock, homeserver: HomeServer
    ) -> None:
        self.store = homeserver.get_datastores().main
        self.module_api = homeserver.get_module_api()
        self.event_creation_handler = homeserver.get_event_creation_handler()
        self.sync_handler = homeserver.get_sync_handler()
        self.auth_handler = homeserver.get_auth_handler()

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        # Mock out the calls over federation.
        fed_transport_client = Mock(spec=["send_transaction"])
        fed_transport_client.send_transaction = simple_async_mock({})

        return self.setup_test_homeserver(
            federation_transport_client=fed_transport_client,
        )

    def test_notify_for_local_invites(self) -> None:
        """
        Local users will get notified for invites
        """

        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # Check we start with no pushes
        channel = self.make_request(
            "GET",
            "/notifications",
            access_token=other_access_token,
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(len(channel.json_body["notifications"]), 0, channel.json_body)

        # Send an invite
        self.helper.invite(room=room, src=user_id, targ=other_user_id, tok=access_token)

        # We should have a notification now
        channel = self.make_request(
            "GET",
            "/notifications",
            access_token=other_access_token,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(len(channel.json_body["notifications"]), 1, channel.json_body)
        self.assertEqual(
            channel.json_body["notifications"][0]["event"]["content"]["membership"],
            "invite",
            channel.json_body,
        )
