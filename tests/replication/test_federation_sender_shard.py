# Copyright 2020 The Matrix.org Foundation C.I.C.
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
import logging
from unittest.mock import Mock

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events.builder import EventBuilderFactory
from synapse.rest.admin import register_servlets_for_client_rest_resource
from synapse.rest.client.v1 import login, room
from synapse.types import UserID, create_requester

from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.test_utils import make_awaitable

logger = logging.getLogger(__name__)


class FederationSenderTestCase(BaseMultiWorkerStreamTestCase):
    servlets = [
        login.register_servlets,
        register_servlets_for_client_rest_resource,
        room.register_servlets,
    ]

    def default_config(self):
        conf = super().default_config()
        conf["send_federation"] = False
        return conf

    def test_send_event_single_sender(self):
        """Test that using a single federation sender worker correctly sends a
        new event.
        """
        mock_client = Mock(spec=["put_json"])
        mock_client.put_json.return_value = make_awaitable({})

        self.make_worker_hs(
            "synapse.app.federation_sender",
            {"send_federation": False},
            federation_http_client=mock_client,
        )

        user = self.register_user("user", "pass")
        token = self.login("user", "pass")

        room = self.create_room_with_remote_server(user, token)

        mock_client.put_json.reset_mock()

        self.create_and_send_event(room, UserID.from_string(user))
        self.replicate()

        # Assert that the event was sent out over federation.
        mock_client.put_json.assert_called()
        self.assertEqual(mock_client.put_json.call_args[0][0], "other_server")
        self.assertTrue(mock_client.put_json.call_args[1]["data"].get("pdus"))

    def test_send_event_sharded(self):
        """Test that using two federation sender workers correctly sends
        new events.
        """
        mock_client1 = Mock(spec=["put_json"])
        mock_client1.put_json.return_value = make_awaitable({})
        self.make_worker_hs(
            "synapse.app.federation_sender",
            {
                "send_federation": True,
                "worker_name": "sender1",
                "federation_sender_instances": ["sender1", "sender2"],
            },
            federation_http_client=mock_client1,
        )

        mock_client2 = Mock(spec=["put_json"])
        mock_client2.put_json.return_value = make_awaitable({})
        self.make_worker_hs(
            "synapse.app.federation_sender",
            {
                "send_federation": True,
                "worker_name": "sender2",
                "federation_sender_instances": ["sender1", "sender2"],
            },
            federation_http_client=mock_client2,
        )

        user = self.register_user("user2", "pass")
        token = self.login("user2", "pass")

        sent_on_1 = False
        sent_on_2 = False
        for i in range(20):
            server_name = "other_server_%d" % (i,)
            room = self.create_room_with_remote_server(user, token, server_name)
            mock_client1.reset_mock()  # type: ignore[attr-defined]
            mock_client2.reset_mock()  # type: ignore[attr-defined]

            self.create_and_send_event(room, UserID.from_string(user))
            self.replicate()

            if mock_client1.put_json.called:
                sent_on_1 = True
                mock_client2.put_json.assert_not_called()
                self.assertEqual(mock_client1.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client1.put_json.call_args[1]["data"].get("pdus"))
            elif mock_client2.put_json.called:
                sent_on_2 = True
                mock_client1.put_json.assert_not_called()
                self.assertEqual(mock_client2.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client2.put_json.call_args[1]["data"].get("pdus"))
            else:
                raise AssertionError(
                    "Expected send transaction from one or the other sender"
                )

            if sent_on_1 and sent_on_2:
                break

        self.assertTrue(sent_on_1)
        self.assertTrue(sent_on_2)

    def test_send_typing_sharded(self):
        """Test that using two federation sender workers correctly sends
        new typing EDUs.
        """
        mock_client1 = Mock(spec=["put_json"])
        mock_client1.put_json.return_value = make_awaitable({})
        self.make_worker_hs(
            "synapse.app.federation_sender",
            {
                "send_federation": True,
                "worker_name": "sender1",
                "federation_sender_instances": ["sender1", "sender2"],
            },
            federation_http_client=mock_client1,
        )

        mock_client2 = Mock(spec=["put_json"])
        mock_client2.put_json.return_value = make_awaitable({})
        self.make_worker_hs(
            "synapse.app.federation_sender",
            {
                "send_federation": True,
                "worker_name": "sender2",
                "federation_sender_instances": ["sender1", "sender2"],
            },
            federation_http_client=mock_client2,
        )

        user = self.register_user("user3", "pass")
        token = self.login("user3", "pass")

        typing_handler = self.hs.get_typing_handler()

        sent_on_1 = False
        sent_on_2 = False
        for i in range(20):
            server_name = "other_server_%d" % (i,)
            room = self.create_room_with_remote_server(user, token, server_name)
            mock_client1.reset_mock()  # type: ignore[attr-defined]
            mock_client2.reset_mock()  # type: ignore[attr-defined]

            self.get_success(
                typing_handler.started_typing(
                    target_user=UserID.from_string(user),
                    requester=create_requester(user),
                    room_id=room,
                    timeout=20000,
                )
            )

            self.replicate()

            if mock_client1.put_json.called:
                sent_on_1 = True
                mock_client2.put_json.assert_not_called()
                self.assertEqual(mock_client1.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client1.put_json.call_args[1]["data"].get("edus"))
            elif mock_client2.put_json.called:
                sent_on_2 = True
                mock_client1.put_json.assert_not_called()
                self.assertEqual(mock_client2.put_json.call_args[0][0], server_name)
                self.assertTrue(mock_client2.put_json.call_args[1]["data"].get("edus"))
            else:
                raise AssertionError(
                    "Expected send transaction from one or the other sender"
                )

            if sent_on_1 and sent_on_2:
                break

        self.assertTrue(sent_on_1)
        self.assertTrue(sent_on_2)

    def create_room_with_remote_server(self, user, token, remote_server="other_server"):
        room = self.helper.create_room_as(user, tok=token)
        store = self.hs.get_datastore()
        federation = self.hs.get_federation_handler()

        prev_event_ids = self.get_success(store.get_latest_event_ids_in_room(room))
        room_version = self.get_success(store.get_room_version(room))

        factory = EventBuilderFactory(self.hs)
        factory.hostname = remote_server

        user_id = UserID("user", remote_server).to_string()

        event_dict = {
            "type": EventTypes.Member,
            "state_key": user_id,
            "content": {"membership": Membership.JOIN},
            "sender": user_id,
            "room_id": room,
        }

        builder = factory.for_room_version(room_version, event_dict)
        join_event = self.get_success(
            builder.build(prev_event_ids=prev_event_ids, auth_event_ids=None)
        )

        self.get_success(
            federation.on_send_membership_event(
                remote_server, join_event, RoomVersions.V6
            )
        )
        self.replicate()

        return room
