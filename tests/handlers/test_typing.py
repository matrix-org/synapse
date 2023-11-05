# Copyright 2014-2016 OpenMarket Ltd
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


import json
from typing import Dict, List, Set
from unittest.mock import ANY, AsyncMock, Mock, call

from netaddr import IPSet

from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

from synapse.api.constants import EduTypes
from synapse.api.errors import AuthError
from synapse.federation.transport.server import TransportLayerServer
from synapse.handlers.typing import TypingWriterHandler
from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
from synapse.server import HomeServer
from synapse.types import JsonDict, Requester, StreamKeyType, UserID, create_requester
from synapse.util import Clock

from tests import unittest
from tests.server import ThreadedMemoryReactorClock
from tests.unittest import override_config

# Some local users to test with
U_APPLE = UserID.from_string("@apple:test")
U_BANANA = UserID.from_string("@banana:test")

# Remote user
U_ONION = UserID.from_string("@onion:farm")

# Test room id
ROOM_ID = "a-room"

# Room we're not in
OTHER_ROOM_ID = "another-room"


def _expect_edu_transaction(
    edu_type: str, content: JsonDict, origin: str = "test"
) -> JsonDict:
    return {
        "origin": origin,
        "origin_server_ts": 1000000,
        "pdus": [],
        "edus": [{"edu_type": edu_type, "content": content}],
    }


def _make_edu_transaction_json(edu_type: str, content: JsonDict) -> bytes:
    return json.dumps(_expect_edu_transaction(edu_type, content)).encode("utf8")


class TypingNotificationsTestCase(unittest.HomeserverTestCase):
    def make_homeserver(
        self,
        reactor: ThreadedMemoryReactorClock,
        clock: Clock,
    ) -> HomeServer:
        # we mock out the keyring so as to skip the authentication check on the
        # federation API call.
        mock_keyring = Mock(spec=["verify_json_for_server"])
        mock_keyring.verify_json_for_server = AsyncMock(return_value=True)

        # we mock out the federation client too
        self.mock_federation_client = AsyncMock(spec=["put_json"])
        self.mock_federation_client.put_json.return_value = (200, "OK")
        self.mock_federation_client.agent = MatrixFederationAgent(
            reactor,
            tls_client_options_factory=None,
            user_agent=b"SynapseInTrialTest/0.0.0",
            ip_allowlist=None,
            ip_blocklist=IPSet(),
        )

        # the tests assume that we are starting at unix time 1000
        reactor.pump((1000,))

        self.mock_hs_notifier = Mock()
        hs = self.setup_test_homeserver(
            notifier=self.mock_hs_notifier,
            federation_http_client=self.mock_federation_client,
            keyring=mock_keyring,
            replication_streams={},
        )

        return hs

    def create_resource_dict(self) -> Dict[str, Resource]:
        d = super().create_resource_dict()
        d["/_matrix/federation"] = TransportLayerServer(self.hs)
        return d

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.on_new_event = self.mock_hs_notifier.on_new_event

        # hs.get_typing_handler will return a TypingWriterHandler when calling it
        # from the main process, and a FollowerTypingHandler on workers.
        # We rely on methods only available on the former, so assert we have the
        # correct type here. We have to assign self.handler after the assert,
        # otherwise mypy will treat it as a FollowerTypingHandler
        handler = hs.get_typing_handler()
        assert isinstance(handler, TypingWriterHandler)
        self.handler = handler

        self.event_source = hs.get_event_sources().sources.typing

        self.datastore = hs.get_datastores().main

        self.datastore.get_device_updates_by_remote = AsyncMock(  # type: ignore[method-assign]
            return_value=(0, [])
        )

        self.datastore.get_destination_last_successful_stream_ordering = AsyncMock(  # type: ignore[method-assign]
            return_value=None
        )

        self.datastore.get_received_txn_response = AsyncMock(  # type: ignore[method-assign]
            return_value=None
        )

        self.room_members: List[UserID] = []

        async def check_user_in_room(room_id: str, requester: Requester) -> None:
            if requester.user.to_string() not in [
                u.to_string() for u in self.room_members
            ]:
                raise AuthError(401, "User is not in the room")
            return None

        hs.get_auth().check_user_in_room = Mock(  # type: ignore[method-assign]
            side_effect=check_user_in_room
        )

        async def check_host_in_room(room_id: str, server_name: str) -> bool:
            return room_id == ROOM_ID

        hs.get_event_auth_handler().is_host_in_room = Mock(  # type: ignore[method-assign]
            side_effect=check_host_in_room
        )

        async def get_current_hosts_in_room(room_id: str) -> Set[str]:
            return {member.domain for member in self.room_members}

        hs.get_storage_controllers().state.get_current_hosts_in_room = Mock(  # type: ignore[method-assign]
            side_effect=get_current_hosts_in_room
        )

        hs.get_storage_controllers().state.get_current_hosts_in_room_or_partial_state_approximation = Mock(  # type: ignore[method-assign]
            side_effect=get_current_hosts_in_room
        )

        async def get_users_in_room(room_id: str) -> Set[str]:
            return {str(u) for u in self.room_members}

        self.datastore.get_users_in_room = Mock(side_effect=get_users_in_room)

        self.datastore.get_user_directory_stream_pos = AsyncMock(  # type: ignore[method-assign]
            # we deliberately return a non-None stream pos to avoid
            # doing an initial_sync
            return_value=1
        )

        self.datastore.get_partial_current_state_deltas = Mock(return_value=(0, []))  # type: ignore[method-assign]

        self.datastore.get_to_device_stream_token = Mock(  # type: ignore[method-assign]
            return_value=0
        )
        self.datastore.get_new_device_msgs_for_remote = AsyncMock(  # type: ignore[method-assign]
            return_value=([], 0)
        )
        self.datastore.delete_device_msgs_for_remote = AsyncMock(  # type: ignore[method-assign]
            return_value=None
        )
        self.datastore.set_received_txn_response = AsyncMock(  # type: ignore[method-assign]
            return_value=None
        )

    def test_started_typing_local(self) -> None:
        self.room_members = [U_APPLE, U_BANANA]

        self.assertEqual(self.event_source.get_current_key(), 0)

        self.get_success(
            self.handler.started_typing(
                target_user=U_APPLE,
                requester=create_requester(U_APPLE),
                room_id=ROOM_ID,
                timeout=20000,
            )
        )

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 1, rooms=[ROOM_ID])]
        )

        self.assertEqual(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE, from_key=0, limit=0, room_ids=[ROOM_ID], is_guest=False
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": [U_APPLE.to_string()]},
                }
            ],
        )

    # Enable federation sending on the main process.
    @override_config({"federation_sender_instances": None})
    def test_started_typing_remote_send(self) -> None:
        self.room_members = [U_APPLE, U_ONION]

        self.get_success(
            self.handler.started_typing(
                target_user=U_APPLE,
                requester=create_requester(U_APPLE),
                room_id=ROOM_ID,
                timeout=20000,
            )
        )

        self.mock_federation_client.put_json.assert_called_once_with(
            "farm",
            path="/_matrix/federation/v1/send/1000000",
            data=_expect_edu_transaction(
                EduTypes.TYPING,
                content={
                    "room_id": ROOM_ID,
                    "user_id": U_APPLE.to_string(),
                    "typing": True,
                },
            ),
            json_data_callback=ANY,
            long_retries=True,
            try_trailing_slash_on_400=True,
            backoff_on_all_error_codes=True,
        )

    def test_started_typing_remote_recv(self) -> None:
        self.room_members = [U_APPLE, U_ONION]

        self.assertEqual(self.event_source.get_current_key(), 0)

        channel = self.make_request(
            "PUT",
            "/_matrix/federation/v1/send/1000000",
            _make_edu_transaction_json(
                EduTypes.TYPING,
                content={
                    "room_id": ROOM_ID,
                    "user_id": U_ONION.to_string(),
                    "typing": True,
                },
            ),
            federation_auth_origin=b"farm",
        )
        self.assertEqual(channel.code, 200)

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 1, rooms=[ROOM_ID])]
        )

        self.assertEqual(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE, from_key=0, limit=0, room_ids=[ROOM_ID], is_guest=False
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": [U_ONION.to_string()]},
                }
            ],
        )

    def test_started_typing_remote_recv_not_in_room(self) -> None:
        self.room_members = [U_APPLE, U_ONION]

        self.assertEqual(self.event_source.get_current_key(), 0)

        channel = self.make_request(
            "PUT",
            "/_matrix/federation/v1/send/1000000",
            _make_edu_transaction_json(
                EduTypes.TYPING,
                content={
                    "room_id": OTHER_ROOM_ID,
                    "user_id": U_ONION.to_string(),
                    "typing": True,
                },
            ),
            federation_auth_origin=b"farm",
        )
        self.assertEqual(channel.code, 200)

        self.on_new_event.assert_not_called()

        self.assertEqual(self.event_source.get_current_key(), 0)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE,
                from_key=0,
                limit=0,
                room_ids=[OTHER_ROOM_ID],
                is_guest=False,
            )
        )
        self.assertEqual(events[0], [])
        self.assertEqual(events[1], 0)

    # Enable federation sending on the main process.
    @override_config({"federation_sender_instances": None})
    def test_stopped_typing(self) -> None:
        self.room_members = [U_APPLE, U_BANANA, U_ONION]

        # Gut-wrenching
        from synapse.handlers.typing import RoomMember

        member = RoomMember(ROOM_ID, U_APPLE.to_string())
        self.handler._member_typing_until[member] = 1002000
        self.handler._room_typing[ROOM_ID] = {U_APPLE.to_string()}

        self.assertEqual(self.event_source.get_current_key(), 0)

        self.get_success(
            self.handler.stopped_typing(
                target_user=U_APPLE,
                requester=create_requester(U_APPLE),
                room_id=ROOM_ID,
            )
        )

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 1, rooms=[ROOM_ID])]
        )

        self.mock_federation_client.put_json.assert_called_once_with(
            "farm",
            path="/_matrix/federation/v1/send/1000000",
            data=_expect_edu_transaction(
                EduTypes.TYPING,
                content={
                    "room_id": ROOM_ID,
                    "user_id": U_APPLE.to_string(),
                    "typing": False,
                },
            ),
            json_data_callback=ANY,
            long_retries=True,
            backoff_on_all_error_codes=True,
            try_trailing_slash_on_400=True,
        )

        self.assertEqual(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE, from_key=0, limit=0, room_ids=[ROOM_ID], is_guest=False
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": []},
                }
            ],
        )

    def test_typing_timeout(self) -> None:
        self.room_members = [U_APPLE, U_BANANA]

        self.assertEqual(self.event_source.get_current_key(), 0)

        self.get_success(
            self.handler.started_typing(
                target_user=U_APPLE,
                requester=create_requester(U_APPLE),
                room_id=ROOM_ID,
                timeout=10000,
            )
        )

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 1, rooms=[ROOM_ID])]
        )
        self.on_new_event.reset_mock()

        self.assertEqual(self.event_source.get_current_key(), 1)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE,
                from_key=0,
                limit=0,
                room_ids=[ROOM_ID],
                is_guest=False,
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": [U_APPLE.to_string()]},
                }
            ],
        )

        self.reactor.pump([16])

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 2, rooms=[ROOM_ID])]
        )

        self.assertEqual(self.event_source.get_current_key(), 2)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE,
                from_key=1,
                limit=0,
                room_ids=[ROOM_ID],
                is_guest=False,
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": []},
                }
            ],
        )

        # SYN-230 - see if we can still set after timeout

        self.get_success(
            self.handler.started_typing(
                target_user=U_APPLE,
                requester=create_requester(U_APPLE),
                room_id=ROOM_ID,
                timeout=10000,
            )
        )

        self.on_new_event.assert_has_calls(
            [call(StreamKeyType.TYPING, 3, rooms=[ROOM_ID])]
        )
        self.on_new_event.reset_mock()

        self.assertEqual(self.event_source.get_current_key(), 3)
        events = self.get_success(
            self.event_source.get_new_events(
                user=U_APPLE,
                from_key=0,
                limit=0,
                room_ids=[ROOM_ID],
                is_guest=False,
            )
        )
        self.assertEqual(
            events[0],
            [
                {
                    "type": EduTypes.TYPING,
                    "room_id": ROOM_ID,
                    "content": {"user_ids": [U_APPLE.to_string()]},
                }
            ],
        )
