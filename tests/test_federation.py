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

from typing import Collection, List, Optional, Union
from unittest.mock import AsyncMock, Mock

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import FederationError
from synapse.api.room_versions import RoomVersion, RoomVersions
from synapse.events import EventBase, make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.federation.federation_base import event_from_pdu_json
from synapse.handlers.device import DeviceListUpdater
from synapse.http.types import QueryParams
from synapse.logging.context import LoggingContext
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID, create_requester
from synapse.util import Clock
from synapse.util.retryutils import NotRetryingDestination

from tests import unittest


class MessageAcceptTests(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.http_client = Mock()
        return self.setup_test_homeserver(federation_http_client=self.http_client)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        user_id = UserID("us", "test")
        our_user = create_requester(user_id)
        room_creator = self.hs.get_room_creation_handler()
        self.room_id = self.get_success(
            room_creator.create_room(
                our_user, room_creator._presets_dict["public_chat"], ratelimit=False
            )
        )[0]

        self.store = self.hs.get_datastores().main

        # Figure out what the most recent event is
        most_recent = next(
            iter(
                self.get_success(
                    self.hs.get_datastores().main.get_latest_event_ids_in_room(
                        self.room_id
                    )
                )
            )
        )

        join_event = make_event_from_dict(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "state_key": "@baduser:test.serv",
                "event_id": "$join:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.member",
                "origin": "test.servx",
                "content": {"membership": "join"},
                "auth_events": [],
                "prev_state": [(most_recent, {})],
                "prev_events": [(most_recent, {})],
            }
        )

        self.handler = self.hs.get_federation_handler()
        federation_event_handler = self.hs.get_federation_event_handler()

        async def _check_event_auth(
            origin: Optional[str], event: EventBase, context: EventContext
        ) -> None:
            pass

        federation_event_handler._check_event_auth = _check_event_auth  # type: ignore[method-assign]
        self.client = self.hs.get_federation_client()

        async def _check_sigs_and_hash_for_pulled_events_and_fetch(
            dest: str, pdus: Collection[EventBase], room_version: RoomVersion
        ) -> List[EventBase]:
            return list(pdus)

        self.client._check_sigs_and_hash_for_pulled_events_and_fetch = _check_sigs_and_hash_for_pulled_events_and_fetch  # type: ignore[assignment]

        # Send the join, it should return None (which is not an error)
        self.assertEqual(
            self.get_success(
                federation_event_handler.on_receive_pdu("test.serv", join_event)
            ),
            None,
        )

        # Make sure we actually joined the room
        self.assertEqual(
            self.get_success(self.store.get_latest_event_ids_in_room(self.room_id)),
            {"$join:test.serv"},
        )

    def test_cant_hide_direct_ancestors(self) -> None:
        """
        If you send a message, you must be able to provide the direct
        prev_events that said event references.
        """

        async def post_json(
            destination: str,
            path: str,
            data: Optional[JsonDict] = None,
            long_retries: bool = False,
            timeout: Optional[int] = None,
            ignore_backoff: bool = False,
            args: Optional[QueryParams] = None,
        ) -> Union[JsonDict, list]:
            # If it asks us for new missing events, give them NOTHING
            if path.startswith("/_matrix/federation/v1/get_missing_events/"):
                return {"events": []}
            return {}

        self.http_client.post_json = post_json

        # Figure out what the most recent event is
        most_recent = next(
            iter(
                self.get_success(self.store.get_latest_event_ids_in_room(self.room_id))
            )
        )

        # Now lie about an event
        lying_event = make_event_from_dict(
            {
                "room_id": self.room_id,
                "sender": "@baduser:test.serv",
                "event_id": "one:test.serv",
                "depth": 1000,
                "origin_server_ts": 1,
                "type": "m.room.message",
                "origin": "test.serv",
                "content": {"body": "hewwo?"},
                "auth_events": [],
                "prev_events": [("two:test.serv", {}), (most_recent, {})],
            }
        )

        federation_event_handler = self.hs.get_federation_event_handler()
        with LoggingContext("test-context"):
            failure = self.get_failure(
                federation_event_handler.on_receive_pdu("test.serv", lying_event),
                FederationError,
            )

        # on_receive_pdu should throw an error
        self.assertEqual(
            failure.value.args[0],
            (
                "ERROR 403: Your server isn't divulging details about prev_events "
                "referenced in this event."
            ),
        )

        # Make sure the invalid event isn't there
        extrem = self.get_success(self.store.get_latest_event_ids_in_room(self.room_id))
        self.assertEqual(extrem, {"$join:test.serv"})

    def test_retry_device_list_resync(self) -> None:
        """Tests that device lists are marked as stale if they couldn't be synced, and
        that stale device lists are retried periodically.
        """
        remote_user_id = "@john:test_remote"
        remote_origin = "test_remote"

        # Track the number of attempts to resync the user's device list.
        self.resync_attempts = 0

        # When this function is called, increment the number of resync attempts (only if
        # we're querying devices for the right user ID), then raise a
        # NotRetryingDestination error to fail the resync gracefully.
        def query_user_devices(
            destination: str, user_id: str, timeout: int = 30000
        ) -> JsonDict:
            if user_id == remote_user_id:
                self.resync_attempts += 1

            raise NotRetryingDestination(0, 0, destination)

        # Register the mock on the federation client.
        federation_client = self.hs.get_federation_client()
        federation_client.query_user_devices = Mock(side_effect=query_user_devices)  # type: ignore[method-assign]

        # Register a mock on the store so that the incoming update doesn't fail because
        # we don't share a room with the user.
        store = self.hs.get_datastores().main
        store.get_rooms_for_user = AsyncMock(return_value=["!someroom:test"])

        # Manually inject a fake device list update. We need this update to include at
        # least one prev_id so that the user's device list will need to be retried.
        device_list_updater = self.hs.get_device_handler().device_list_updater
        assert isinstance(device_list_updater, DeviceListUpdater)
        self.get_success(
            device_list_updater.incoming_device_list_update(
                origin=remote_origin,
                edu_content={
                    "deleted": False,
                    "device_display_name": "Mobile",
                    "device_id": "QBUAZIFURK",
                    "prev_id": [5],
                    "stream_id": 6,
                    "user_id": remote_user_id,
                },
            )
        )

        # Check that there was one resync attempt.
        self.assertEqual(self.resync_attempts, 1)

        # Check that the resync attempt failed and caused the user's device list to be
        # marked as stale.
        need_resync = self.get_success(
            store.get_user_ids_requiring_device_list_resync()
        )
        self.assertIn(remote_user_id, need_resync)

        # Check that waiting for 30 seconds caused Synapse to retry resyncing the device
        # list.
        self.reactor.advance(30)
        self.assertEqual(self.resync_attempts, 2)

    def test_cross_signing_keys_retry(self) -> None:
        """Tests that resyncing a device list correctly processes cross-signing keys from
        the remote server.
        """
        remote_user_id = "@john:test_remote"
        remote_master_key = "85T7JXPFBAySB/jwby4S3lBPTqY3+Zg53nYuGmu1ggY"
        remote_self_signing_key = "QeIiFEjluPBtI7WQdG365QKZcFs9kqmHir6RBD0//nQ"

        # Register mock device list retrieval on the federation client.
        federation_client = self.hs.get_federation_client()
        federation_client.query_user_devices = AsyncMock(  # type: ignore[method-assign]
            return_value={
                "user_id": remote_user_id,
                "stream_id": 1,
                "devices": [],
                "master_key": {
                    "user_id": remote_user_id,
                    "usage": ["master"],
                    "keys": {"ed25519:" + remote_master_key: remote_master_key},
                },
                "self_signing_key": {
                    "user_id": remote_user_id,
                    "usage": ["self_signing"],
                    "keys": {
                        "ed25519:" + remote_self_signing_key: remote_self_signing_key
                    },
                },
            }
        )

        # Resync the device list.
        device_handler = self.hs.get_device_handler()
        self.get_success(
            device_handler.device_list_updater.multi_user_device_resync(
                [remote_user_id]
            ),
        )

        # Retrieve the cross-signing keys for this user.
        keys = self.get_success(
            self.store.get_e2e_cross_signing_keys_bulk(user_ids=[remote_user_id]),
        )
        self.assertIn(remote_user_id, keys)
        key = keys[remote_user_id]
        assert key is not None

        # Check that the master key is the one returned by the mock.
        master_key = key["master"]
        self.assertEqual(len(master_key["keys"]), 1)
        self.assertTrue("ed25519:" + remote_master_key in master_key["keys"].keys())
        self.assertTrue(remote_master_key in master_key["keys"].values())

        # Check that the self-signing key is the one returned by the mock.
        self_signing_key = key["self_signing"]
        self.assertEqual(len(self_signing_key["keys"]), 1)
        self.assertTrue(
            "ed25519:" + remote_self_signing_key in self_signing_key["keys"].keys(),
        )
        self.assertTrue(remote_self_signing_key in self_signing_key["keys"].values())


class StripUnsignedFromEventsTestCase(unittest.TestCase):
    def test_strip_unauthorized_unsigned_values(self) -> None:
        event1 = {
            "sender": "@baduser:test.serv",
            "state_key": "@baduser:test.serv",
            "event_id": "$event1:test.serv",
            "depth": 1000,
            "origin_server_ts": 1,
            "type": "m.room.member",
            "origin": "test.servx",
            "content": {"membership": "join"},
            "auth_events": [],
            "unsigned": {"malicious garbage": "hackz", "more warez": "more hackz"},
        }
        filtered_event = event_from_pdu_json(event1, RoomVersions.V1)
        # Make sure unauthorized fields are stripped from unsigned
        self.assertNotIn("more warez", filtered_event.unsigned)

    def test_strip_event_maintains_allowed_fields(self) -> None:
        event2 = {
            "sender": "@baduser:test.serv",
            "state_key": "@baduser:test.serv",
            "event_id": "$event2:test.serv",
            "depth": 1000,
            "origin_server_ts": 1,
            "type": "m.room.member",
            "origin": "test.servx",
            "auth_events": [],
            "content": {"membership": "join"},
            "unsigned": {
                "malicious garbage": "hackz",
                "more warez": "more hackz",
                "age": 14,
                "invite_room_state": [],
            },
        }

        filtered_event2 = event_from_pdu_json(event2, RoomVersions.V1)
        self.assertIn("age", filtered_event2.unsigned)
        self.assertEqual(14, filtered_event2.unsigned["age"])
        self.assertNotIn("more warez", filtered_event2.unsigned)
        # Invite_room_state is allowed in events of type m.room.member
        self.assertIn("invite_room_state", filtered_event2.unsigned)
        self.assertEqual([], filtered_event2.unsigned["invite_room_state"])

    def test_strip_event_removes_fields_based_on_event_type(self) -> None:
        event3 = {
            "sender": "@baduser:test.serv",
            "state_key": "@baduser:test.serv",
            "event_id": "$event3:test.serv",
            "depth": 1000,
            "origin_server_ts": 1,
            "type": "m.room.power_levels",
            "origin": "test.servx",
            "content": {},
            "auth_events": [],
            "unsigned": {
                "malicious garbage": "hackz",
                "more warez": "more hackz",
                "age": 14,
                "invite_room_state": [],
            },
        }
        filtered_event3 = event_from_pdu_json(event3, RoomVersions.V1)
        self.assertIn("age", filtered_event3.unsigned)
        # Invite_room_state field is only permitted in event type m.room.member
        self.assertNotIn("invite_room_state", filtered_event3.unsigned)
        self.assertNotIn("more warez", filtered_event3.unsigned)
