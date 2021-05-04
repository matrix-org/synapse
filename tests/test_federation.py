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

from unittest.mock import Mock

from twisted.internet.defer import succeed

from synapse.api.errors import FederationError
from synapse.events import make_event_from_dict
from synapse.logging.context import LoggingContext
from synapse.types import UserID, create_requester
from synapse.util import Clock
from synapse.util.retryutils import NotRetryingDestination

from tests import unittest
from tests.server import ThreadedMemoryReactorClock, setup_test_homeserver
from tests.test_utils import make_awaitable


class MessageAcceptTests(unittest.HomeserverTestCase):
    def setUp(self):

        self.http_client = Mock()
        self.reactor = ThreadedMemoryReactorClock()
        self.hs_clock = Clock(self.reactor)
        self.homeserver = setup_test_homeserver(
            self.addCleanup,
            federation_http_client=self.http_client,
            clock=self.hs_clock,
            reactor=self.reactor,
        )

        user_id = UserID("us", "test")
        our_user = create_requester(user_id)
        room_creator = self.homeserver.get_room_creation_handler()
        self.room_id = self.get_success(
            room_creator.create_room(
                our_user, room_creator._presets_dict["public_chat"], ratelimit=False
            )
        )[0]["room_id"]

        self.store = self.homeserver.get_datastore()

        # Figure out what the most recent event is
        most_recent = self.get_success(
            self.homeserver.get_datastore().get_latest_event_ids_in_room(self.room_id)
        )[0]

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

        self.handler = self.homeserver.get_federation_handler()
        self.handler._check_event_auth = (
            lambda origin, event, context, state, auth_events, backfilled: succeed(
                context
            )
        )
        self.client = self.homeserver.get_federation_client()
        self.client._check_sigs_and_hash_and_fetch = lambda dest, pdus, **k: succeed(
            pdus
        )

        # Send the join, it should return None (which is not an error)
        self.assertEqual(
            self.get_success(
                self.handler.on_receive_pdu(
                    "test.serv", join_event, sent_to_us_directly=True
                )
            ),
            None,
        )

        # Make sure we actually joined the room
        self.assertEqual(
            self.get_success(self.store.get_latest_event_ids_in_room(self.room_id))[0],
            "$join:test.serv",
        )

    def test_cant_hide_direct_ancestors(self):
        """
        If you send a message, you must be able to provide the direct
        prev_events that said event references.
        """

        async def post_json(destination, path, data, headers=None, timeout=0):
            # If it asks us for new missing events, give them NOTHING
            if path.startswith("/_matrix/federation/v1/get_missing_events/"):
                return {"events": []}

        self.http_client.post_json = post_json

        # Figure out what the most recent event is
        most_recent = self.get_success(
            self.store.get_latest_event_ids_in_room(self.room_id)
        )[0]

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

        with LoggingContext("test-context"):
            failure = self.get_failure(
                self.handler.on_receive_pdu(
                    "test.serv", lying_event, sent_to_us_directly=True
                ),
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
        self.assertEqual(extrem[0], "$join:test.serv")

    def test_retry_device_list_resync(self):
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
        def query_user_devices(destination, user_id):
            if user_id == remote_user_id:
                self.resync_attempts += 1

            raise NotRetryingDestination(0, 0, destination)

        # Register the mock on the federation client.
        federation_client = self.homeserver.get_federation_client()
        federation_client.query_user_devices = Mock(side_effect=query_user_devices)

        # Register a mock on the store so that the incoming update doesn't fail because
        # we don't share a room with the user.
        store = self.homeserver.get_datastore()
        store.get_rooms_for_user = Mock(return_value=make_awaitable(["!someroom:test"]))

        # Manually inject a fake device list update. We need this update to include at
        # least one prev_id so that the user's device list will need to be retried.
        device_list_updater = self.homeserver.get_device_handler().device_list_updater
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

    def test_cross_signing_keys_retry(self):
        """Tests that resyncing a device list correctly processes cross-signing keys from
        the remote server.
        """
        remote_user_id = "@john:test_remote"
        remote_master_key = "85T7JXPFBAySB/jwby4S3lBPTqY3+Zg53nYuGmu1ggY"
        remote_self_signing_key = "QeIiFEjluPBtI7WQdG365QKZcFs9kqmHir6RBD0//nQ"

        # Register mock device list retrieval on the federation client.
        federation_client = self.homeserver.get_federation_client()
        federation_client.query_user_devices = Mock(
            return_value=succeed(
                {
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
                            "ed25519:"
                            + remote_self_signing_key: remote_self_signing_key
                        },
                    },
                }
            )
        )

        # Resync the device list.
        device_handler = self.homeserver.get_device_handler()
        self.get_success(
            device_handler.device_list_updater.user_device_resync(remote_user_id),
        )

        # Retrieve the cross-signing keys for this user.
        keys = self.get_success(
            self.store.get_e2e_cross_signing_keys_bulk(user_ids=[remote_user_id]),
        )
        self.assertTrue(remote_user_id in keys)

        # Check that the master key is the one returned by the mock.
        master_key = keys[remote_user_id]["master"]
        self.assertEqual(len(master_key["keys"]), 1)
        self.assertTrue("ed25519:" + remote_master_key in master_key["keys"].keys())
        self.assertTrue(remote_master_key in master_key["keys"].values())

        # Check that the self-signing key is the one returned by the mock.
        self_signing_key = keys[remote_user_id]["self_signing"]
        self.assertEqual(len(self_signing_key["keys"]), 1)
        self.assertTrue(
            "ed25519:" + remote_self_signing_key in self_signing_key["keys"].keys(),
        )
        self.assertTrue(remote_self_signing_key in self_signing_key["keys"].values())
