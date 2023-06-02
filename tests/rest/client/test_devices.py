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
from http import HTTPStatus

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import NotFoundError
from synapse.rest import admin, devices, room, sync
from synapse.rest.client import account, login, register
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class DeviceListsTestCase(unittest.HomeserverTestCase):
    """Tests regarding device list changes."""

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        register.register_servlets,
        account.register_servlets,
        room.register_servlets,
        sync.register_servlets,
        devices.register_servlets,
    ]

    def test_receiving_local_device_list_changes(self) -> None:
        """Tests that a local users that share a room receive each other's device list
        changes.
        """
        # Register two users
        test_device_id = "TESTDEVICE"
        alice_user_id = self.register_user("alice", "correcthorse")
        alice_access_token = self.login(
            alice_user_id, "correcthorse", device_id=test_device_id
        )

        bob_user_id = self.register_user("bob", "ponyponypony")
        bob_access_token = self.login(bob_user_id, "ponyponypony")

        # Create a room for them to coexist peacefully in
        new_room_id = self.helper.create_room_as(
            alice_user_id, is_public=True, tok=alice_access_token
        )
        self.assertIsNotNone(new_room_id)

        # Have Bob join the room
        self.helper.invite(
            new_room_id, alice_user_id, bob_user_id, tok=alice_access_token
        )
        self.helper.join(new_room_id, bob_user_id, tok=bob_access_token)

        # Now have Bob initiate an initial sync (in order to get a since token)
        channel = self.make_request(
            "GET",
            "/sync",
            access_token=bob_access_token,
        )
        self.assertEqual(channel.code, 200, channel.json_body)
        next_batch_token = channel.json_body["next_batch"]

        # ...and then an incremental sync. This should block until the sync stream is woken up,
        # which we hope will happen as a result of Alice updating their device list.
        bob_sync_channel = self.make_request(
            "GET",
            f"/sync?since={next_batch_token}&timeout=30000",
            access_token=bob_access_token,
            # Start the request, then continue on.
            await_result=False,
        )

        # Have alice update their device list
        channel = self.make_request(
            "PUT",
            f"/devices/{test_device_id}",
            {
                "display_name": "New Device Name",
            },
            access_token=alice_access_token,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)

        # Check that bob's incremental sync contains the updated device list.
        # If not, the client would only receive the device list update on the
        # *next* sync.
        bob_sync_channel.await_result()
        self.assertEqual(bob_sync_channel.code, 200, bob_sync_channel.json_body)

        changed_device_lists = bob_sync_channel.json_body.get("device_lists", {}).get(
            "changed", []
        )
        self.assertIn(alice_user_id, changed_device_lists, bob_sync_channel.json_body)

    def test_not_receiving_local_device_list_changes(self) -> None:
        """Tests a local users DO NOT receive device updates from each other if they do not
        share a room.
        """
        # Register two users
        test_device_id = "TESTDEVICE"
        alice_user_id = self.register_user("alice", "correcthorse")
        alice_access_token = self.login(
            alice_user_id, "correcthorse", device_id=test_device_id
        )

        bob_user_id = self.register_user("bob", "ponyponypony")
        bob_access_token = self.login(bob_user_id, "ponyponypony")

        # These users do not share a room. They are lonely.

        # Have Bob initiate an initial sync (in order to get a since token)
        channel = self.make_request(
            "GET",
            "/sync",
            access_token=bob_access_token,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        next_batch_token = channel.json_body["next_batch"]

        # ...and then an incremental sync. This should block until the sync stream is woken up,
        # which we hope will happen as a result of Alice updating their device list.
        bob_sync_channel = self.make_request(
            "GET",
            f"/sync?since={next_batch_token}&timeout=1000",
            access_token=bob_access_token,
            # Start the request, then continue on.
            await_result=False,
        )

        # Have alice update their device list
        channel = self.make_request(
            "PUT",
            f"/devices/{test_device_id}",
            {
                "display_name": "New Device Name",
            },
            access_token=alice_access_token,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)

        # Check that bob's incremental sync does not contain the updated device list.
        bob_sync_channel.await_result()
        self.assertEqual(
            bob_sync_channel.code, HTTPStatus.OK, bob_sync_channel.json_body
        )

        changed_device_lists = bob_sync_channel.json_body.get("device_lists", {}).get(
            "changed", []
        )
        self.assertNotIn(
            alice_user_id, changed_device_lists, bob_sync_channel.json_body
        )


class DevicesTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.handler = hs.get_device_handler()

    @unittest.override_config({"delete_stale_devices_after": 72000000})
    def test_delete_stale_devices(self) -> None:
        """Tests that stale devices are automatically removed after a set time of
        inactivity.
        The configuration is set to delete devices that haven't been used in the past 20h.
        """
        # Register a user and creates 2 devices for them.
        user_id = self.register_user("user", "password")
        tok1 = self.login("user", "password", device_id="abc")
        tok2 = self.login("user", "password", device_id="def")

        # Sync them so they have a last_seen value.
        self.make_request("GET", "/sync", access_token=tok1)
        self.make_request("GET", "/sync", access_token=tok2)

        # Advance half a day and sync again with one of the devices, so that the next
        # time the background job runs we don't delete this device (since it will look
        # for devices that haven't been used for over an hour).
        self.reactor.advance(43200)
        self.make_request("GET", "/sync", access_token=tok1)

        # Advance another half a day, and check that the device that has synced still
        # exists but the one that hasn't has been removed.
        self.reactor.advance(43200)
        self.get_success(self.handler.get_device(user_id, "abc"))
        self.get_failure(self.handler.get_device(user_id, "def"), NotFoundError)


class DehydratedDeviceTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        register.register_servlets,
        devices.register_servlets,
    ]

    def test_PUT(self) -> None:
        """Sanity-check that we can PUT a dehydrated device.

        Detects https://github.com/matrix-org/synapse/issues/14334.
        """
        alice = self.register_user("alice", "correcthorse")
        token = self.login(alice, "correcthorse")

        # Have alice update their device list
        channel = self.make_request(
            "PUT",
            "_matrix/client/unstable/org.matrix.msc2697.v2/dehydrated_device",
            {
                "device_data": {
                    "algorithm": "org.matrix.msc2697.v1.dehydration.v1.olm",
                    "account": "dehydrated_device",
                }
            },
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        device_id = channel.json_body.get("device_id")
        self.assertIsInstance(device_id, str)
