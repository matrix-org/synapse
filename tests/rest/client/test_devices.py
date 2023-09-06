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

from twisted.internet.defer import ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import NotFoundError
from synapse.rest import admin, devices, room, sync
from synapse.rest.client import account, keys, login, register
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID, create_requester
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
        keys.register_servlets,
    ]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.registration = hs.get_registration_handler()
        self.message_handler = hs.get_device_message_handler()

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
                },
                "device_keys": {
                    "user_id": "@alice:test",
                    "device_id": "device1",
                    "valid_until_ts": "80",
                    "algorithms": [
                        "m.olm.curve25519-aes-sha2",
                    ],
                    "keys": {
                        "<algorithm>:<device_id>": "<key_base64>",
                    },
                    "signatures": {
                        "<user_id>": {"<algorithm>:<device_id>": "<signature_base64>"}
                    },
                },
            },
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, HTTPStatus.OK, channel.json_body)
        device_id = channel.json_body.get("device_id")
        self.assertIsInstance(device_id, str)

    @unittest.override_config(
        {"experimental_features": {"msc2697_enabled": False, "msc3814_enabled": True}}
    )
    def test_dehydrate_msc3814(self) -> None:
        user = self.register_user("mikey", "pass")
        token = self.login(user, "pass", device_id="device1")
        content: JsonDict = {
            "device_data": {
                "algorithm": "m.dehydration.v1.olm",
            },
            "device_id": "device1",
            "initial_device_display_name": "foo bar",
            "device_keys": {
                "user_id": "@mikey:test",
                "device_id": "device1",
                "valid_until_ts": "80",
                "algorithms": [
                    "m.olm.curve25519-aes-sha2",
                ],
                "keys": {
                    "<algorithm>:<device_id>": "<key_base64>",
                },
                "signatures": {
                    "<user_id>": {"<algorithm>:<device_id>": "<signature_base64>"}
                },
            },
            "fallback_keys": {
                "alg1:device1": "f4llb4ckk3y",
                "signed_<algorithm>:<device_id>": {
                    "fallback": "true",
                    "key": "f4llb4ckk3y",
                    "signatures": {
                        "<user_id>": {"<algorithm>:<device_id>": "<key_base64>"}
                    },
                },
            },
            "one_time_keys": {"alg1:k1": "0net1m3k3y"},
        }
        channel = self.make_request(
            "PUT",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            content=content,
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        device_id = channel.json_body.get("device_id")
        assert device_id is not None
        self.assertIsInstance(device_id, str)
        self.assertEqual("device1", device_id)

        # test that we can now GET the dehydrated device info
        channel = self.make_request(
            "GET",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        returned_device_id = channel.json_body.get("device_id")
        self.assertEqual(returned_device_id, device_id)
        device_data = channel.json_body.get("device_data")
        expected_device_data = {
            "algorithm": "m.dehydration.v1.olm",
        }
        self.assertEqual(device_data, expected_device_data)

        # test that the keys are correctly uploaded
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    user: ["device1"],
                },
            },
            token,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(
            channel.json_body["device_keys"][user][device_id]["keys"],
            content["device_keys"]["keys"],
        )
        # first claim should return the onetime key we uploaded
        res = self.get_success(
            self.hs.get_e2e_keys_handler().claim_one_time_keys(
                {user: {device_id: {"alg1": 1}}},
                UserID.from_string(user),
                timeout=None,
                always_include_fallback_keys=False,
            )
        )
        self.assertEqual(
            res,
            {
                "failures": {},
                "one_time_keys": {user: {device_id: {"alg1:k1": "0net1m3k3y"}}},
            },
        )
        # second claim should return fallback key
        res2 = self.get_success(
            self.hs.get_e2e_keys_handler().claim_one_time_keys(
                {user: {device_id: {"alg1": 1}}},
                UserID.from_string(user),
                timeout=None,
                always_include_fallback_keys=False,
            )
        )
        self.assertEqual(
            res2,
            {
                "failures": {},
                "one_time_keys": {user: {device_id: {"alg1:device1": "f4llb4ckk3y"}}},
            },
        )

        # create another device for the user
        (
            new_device_id,
            _,
            _,
            _,
        ) = self.get_success(
            self.registration.register_device(
                user_id=user,
                device_id=None,
                initial_display_name="new device",
            )
        )
        requester = create_requester(user, device_id=new_device_id)

        # Send a message to the dehydrated device
        ensureDeferred(
            self.message_handler.send_device_message(
                requester=requester,
                message_type="test.message",
                messages={user: {device_id: {"body": "test_message"}}},
            )
        )
        self.pump()

        # make sure we can fetch the message with our dehydrated device id
        channel = self.make_request(
            "POST",
            f"_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device_id}/events",
            content={},
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        expected_content = {"body": "test_message"}
        self.assertEqual(channel.json_body["events"][0]["content"], expected_content)

        # fetch messages again and make sure that the message was not deleted
        channel = self.make_request(
            "POST",
            f"_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device_id}/events",
            content={},
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["events"][0]["content"], expected_content)
        next_batch_token = channel.json_body.get("next_batch")

        # make sure fetching messages with next batch token works - there are no unfetched
        # messages so we should receive an empty array
        content = {"next_batch": next_batch_token}
        channel = self.make_request(
            "POST",
            f"_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device/{device_id}/events",
            content=content,
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["events"], [])

        # make sure we can delete the dehydrated device
        channel = self.make_request(
            "DELETE",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)

        # ...and after deleting it is no longer available
        channel = self.make_request(
            "GET",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 401)

    @unittest.override_config(
        {"experimental_features": {"msc2697_enabled": False, "msc3814_enabled": True}}
    )
    def test_msc3814_dehydrated_device_delete_works(self) -> None:
        user = self.register_user("mikey", "pass")
        token = self.login(user, "pass", device_id="device1")
        content: JsonDict = {
            "device_data": {
                "algorithm": "m.dehydration.v1.olm",
            },
            "device_id": "device2",
            "initial_device_display_name": "foo bar",
            "device_keys": {
                "user_id": "@mikey:test",
                "device_id": "device2",
                "valid_until_ts": "80",
                "algorithms": [
                    "m.olm.curve25519-aes-sha2",
                ],
                "keys": {
                    "<algorithm>:<device_id>": "<key_base64>",
                },
                "signatures": {
                    "<user_id>": {"<algorithm>:<device_id>": "<signature_base64>"}
                },
            },
        }
        channel = self.make_request(
            "PUT",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            content=content,
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        device_id = channel.json_body.get("device_id")
        assert device_id is not None
        self.assertIsInstance(device_id, str)
        self.assertEqual("device2", device_id)

        # ensure that keys were uploaded and available
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    user: ["device2"],
                },
            },
            token,
        )
        self.assertEqual(
            channel.json_body["device_keys"][user]["device2"]["keys"],
            {
                "<algorithm>:<device_id>": "<key_base64>",
            },
        )

        # delete the dehydrated device
        channel = self.make_request(
            "DELETE",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)

        # ensure that keys are no longer available for deleted device
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    user: ["device2"],
                },
            },
            token,
        )
        self.assertEqual(channel.json_body["device_keys"], {"@mikey:test": {}})

        # check that an old device is deleted when user PUTs a new device
        # First, create a device
        content["device_id"] = "device3"
        content["device_keys"]["device_id"] = "device3"
        channel = self.make_request(
            "PUT",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            content=content,
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        device_id = channel.json_body.get("device_id")
        assert device_id is not None
        self.assertIsInstance(device_id, str)
        self.assertEqual("device3", device_id)

        # create a second device without deleting first device
        content["device_id"] = "device4"
        content["device_keys"]["device_id"] = "device4"
        channel = self.make_request(
            "PUT",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            content=content,
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        device_id = channel.json_body.get("device_id")
        assert device_id is not None
        self.assertIsInstance(device_id, str)
        self.assertEqual("device4", device_id)

        # check that the second device that was created is what is returned when we GET
        channel = self.make_request(
            "GET",
            "_matrix/client/unstable/org.matrix.msc3814.v1/dehydrated_device",
            access_token=token,
            shorthand=False,
        )
        self.assertEqual(channel.code, 200)
        returned_device_id = channel.json_body["device_id"]
        self.assertEqual(returned_device_id, "device4")

        # and that if we query the keys for the first device they are not there
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/keys/query",
            {
                "device_keys": {
                    user: ["device3"],
                },
            },
            token,
        )
        self.assertEqual(channel.json_body["device_keys"], {"@mikey:test": {}})
