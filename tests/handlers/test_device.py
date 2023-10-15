# Copyright 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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

from typing import Optional
from unittest import mock

from twisted.internet.defer import ensureDeferred
from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import RoomEncryptionAlgorithms
from synapse.api.errors import NotFoundError, SynapseError
from synapse.appservice import ApplicationService
from synapse.handlers.device import MAX_DEVICE_DISPLAY_NAME_LEN, DeviceHandler
from synapse.rest import admin
from synapse.rest.client import devices, login, register
from synapse.server import HomeServer
from synapse.storage.databases.main.appservice import _make_exclusive_regex
from synapse.types import JsonDict, create_requester
from synapse.util import Clock
from synapse.util.task_scheduler import TaskScheduler

from tests import unittest
from tests.unittest import override_config

user1 = "@boris:aaa"
user2 = "@theresa:bbb"


class DeviceTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.appservice_api = mock.AsyncMock()
        hs = self.setup_test_homeserver(
            "server",
            application_service_api=self.appservice_api,
        )
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.handler = handler
        self.store = hs.get_datastores().main
        self.device_message_handler = hs.get_device_message_handler()
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        # These tests assume that it starts 1000 seconds in.
        self.reactor.advance(1000)

    def test_device_is_created_with_invalid_name(self) -> None:
        self.get_failure(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="foo",
                initial_device_display_name="a" * (MAX_DEVICE_DISPLAY_NAME_LEN + 1),
            ),
            SynapseError,
        )

    def test_device_is_created_if_doesnt_exist(self) -> None:
        res = self.get_success(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="fco",
                initial_device_display_name="display name",
            )
        )
        self.assertEqual(res, "fco")

        dev = self.get_success(self.handler.store.get_device("@boris:foo", "fco"))
        assert dev is not None
        self.assertEqual(dev["display_name"], "display name")

    def test_device_is_preserved_if_exists(self) -> None:
        res1 = self.get_success(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="fco",
                initial_device_display_name="display name",
            )
        )
        self.assertEqual(res1, "fco")

        res2 = self.get_success(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="fco",
                initial_device_display_name="new display name",
            )
        )
        self.assertEqual(res2, "fco")

        dev = self.get_success(self.handler.store.get_device("@boris:foo", "fco"))
        assert dev is not None
        self.assertEqual(dev["display_name"], "display name")

    def test_device_id_is_made_up_if_unspecified(self) -> None:
        device_id = self.get_success(
            self.handler.check_device_registered(
                user_id="@theresa:foo",
                device_id=None,
                initial_device_display_name="display",
            )
        )

        dev = self.get_success(self.handler.store.get_device("@theresa:foo", device_id))
        assert dev is not None
        self.assertEqual(dev["display_name"], "display")

    def test_get_devices_by_user(self) -> None:
        self._record_users()

        res = self.get_success(self.handler.get_devices_by_user(user1))

        self.assertEqual(3, len(res))
        device_map = {d["device_id"]: d for d in res}
        self.assertLessEqual(
            {
                "user_id": user1,
                "device_id": "xyz",
                "display_name": "display 0",
                "last_seen_ip": None,
                "last_seen_ts": None,
            }.items(),
            device_map["xyz"].items(),
        )
        self.assertLessEqual(
            {
                "user_id": user1,
                "device_id": "fco",
                "display_name": "display 1",
                "last_seen_ip": "ip1",
                "last_seen_ts": 1000000,
            }.items(),
            device_map["fco"].items(),
        )
        self.assertLessEqual(
            {
                "user_id": user1,
                "device_id": "abc",
                "display_name": "display 2",
                "last_seen_ip": "ip3",
                "last_seen_ts": 3000000,
            }.items(),
            device_map["abc"].items(),
        )

    def test_get_device(self) -> None:
        self._record_users()

        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertLessEqual(
            {
                "user_id": user1,
                "device_id": "abc",
                "display_name": "display 2",
                "last_seen_ip": "ip3",
                "last_seen_ts": 3000000,
            }.items(),
            res.items(),
        )

    def test_delete_device(self) -> None:
        self._record_users()

        # delete the device
        self.get_success(self.handler.delete_devices(user1, ["abc"]))

        # check the device was deleted
        self.get_failure(self.handler.get_device(user1, "abc"), NotFoundError)

        # we'd like to check the access token was invalidated, but that's a
        # bit of a PITA.

    def test_delete_device_and_device_inbox(self) -> None:
        self._record_users()

        # add an device_inbox
        self.get_success(
            self.store.db_pool.simple_insert(
                "device_inbox",
                {
                    "user_id": user1,
                    "device_id": "abc",
                    "stream_id": 1,
                    "message_json": "{}",
                },
            )
        )

        # delete the device
        self.get_success(self.handler.delete_devices(user1, ["abc"]))

        # check that the device_inbox was deleted
        res = self.get_success(
            self.store.db_pool.simple_select_one(
                table="device_inbox",
                keyvalues={"user_id": user1, "device_id": "abc"},
                retcols=("user_id", "device_id"),
                allow_none=True,
                desc="get_device_id_from_device_inbox",
            )
        )
        self.assertIsNone(res)

    def test_delete_device_and_big_device_inbox(self) -> None:
        """Check that deleting a big device inbox is staged and batched asynchronously."""
        DEVICE_ID = "abc"
        sender = "@sender:" + self.hs.hostname
        receiver = "@receiver:" + self.hs.hostname
        self._record_user(sender, DEVICE_ID, DEVICE_ID)
        self._record_user(receiver, DEVICE_ID, DEVICE_ID)

        # queue a bunch of messages in the inbox
        requester = create_requester(sender, device_id=DEVICE_ID)
        for i in range(DeviceHandler.DEVICE_MSGS_DELETE_BATCH_LIMIT + 10):
            self.get_success(
                self.device_message_handler.send_device_message(
                    requester, "message_type", {receiver: {"*": {"val": i}}}
                )
            )

        # delete the device
        self.get_success(self.handler.delete_devices(receiver, [DEVICE_ID]))

        # messages should be deleted up to DEVICE_MSGS_DELETE_BATCH_LIMIT straight away
        res = self.get_success(
            self.store.db_pool.simple_select_list(
                table="device_inbox",
                keyvalues={"user_id": receiver},
                retcols=("user_id", "device_id", "stream_id"),
                desc="get_device_id_from_device_inbox",
            )
        )
        self.assertEqual(10, len(res))

        # wait for the task scheduler to do a second delete pass
        self.reactor.advance(TaskScheduler.SCHEDULE_INTERVAL_MS / 1000)

        # remaining messages should now be deleted
        res = self.get_success(
            self.store.db_pool.simple_select_list(
                table="device_inbox",
                keyvalues={"user_id": receiver},
                retcols=("user_id", "device_id", "stream_id"),
                desc="get_device_id_from_device_inbox",
            )
        )
        self.assertEqual(0, len(res))

    def test_update_device(self) -> None:
        self._record_users()

        update = {"display_name": "new display"}
        self.get_success(self.handler.update_device(user1, "abc", update))

        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertEqual(res["display_name"], "new display")

    def test_update_device_too_long_display_name(self) -> None:
        """Update a device with a display name that is invalid (too long)."""
        self._record_users()

        # Request to update a device display name with a new value that is longer than allowed.
        update = {"display_name": "a" * (MAX_DEVICE_DISPLAY_NAME_LEN + 1)}
        self.get_failure(
            self.handler.update_device(user1, "abc", update),
            SynapseError,
        )

        # Ensure the display name was not updated.
        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertEqual(res["display_name"], "display 2")

    def test_update_unknown_device(self) -> None:
        update = {"display_name": "new_display"}
        self.get_failure(
            self.handler.update_device("user_id", "unknown_device_id", update),
            NotFoundError,
        )

    def _record_users(self) -> None:
        # check this works for both devices which have a recorded client_ip,
        # and those which don't.
        self._record_user(user1, "xyz", "display 0")
        self._record_user(user1, "fco", "display 1", "token1", "ip1")
        self._record_user(user1, "abc", "display 2", "token2", "ip2")
        self._record_user(user1, "abc", "display 2", "token3", "ip3")

        self._record_user(user2, "def", "dispkay", "token4", "ip4")

        self.reactor.advance(10000)

    def _record_user(
        self,
        user_id: str,
        device_id: str,
        display_name: str,
        access_token: Optional[str] = None,
        ip: Optional[str] = None,
    ) -> None:
        device_id = self.get_success(
            self.handler.check_device_registered(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=display_name,
            )
        )

        if access_token is not None and ip is not None:
            self.get_success(
                self.store.insert_client_ip(
                    user_id, access_token, ip, "user_agent", device_id
                )
            )
            self.reactor.advance(1000)

    @override_config({"experimental_features": {"msc3984_appservice_key_query": True}})
    def test_on_federation_query_user_devices_appservice(self) -> None:
        """Test that querying of appservices for keys overrides responses from the database."""
        local_user = "@boris:" + self.hs.hostname
        device_1 = "abc"
        device_2 = "def"
        device_3 = "ghi"

        # There are 3 devices:
        #
        # 1. One which is uploaded to the homeserver.
        # 2. One which is uploaded to the homeserver, but a newer copy is returned
        #     by the appservice.
        # 3. One which is only returned by the appservice.
        device_key_1: JsonDict = {
            "user_id": local_user,
            "device_id": device_1,
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {
                "ed25519:abc": "base64+ed25519+key",
                "curve25519:abc": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:abc": "base64+signature"}},
        }
        device_key_2a: JsonDict = {
            "user_id": local_user,
            "device_id": device_2,
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {
                "ed25519:def": "base64+ed25519+key",
                "curve25519:def": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:def": "base64+signature"}},
        }

        device_key_2b: JsonDict = {
            "user_id": local_user,
            "device_id": device_2,
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            # The device ID is the same (above), but the keys are different.
            "keys": {
                "ed25519:xyz": "base64+ed25519+key",
                "curve25519:xyz": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:xyz": "base64+signature"}},
        }
        device_key_3: JsonDict = {
            "user_id": local_user,
            "device_id": device_3,
            "algorithms": [
                "m.olm.curve25519-aes-sha2",
                RoomEncryptionAlgorithms.MEGOLM_V1_AES_SHA2,
            ],
            "keys": {
                "ed25519:jkl": "base64+ed25519+key",
                "curve25519:jkl": "base64+curve25519+key",
            },
            "signatures": {local_user: {"ed25519:jkl": "base64+signature"}},
        }

        # Upload keys for devices 1 & 2a.
        e2e_keys_handler = self.hs.get_e2e_keys_handler()
        self.get_success(
            e2e_keys_handler.upload_keys_for_user(
                local_user, device_1, {"device_keys": device_key_1}
            )
        )
        self.get_success(
            e2e_keys_handler.upload_keys_for_user(
                local_user, device_2, {"device_keys": device_key_2a}
            )
        )

        # Inject an appservice interested in this user.
        appservice = ApplicationService(
            token="i_am_an_app_service",
            id="1234",
            namespaces={"users": [{"regex": r"@boris:.+", "exclusive": True}]},
            # Note: this user does not have to match the regex above
            sender="@as_main:test",
        )
        self.hs.get_datastores().main.services_cache = [appservice]
        self.hs.get_datastores().main.exclusive_user_regex = _make_exclusive_regex(
            [appservice]
        )

        # Setup a response.
        self.appservice_api.query_keys.return_value = {
            "device_keys": {
                local_user: {device_2: device_key_2b, device_3: device_key_3}
            }
        }

        # Request all devices.
        res = self.get_success(
            self.handler.on_federation_query_user_devices(local_user)
        )
        self.assertIn("devices", res)
        res_devices = res["devices"]
        for device in res_devices:
            device["keys"].pop("unsigned", None)
        self.assertEqual(
            res_devices,
            [
                {"device_id": device_1, "keys": device_key_1},
                {"device_id": device_2, "keys": device_key_2b},
                {"device_id": device_3, "keys": device_key_3},
            ],
        )


class DehydrationTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        register.register_servlets,
        devices.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        hs = self.setup_test_homeserver("server")
        handler = hs.get_device_handler()
        assert isinstance(handler, DeviceHandler)
        self.handler = handler
        self.message_handler = hs.get_device_message_handler()
        self.registration = hs.get_registration_handler()
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()
        self.store = hs.get_datastores().main
        return hs

    def test_dehydrate_and_rehydrate_device(self) -> None:
        user_id = "@boris:dehydration"

        self.get_success(self.store.register_user(user_id, "foobar"))

        # First check if we can store and fetch a dehydrated device
        stored_dehydrated_device_id = self.get_success(
            self.handler.store_dehydrated_device(
                user_id=user_id,
                device_id=None,
                device_data={"device_data": {"foo": "bar"}},
                initial_device_display_name="dehydrated device",
            )
        )

        result = self.get_success(self.handler.get_dehydrated_device(user_id=user_id))
        assert result is not None
        retrieved_device_id, device_data = result

        self.assertEqual(retrieved_device_id, stored_dehydrated_device_id)
        self.assertEqual(device_data, {"device_data": {"foo": "bar"}})

        # Create a new login for the user and dehydrated the device
        device_id, access_token, _expiration_time, refresh_token = self.get_success(
            self.registration.register_device(
                user_id=user_id,
                device_id=None,
                initial_display_name="new device",
                should_issue_refresh_token=True,
            )
        )

        # Trying to claim a nonexistent device should throw an error
        self.get_failure(
            self.handler.rehydrate_device(
                user_id=user_id,
                access_token=access_token,
                device_id="not the right device ID",
            ),
            NotFoundError,
        )

        # dehydrating the right devices should succeed and change our device ID
        # to the dehydrated device's ID
        res = self.get_success(
            self.handler.rehydrate_device(
                user_id=user_id,
                access_token=access_token,
                device_id=retrieved_device_id,
            )
        )

        self.assertEqual(res, {"success": True})

        # make sure that our device ID has changed
        user_info = self.get_success(self.auth.get_user_by_access_token(access_token))

        self.assertEqual(user_info.device_id, retrieved_device_id)

        # make sure the user device has the refresh token
        assert refresh_token is not None
        self.get_success(
            self.auth_handler.refresh_token(refresh_token, 5 * 60 * 1000, 5 * 60 * 1000)
        )

        # make sure the device has the display name that was set from the login
        res = self.get_success(self.handler.get_device(user_id, retrieved_device_id))

        self.assertEqual(res["display_name"], "new device")

        # make sure that the device ID that we were initially assigned no longer exists
        self.get_failure(
            self.handler.get_device(user_id, device_id),
            NotFoundError,
        )

        # make sure that there's no device available for dehydrating now
        ret = self.get_success(self.handler.get_dehydrated_device(user_id=user_id))

        self.assertIsNone(ret)

    @unittest.override_config(
        {"experimental_features": {"msc2697_enabled": False, "msc3814_enabled": True}}
    )
    def test_dehydrate_v2_and_fetch_events(self) -> None:
        user_id = "@boris:server"

        self.get_success(self.store.register_user(user_id, "foobar"))

        # First check if we can store and fetch a dehydrated device
        stored_dehydrated_device_id = self.get_success(
            self.handler.store_dehydrated_device(
                user_id=user_id,
                device_id=None,
                device_data={"device_data": {"foo": "bar"}},
                initial_device_display_name="dehydrated device",
            )
        )

        device_info = self.get_success(
            self.handler.get_dehydrated_device(user_id=user_id)
        )
        assert device_info is not None
        retrieved_device_id, device_data = device_info
        self.assertEqual(retrieved_device_id, stored_dehydrated_device_id)
        self.assertEqual(device_data, {"device_data": {"foo": "bar"}})

        # Create a new login for the user
        device_id, access_token, _expiration_time, _refresh_token = self.get_success(
            self.registration.register_device(
                user_id=user_id,
                device_id=None,
                initial_display_name="new device",
            )
        )

        requester = create_requester(user_id, device_id=device_id)

        # Fetching messages for a non-existing device should return an error
        self.get_failure(
            self.message_handler.get_events_for_dehydrated_device(
                requester=requester,
                device_id="not the right device ID",
                since_token=None,
                limit=10,
            ),
            SynapseError,
        )

        # Send a message to the dehydrated device
        ensureDeferred(
            self.message_handler.send_device_message(
                requester=requester,
                message_type="test.message",
                messages={user_id: {stored_dehydrated_device_id: {"body": "foo"}}},
            )
        )
        self.pump()

        # Fetch the message of the dehydrated device
        res = self.get_success(
            self.message_handler.get_events_for_dehydrated_device(
                requester=requester,
                device_id=stored_dehydrated_device_id,
                since_token=None,
                limit=10,
            )
        )

        self.assertTrue(len(res["next_batch"]) > 1)
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(res["events"][0]["content"]["body"], "foo")

        # Fetch the message of the dehydrated device again, which should return
        # the same message as it has not been deleted
        res = self.get_success(
            self.message_handler.get_events_for_dehydrated_device(
                requester=requester,
                device_id=stored_dehydrated_device_id,
                since_token=None,
                limit=10,
            )
        )
        self.assertTrue(len(res["next_batch"]) > 1)
        self.assertEqual(len(res["events"]), 1)
        self.assertEqual(res["events"][0]["content"]["body"], "foo")
