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

import synapse.api.errors
import synapse.handlers.device
import synapse.storage

from tests import unittest

user1 = "@boris:aaa"
user2 = "@theresa:bbb"


class DeviceTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver("server", federation_http_client=None)
        self.handler = hs.get_device_handler()
        self.store = hs.get_datastore()
        return hs

    def prepare(self, reactor, clock, hs):
        # These tests assume that it starts 1000 seconds in.
        self.reactor.advance(1000)

    def test_device_is_created_with_invalid_name(self):
        self.get_failure(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="foo",
                initial_device_display_name="a"
                * (synapse.handlers.device.MAX_DEVICE_DISPLAY_NAME_LEN + 1),
            ),
            synapse.api.errors.SynapseError,
        )

    def test_device_is_created_if_doesnt_exist(self):
        res = self.get_success(
            self.handler.check_device_registered(
                user_id="@boris:foo",
                device_id="fco",
                initial_device_display_name="display name",
            )
        )
        self.assertEqual(res, "fco")

        dev = self.get_success(self.handler.store.get_device("@boris:foo", "fco"))
        self.assertEqual(dev["display_name"], "display name")

    def test_device_is_preserved_if_exists(self):
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
        self.assertEqual(dev["display_name"], "display name")

    def test_device_id_is_made_up_if_unspecified(self):
        device_id = self.get_success(
            self.handler.check_device_registered(
                user_id="@theresa:foo",
                device_id=None,
                initial_device_display_name="display",
            )
        )

        dev = self.get_success(self.handler.store.get_device("@theresa:foo", device_id))
        self.assertEqual(dev["display_name"], "display")

    def test_get_devices_by_user(self):
        self._record_users()

        res = self.get_success(self.handler.get_devices_by_user(user1))

        self.assertEqual(3, len(res))
        device_map = {d["device_id"]: d for d in res}
        self.assertDictContainsSubset(
            {
                "user_id": user1,
                "device_id": "xyz",
                "display_name": "display 0",
                "last_seen_ip": None,
                "last_seen_ts": None,
            },
            device_map["xyz"],
        )
        self.assertDictContainsSubset(
            {
                "user_id": user1,
                "device_id": "fco",
                "display_name": "display 1",
                "last_seen_ip": "ip1",
                "last_seen_ts": 1000000,
            },
            device_map["fco"],
        )
        self.assertDictContainsSubset(
            {
                "user_id": user1,
                "device_id": "abc",
                "display_name": "display 2",
                "last_seen_ip": "ip3",
                "last_seen_ts": 3000000,
            },
            device_map["abc"],
        )

    def test_get_device(self):
        self._record_users()

        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertDictContainsSubset(
            {
                "user_id": user1,
                "device_id": "abc",
                "display_name": "display 2",
                "last_seen_ip": "ip3",
                "last_seen_ts": 3000000,
            },
            res,
        )

    def test_delete_device(self):
        self._record_users()

        # delete the device
        self.get_success(self.handler.delete_device(user1, "abc"))

        # check the device was deleted
        self.get_failure(
            self.handler.get_device(user1, "abc"), synapse.api.errors.NotFoundError
        )

        # we'd like to check the access token was invalidated, but that's a
        # bit of a PITA.

    def test_update_device(self):
        self._record_users()

        update = {"display_name": "new display"}
        self.get_success(self.handler.update_device(user1, "abc", update))

        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertEqual(res["display_name"], "new display")

    def test_update_device_too_long_display_name(self):
        """Update a device with a display name that is invalid (too long)."""
        self._record_users()

        # Request to update a device display name with a new value that is longer than allowed.
        update = {
            "display_name": "a"
            * (synapse.handlers.device.MAX_DEVICE_DISPLAY_NAME_LEN + 1)
        }
        self.get_failure(
            self.handler.update_device(user1, "abc", update),
            synapse.api.errors.SynapseError,
        )

        # Ensure the display name was not updated.
        res = self.get_success(self.handler.get_device(user1, "abc"))
        self.assertEqual(res["display_name"], "display 2")

    def test_update_unknown_device(self):
        update = {"display_name": "new_display"}
        self.get_failure(
            self.handler.update_device("user_id", "unknown_device_id", update),
            synapse.api.errors.NotFoundError,
        )

    def _record_users(self):
        # check this works for both devices which have a recorded client_ip,
        # and those which don't.
        self._record_user(user1, "xyz", "display 0")
        self._record_user(user1, "fco", "display 1", "token1", "ip1")
        self._record_user(user1, "abc", "display 2", "token2", "ip2")
        self._record_user(user1, "abc", "display 2", "token3", "ip3")

        self._record_user(user2, "def", "dispkay", "token4", "ip4")

        self.reactor.advance(10000)

    def _record_user(
        self, user_id, device_id, display_name, access_token=None, ip=None
    ):
        device_id = self.get_success(
            self.handler.check_device_registered(
                user_id=user_id,
                device_id=device_id,
                initial_device_display_name=display_name,
            )
        )

        if ip is not None:
            self.get_success(
                self.store.insert_client_ip(
                    user_id, access_token, ip, "user_agent", device_id
                )
            )
            self.reactor.advance(1000)


class DehydrationTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver("server", federation_http_client=None)
        self.handler = hs.get_device_handler()
        self.registration = hs.get_registration_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        return hs

    def test_dehydrate_and_rehydrate_device(self):
        user_id = "@boris:dehydration"

        self.get_success(self.store.register_user(user_id, "foobar"))

        # First check if we can store and fetch a dehydrated device
        stored_dehydrated_device_id = self.get_success(
            self.handler.store_dehydrated_device(
                user_id=user_id,
                device_data={"device_data": {"foo": "bar"}},
                initial_device_display_name="dehydrated device",
            )
        )

        retrieved_device_id, device_data = self.get_success(
            self.handler.get_dehydrated_device(user_id=user_id)
        )

        self.assertEqual(retrieved_device_id, stored_dehydrated_device_id)
        self.assertEqual(device_data, {"device_data": {"foo": "bar"}})

        # Create a new login for the user and dehydrated the device
        device_id, access_token = self.get_success(
            self.registration.register_device(
                user_id=user_id,
                device_id=None,
                initial_display_name="new device",
            )
        )

        # Trying to claim a nonexistent device should throw an error
        self.get_failure(
            self.handler.rehydrate_device(
                user_id=user_id,
                access_token=access_token,
                device_id="not the right device ID",
            ),
            synapse.api.errors.NotFoundError,
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

        # make sure the device has the display name that was set from the login
        res = self.get_success(self.handler.get_device(user_id, retrieved_device_id))

        self.assertEqual(res["display_name"], "new device")

        # make sure that the device ID that we were initially assigned no longer exists
        self.get_failure(
            self.handler.get_device(user_id, device_id),
            synapse.api.errors.NotFoundError,
        )

        # make sure that there's no device available for dehydrating now
        ret = self.get_success(self.handler.get_dehydrated_device(user_id=user_id))

        self.assertIsNone(ret)
