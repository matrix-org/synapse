# Copyright 2016-2021 The Matrix.org Foundation C.I.C.
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

from tests.unittest import HomeserverTestCase


class DeviceStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

    def test_store_new_device(self):
        self.get_success(
            self.store.store_device("user_id", "device_id", "display_name")
        )

        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device_id",
                "display_name": "display_name",
            },
            res,
        )

    def test_get_devices_by_user(self):
        self.get_success(
            self.store.store_device("user_id", "device1", "display_name 1")
        )
        self.get_success(
            self.store.store_device("user_id", "device2", "display_name 2")
        )
        self.get_success(
            self.store.store_device("user_id2", "device3", "display_name 3")
        )

        res = self.get_success(self.store.get_devices_by_user("user_id"))
        self.assertEqual(2, len(res.keys()))
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device1",
                "display_name": "display_name 1",
            },
            res["device1"],
        )
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device2",
                "display_name": "display_name 2",
            },
            res["device2"],
        )

    def test_count_devices_by_users(self):
        self.get_success(
            self.store.store_device("user_id", "device1", "display_name 1")
        )
        self.get_success(
            self.store.store_device("user_id", "device2", "display_name 2")
        )
        self.get_success(
            self.store.store_device("user_id2", "device3", "display_name 3")
        )

        res = self.get_success(self.store.count_devices_by_users())
        self.assertEqual(0, res)

        res = self.get_success(self.store.count_devices_by_users(["unknown"]))
        self.assertEqual(0, res)

        res = self.get_success(self.store.count_devices_by_users(["user_id"]))
        self.assertEqual(2, res)

        res = self.get_success(
            self.store.count_devices_by_users(["user_id", "user_id2"])
        )
        self.assertEqual(3, res)

    def test_get_device_updates_by_remote(self):
        device_ids = ["device_id1", "device_id2"]

        # Add two device updates with a single stream_id
        self.get_success(
            self.store.add_device_change_to_streams("user_id", device_ids, ["somehost"])
        )

        # Get all device updates ever meant for this remote
        now_stream_id, device_updates = self.get_success(
            self.store.get_device_updates_by_remote("somehost", -1, limit=100)
        )

        # Check original device_ids are contained within these updates
        self._check_devices_in_updates(device_ids, device_updates)

    def _check_devices_in_updates(self, expected_device_ids, device_updates):
        """Check that an specific device ids exist in a list of device update EDUs"""
        self.assertEqual(len(device_updates), len(expected_device_ids))

        received_device_ids = {
            update["device_id"] for edu_type, update in device_updates
        }
        self.assertEqual(received_device_ids, set(expected_device_ids))

    def test_update_device(self):
        self.get_success(
            self.store.store_device("user_id", "device_id", "display_name 1")
        )

        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 1", res["display_name"])

        # do a no-op first
        self.get_success(self.store.update_device("user_id", "device_id"))
        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 1", res["display_name"])

        # do the update
        self.get_success(
            self.store.update_device(
                "user_id", "device_id", new_display_name="display_name 2"
            )
        )

        # check it worked
        res = self.get_success(self.store.get_device("user_id", "device_id"))
        self.assertEqual("display_name 2", res["display_name"])

    def test_update_unknown_device(self):
        exc = self.get_failure(
            self.store.update_device(
                "user_id", "unknown_device_id", new_display_name="display_name 2"
            ),
            synapse.api.errors.StoreError,
        )
        self.assertEqual(404, exc.value.code)
