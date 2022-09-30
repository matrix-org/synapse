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

from tests.unittest import HomeserverTestCase


class EndToEndKeyStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastores().main

    def test_key_without_device_name(self):
        now = 1470174257070
        json = {"key": "value"}

        self.get_success(self.store.store_device("user", "device", None))

        self.get_success(self.store.set_e2e_device_keys("user", "device", now, json))

        res = self.get_success(
            self.store.get_e2e_device_keys_for_cs_api((("user", "device"),))
        )
        self.assertIn("user", res)
        self.assertIn("device", res["user"])
        dev = res["user"]["device"]
        self.assertDictContainsSubset(json, dev)

    def test_reupload_key(self):
        now = 1470174257070
        json = {"key": "value"}

        self.get_success(self.store.store_device("user", "device", None))

        changed = self.get_success(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )
        self.assertTrue(changed)

        # If we try to upload the same key then we should be told nothing
        # changed
        changed = self.get_success(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )
        self.assertFalse(changed)

    def test_get_key_with_device_name(self):
        now = 1470174257070
        json = {"key": "value"}

        self.get_success(self.store.set_e2e_device_keys("user", "device", now, json))
        self.get_success(self.store.store_device("user", "device", "display_name"))

        res = self.get_success(
            self.store.get_e2e_device_keys_for_cs_api((("user", "device"),))
        )
        self.assertIn("user", res)
        self.assertIn("device", res["user"])
        dev = res["user"]["device"]
        self.assertDictContainsSubset(
            {"key": "value", "unsigned": {"device_display_name": "display_name"}}, dev
        )

    def test_multiple_devices(self):
        now = 1470174257070

        self.get_success(self.store.store_device("user1", "device1", None))
        self.get_success(self.store.store_device("user1", "device2", None))
        self.get_success(self.store.store_device("user2", "device1", None))
        self.get_success(self.store.store_device("user2", "device2", None))

        self.get_success(
            self.store.set_e2e_device_keys("user1", "device1", now, {"key": "json11"})
        )
        self.get_success(
            self.store.set_e2e_device_keys("user1", "device2", now, {"key": "json12"})
        )
        self.get_success(
            self.store.set_e2e_device_keys("user2", "device1", now, {"key": "json21"})
        )
        self.get_success(
            self.store.set_e2e_device_keys("user2", "device2", now, {"key": "json22"})
        )

        res = self.get_success(
            self.store.get_e2e_device_keys_for_cs_api(
                (("user1", "device1"), ("user2", "device2"))
            )
        )
        self.assertIn("user1", res)
        self.assertIn("device1", res["user1"])
        self.assertNotIn("device2", res["user1"])
        self.assertIn("user2", res)
        self.assertNotIn("device1", res["user2"])
        self.assertIn("device2", res["user2"])
