# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from twisted.internet import defer

import tests.unittest
import tests.utils


class EndToEndKeyStoreTestCase(tests.unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver(self.addCleanup)
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_key_without_device_name(self):
        now = 1470174257070
        json = {"key": "value"}

        yield defer.ensureDeferred(self.store.store_device("user", "device", None))

        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )

        res = yield defer.ensureDeferred(
            self.store.get_e2e_device_keys_for_cs_api((("user", "device"),))
        )
        self.assertIn("user", res)
        self.assertIn("device", res["user"])
        dev = res["user"]["device"]
        self.assertDictContainsSubset(json, dev)

    @defer.inlineCallbacks
    def test_reupload_key(self):
        now = 1470174257070
        json = {"key": "value"}

        yield defer.ensureDeferred(self.store.store_device("user", "device", None))

        changed = yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )
        self.assertTrue(changed)

        # If we try to upload the same key then we should be told nothing
        # changed
        changed = yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )
        self.assertFalse(changed)

    @defer.inlineCallbacks
    def test_get_key_with_device_name(self):
        now = 1470174257070
        json = {"key": "value"}

        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user", "device", now, json)
        )
        yield defer.ensureDeferred(
            self.store.store_device("user", "device", "display_name")
        )

        res = yield defer.ensureDeferred(
            self.store.get_e2e_device_keys_for_cs_api((("user", "device"),))
        )
        self.assertIn("user", res)
        self.assertIn("device", res["user"])
        dev = res["user"]["device"]
        self.assertDictContainsSubset(
            {"key": "value", "unsigned": {"device_display_name": "display_name"}}, dev
        )

    @defer.inlineCallbacks
    def test_multiple_devices(self):
        now = 1470174257070

        yield defer.ensureDeferred(self.store.store_device("user1", "device1", None))
        yield defer.ensureDeferred(self.store.store_device("user1", "device2", None))
        yield defer.ensureDeferred(self.store.store_device("user2", "device1", None))
        yield defer.ensureDeferred(self.store.store_device("user2", "device2", None))

        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user1", "device1", now, {"key": "json11"})
        )
        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user1", "device2", now, {"key": "json12"})
        )
        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user2", "device1", now, {"key": "json21"})
        )
        yield defer.ensureDeferred(
            self.store.set_e2e_device_keys("user2", "device2", now, {"key": "json22"})
        )

        res = yield defer.ensureDeferred(
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
