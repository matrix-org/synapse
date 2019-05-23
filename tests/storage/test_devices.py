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

import logging

from twisted.internet import defer

import synapse.api.errors

import tests.unittest
import tests.utils

logger = logging.getLogger(__name__)


class DeviceStoreTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(DeviceStoreTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.DataStore

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver(self.addCleanup)

        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_store_new_device(self):
        yield self.store.store_device("user_id", "device_id", "display_name")

        res = yield self.store.get_device("user_id", "device_id")
        self.assertDictContainsSubset(
            {
                "user_id": "user_id",
                "device_id": "device_id",
                "display_name": "display_name",
            },
            res,
        )

    @defer.inlineCallbacks
    def test_get_devices_by_user(self):
        yield self.store.store_device("user_id", "device1", "display_name 1")
        yield self.store.store_device("user_id", "device2", "display_name 2")
        yield self.store.store_device("user_id2", "device3", "display_name 3")

        res = yield self.store.get_devices_by_user("user_id")
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

    @defer.inlineCallbacks
    def test_get_devices_by_remote(self):
        device_ids = ["device_id1", "device_id2"]

        # Add a device update to the stream
        yield self.store.add_device_change_to_streams(
            "user_id", device_ids, ["somehost"],
        )

        # Get all device updates ever meant for this remote
        res = yield self.store.get_devices_by_remote("somehost", -1, limit=100)

        device_updates = res[1]

        for update in device_updates:
            d_id = update["device_id"]
            if d_id in device_ids:
                device_ids.remove(d_id)

        # All device_ids should've been accounted for
        self.assertEqual(len(device_ids), 0)

    @defer.inlineCallbacks
    def test_update_device(self):
        yield self.store.store_device("user_id", "device_id", "display_name 1")

        res = yield self.store.get_device("user_id", "device_id")
        self.assertEqual("display_name 1", res["display_name"])

        # do a no-op first
        yield self.store.update_device("user_id", "device_id")
        res = yield self.store.get_device("user_id", "device_id")
        self.assertEqual("display_name 1", res["display_name"])

        # do the update
        yield self.store.update_device(
            "user_id", "device_id", new_display_name="display_name 2"
        )

        # check it worked
        res = yield self.store.get_device("user_id", "device_id")
        self.assertEqual("display_name 2", res["display_name"])

    @defer.inlineCallbacks
    def test_update_unknown_device(self):
        with self.assertRaises(synapse.api.errors.StoreError) as cm:
            yield self.store.update_device(
                "user_id", "unknown_device_id", new_display_name="display_name 2"
            )
        self.assertEqual(404, cm.exception.code)
