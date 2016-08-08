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

import synapse.server
import synapse.storage
import synapse.types
import tests.unittest
import tests.utils


class ClientIpStoreTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClientIpStoreTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.DataStore
        self.clock = None  # type: tests.utils.MockClock

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def test_insert_new_client_ip(self):
        self.clock.now = 12345678
        user_id = "@user:id"
        yield self.store.insert_client_ip(
            synapse.types.UserID.from_string(user_id),
            "access_token", "ip", "user_agent", "device_id",
        )

        # deliberately use an iterable here to make sure that the lookup
        # method doesn't iterate it twice
        device_list = iter(((user_id, "device_id"),))
        result = yield self.store.get_last_client_ip_by_device(device_list)

        r = result[(user_id, "device_id")]
        self.assertDictContainsSubset(
            {
                "user_id": user_id,
                "device_id": "device_id",
                "access_token": "access_token",
                "ip": "ip",
                "user_agent": "user_agent",
                "last_seen": 12345678000,
            },
            r
        )
