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
from mock import Mock

from twisted.internet import defer

import tests.unittest
import tests.utils


class ClientIpStoreTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(ClientIpStoreTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.DataStore
        self.clock = None  # type: tests.utils.MockClock

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield tests.utils.setup_test_homeserver(self.addCleanup)
        self.store = self.hs.get_datastore()
        self.clock = self.hs.get_clock()

    @defer.inlineCallbacks
    def test_insert_new_client_ip(self):
        self.clock.now = 12345678
        user_id = "@user:id"
        yield self.store.insert_client_ip(
            user_id, "access_token", "ip", "user_agent", "device_id"
        )

        result = yield self.store.get_last_client_ip_by_device(user_id, "device_id")

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
            r,
        )

    @defer.inlineCallbacks
    def test_disabled_monthly_active_user(self):
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        yield self.store.insert_client_ip(
            user_id, "access_token", "ip", "user_agent", "device_id"
        )
        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertFalse(active)

    @defer.inlineCallbacks
    def test_adding_monthly_active_user_when_full(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        lots_of_users = 100
        user_id = "@user:server"

        self.store.get_monthly_active_count = Mock(
            return_value=defer.succeed(lots_of_users)
        )
        yield self.store.insert_client_ip(
            user_id, "access_token", "ip", "user_agent", "device_id"
        )
        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertFalse(active)

    @defer.inlineCallbacks
    def test_adding_monthly_active_user_when_space(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertFalse(active)

        yield self.store.insert_client_ip(
            user_id, "access_token", "ip", "user_agent", "device_id"
        )
        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertTrue(active)

    @defer.inlineCallbacks
    def test_updating_monthly_active_user_when_space(self):
        self.hs.config.limit_usage_by_mau = True
        self.hs.config.max_mau_value = 50
        user_id = "@user:server"
        yield self.store.register(user_id=user_id, token="123", password_hash=None)

        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertFalse(active)

        yield self.store.insert_client_ip(
            user_id, "access_token", "ip", "user_agent", "device_id"
        )
        active = yield self.store.user_last_seen_monthly_active(user_id)
        self.assertTrue(active)
