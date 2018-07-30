# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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
import sys

from twisted.internet import defer

import tests.unittest
import tests.utils


class InitTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(InitTestCase, self).__init__(*args, **kwargs)
        self.store = None  # type: synapse.storage.DataStore

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()
        hs.config.max_mau_value = 50
        hs.config.limit_usage_by_mau = True
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def test_count_monthly_users(self):
        count = yield self.store.count_monthly_users()
        self.assertEqual(0, count)
        yield self.store.insert_client_ip(
            "@user:server1", "access_token", "ip", "user_agent", "device_id"
        )

        yield self.store.insert_client_ip(
            "@user:server2", "access_token", "ip", "user_agent", "device_id"
        )
        count = self.store.count_monthly_users()

        self.assertEqual(2, count)
