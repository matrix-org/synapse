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

from twisted.internet import defer

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
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def test_count_monthly_users(self):
        count = yield self.store.count_monthly_users()
        self.assertEqual(0, count)

        yield self._insert_user_ips("@user:server1")
        yield self._insert_user_ips("@user:server2")

        count = yield self.store.count_monthly_users()
        self.assertEqual(2, count)

    @defer.inlineCallbacks
    def _insert_user_ips(self, user):
        """
        Helper function to populate user_ips without using batch insertion infra
        args:
            user (str):  specify username i.e. @user:server.com
        """
        yield self.store._simple_upsert(
            table="user_ips",
            keyvalues={
                "user_id": user,
                "access_token": "access_token",
                "ip": "ip",
                "user_agent": "user_agent",
                "device_id": "device_id",
            },
            values={
                "last_seen": self.clock.time_msec(),
            }
        )
