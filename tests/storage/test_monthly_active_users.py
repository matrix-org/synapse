# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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
from tests.utils import setup_test_homeserver


class MonthlyActiveUsersTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(MonthlyActiveUsersTestCase, self).__init__(*args, **kwargs)

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver()
        self.store = self.hs.get_datastore()

    @defer.inlineCallbacks
    def test_can_insert_and_count_mau(self):
        count = yield self.store.get_monthly_active_count()
        self.assertEqual(0, count)

        yield self.store.upsert_monthly_active_user("@user:server")
        count = yield self.store.get_monthly_active_count()

        self.assertEqual(1, count)

    @defer.inlineCallbacks
    def test_is_user_monthly_active(self):
        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        user_id3 = "@user3:server"
        result = yield self.store.is_user_monthly_active(user_id1)
        self.assertFalse(result)
        yield self.store.upsert_monthly_active_user(user_id1)
        yield self.store.upsert_monthly_active_user(user_id2)
        result = yield self.store.is_user_monthly_active(user_id1)
        self.assertTrue(result)
        result = yield self.store.is_user_monthly_active(user_id3)
        self.assertFalse(result)

    @defer.inlineCallbacks
    def test_reap_monthly_active_users(self):
        self.hs.config.max_mau_value = 5
        initial_users = 10
        for i in range(initial_users):
            yield self.store.upsert_monthly_active_user("@user%d:server" % i)
        count = yield self.store.get_monthly_active_count()
        self.assertTrue(count, initial_users)
        yield self.store.reap_monthly_active_users()
        count = yield self.store.get_monthly_active_count()
        self.assertTrue(count, initial_users - self.hs.config.max_mau_value)
