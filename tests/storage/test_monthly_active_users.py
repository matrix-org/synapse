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

FORTY_DAYS = 40 * 24 * 60 * 60


class MonthlyActiveUsersTestCase(tests.unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(MonthlyActiveUsersTestCase, self).__init__(*args, **kwargs)

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield setup_test_homeserver(self.addCleanup)
        self.store = self.hs.get_datastore()

    @defer.inlineCallbacks
    def test_initialise_reserved_users(self):
        self.hs.config.max_mau_value = 5
        user1 = "@user1:server"
        user1_email = "user1@matrix.org"
        user2 = "@user2:server"
        user2_email = "user2@matrix.org"
        threepids = [
            {'medium': 'email', 'address': user1_email},
            {'medium': 'email', 'address': user2_email},
        ]
        user_num = len(threepids)

        yield self.store.register(user_id=user1, token="123", password_hash=None)

        yield self.store.register(user_id=user2, token="456", password_hash=None)

        now = int(self.hs.get_clock().time_msec())
        yield self.store.user_add_threepid(user1, "email", user1_email, now, now)
        yield self.store.user_add_threepid(user2, "email", user2_email, now, now)
        yield self.store.initialise_reserved_users(threepids)

        active_count = yield self.store.get_monthly_active_count()

        # Test total counts
        self.assertEquals(active_count, user_num)

        # Test user is marked as active

        timestamp = yield self.store.user_last_seen_monthly_active(user1)
        self.assertTrue(timestamp)
        timestamp = yield self.store.user_last_seen_monthly_active(user2)
        self.assertTrue(timestamp)

        # Test that users are never removed from the db.
        self.hs.config.max_mau_value = 0

        self.hs.get_clock().advance_time(FORTY_DAYS)

        yield self.store.reap_monthly_active_users()

        active_count = yield self.store.get_monthly_active_count()
        self.assertEquals(active_count, user_num)

        # Test that regalar users are removed from the db
        ru_count = 2
        yield self.store.upsert_monthly_active_user("@ru1:server")
        yield self.store.upsert_monthly_active_user("@ru2:server")
        active_count = yield self.store.get_monthly_active_count()

        self.assertEqual(active_count, user_num + ru_count)
        self.hs.config.max_mau_value = user_num
        yield self.store.reap_monthly_active_users()

        active_count = yield self.store.get_monthly_active_count()
        self.assertEquals(active_count, user_num)

    @defer.inlineCallbacks
    def test_can_insert_and_count_mau(self):
        count = yield self.store.get_monthly_active_count()
        self.assertEqual(0, count)

        yield self.store.upsert_monthly_active_user("@user:server")
        count = yield self.store.get_monthly_active_count()

        self.assertEqual(1, count)

    @defer.inlineCallbacks
    def test_user_last_seen_monthly_active(self):
        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        user_id3 = "@user3:server"

        result = yield self.store.user_last_seen_monthly_active(user_id1)
        self.assertFalse(result == 0)
        yield self.store.upsert_monthly_active_user(user_id1)
        yield self.store.upsert_monthly_active_user(user_id2)
        result = yield self.store.user_last_seen_monthly_active(user_id1)
        self.assertTrue(result > 0)
        result = yield self.store.user_last_seen_monthly_active(user_id3)
        self.assertFalse(result == 0)

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
        self.assertEquals(count, initial_users - self.hs.config.max_mau_value)

        self.hs.get_clock().advance_time(FORTY_DAYS)
        yield self.store.reap_monthly_active_users()
        count = yield self.store.get_monthly_active_count()
        self.assertEquals(count, 0)
