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

from tests.unittest import HomeserverTestCase

FORTY_DAYS = 40 * 24 * 60 * 60


class MonthlyActiveUsersTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver()
        self.store = hs.get_datastore()

        # Advance the clock a bit
        reactor.advance(FORTY_DAYS)

        return hs

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

        self.store.register(user_id=user1, token="123", password_hash=None)
        self.store.register(user_id=user2, token="456", password_hash=None)
        self.pump()

        now = int(self.hs.get_clock().time_msec())
        self.store.user_add_threepid(user1, "email", user1_email, now, now)
        self.store.user_add_threepid(user2, "email", user2_email, now, now)
        self.store.initialise_reserved_users(threepids)
        self.pump()

        active_count = self.store.get_monthly_active_count()

        # Test total counts
        self.assertEquals(self.get_success(active_count), user_num)

        # Test user is marked as active
        timestamp = self.store.user_last_seen_monthly_active(user1)
        self.assertTrue(self.get_success(timestamp))
        timestamp = self.store.user_last_seen_monthly_active(user2)
        self.assertTrue(self.get_success(timestamp))

        # Test that users are never removed from the db.
        self.hs.config.max_mau_value = 0

        self.reactor.advance(FORTY_DAYS)

        self.store.reap_monthly_active_users()
        self.pump()

        active_count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(active_count), user_num)

        # Test that regalar users are removed from the db
        ru_count = 2
        self.store.upsert_monthly_active_user("@ru1:server")
        self.store.upsert_monthly_active_user("@ru2:server")
        self.pump()

        active_count = self.store.get_monthly_active_count()
        self.assertEqual(self.get_success(active_count), user_num + ru_count)
        self.hs.config.max_mau_value = user_num
        self.store.reap_monthly_active_users()
        self.pump()

        active_count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(active_count), user_num)

    def test_can_insert_and_count_mau(self):
        count = self.store.get_monthly_active_count()
        self.assertEqual(0, self.get_success(count))

        self.store.upsert_monthly_active_user("@user:server")
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertEqual(1, self.get_success(count))

    def test_user_last_seen_monthly_active(self):
        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        user_id3 = "@user3:server"

        result = self.store.user_last_seen_monthly_active(user_id1)
        self.assertFalse(self.get_success(result) == 0)

        self.store.upsert_monthly_active_user(user_id1)
        self.store.upsert_monthly_active_user(user_id2)
        self.pump()

        result = self.store.user_last_seen_monthly_active(user_id1)
        self.assertGreater(self.get_success(result), 0)

        result = self.store.user_last_seen_monthly_active(user_id3)
        self.assertNotEqual(self.get_success(result), 0)

    def test_reap_monthly_active_users(self):
        self.hs.config.max_mau_value = 5
        initial_users = 10
        for i in range(initial_users):
            self.store.upsert_monthly_active_user("@user%d:server" % i)
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertTrue(self.get_success(count), initial_users)

        self.store.reap_monthly_active_users()
        self.pump()
        count = self.store.get_monthly_active_count()
        self.assertEquals(
            self.get_success(count), initial_users - self.hs.config.max_mau_value
        )

        self.reactor.advance(FORTY_DAYS)
        self.store.reap_monthly_active_users()
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(count), 0)
