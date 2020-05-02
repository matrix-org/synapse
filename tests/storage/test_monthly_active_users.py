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
from mock import Mock

from twisted.internet import defer

from synapse.api.constants import UserTypes

from tests import unittest

FORTY_DAYS = 40 * 24 * 60 * 60


class MonthlyActiveUsersTestCase(unittest.HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver()
        self.store = hs.get_datastore()
        hs.config.limit_usage_by_mau = True
        hs.config.max_mau_value = 50

        # Advance the clock a bit
        reactor.advance(FORTY_DAYS)

        return hs

    def test_initialise_reserved_users(self):
        self.hs.config.max_mau_value = 5
        user1 = "@user1:server"
        user1_email = "user1@matrix.org"
        user2 = "@user2:server"
        user2_email = "user2@matrix.org"
        user3 = "@user3:server"
        user3_email = "user3@matrix.org"

        threepids = [
            {"medium": "email", "address": user1_email},
            {"medium": "email", "address": user2_email},
            {"medium": "email", "address": user3_email},
        ]
        self.hs.config.mau_limits_reserved_threepids = threepids
        # -1 because user3 is a support user and does not count
        user_num = len(threepids) - 1

        self.store.register_user(user_id=user1, password_hash=None)
        self.store.register_user(user_id=user2, password_hash=None)
        self.store.register_user(
            user_id=user3, password_hash=None, user_type=UserTypes.SUPPORT
        )
        self.pump()

        now = int(self.hs.get_clock().time_msec())
        self.store.user_add_threepid(user1, "email", user1_email, now, now)
        self.store.user_add_threepid(user2, "email", user2_email, now, now)

        self.store.db.runInteraction(
            "initialise", self.store._initialise_reserved_users, threepids
        )
        self.pump()

        active_count = self.store.get_monthly_active_count()

        # Test total counts, ensure user3 (support user) is not counted
        self.assertEquals(self.get_success(active_count), user_num)

        # Test user is marked as active
        timestamp = self.store.user_last_seen_monthly_active(user1)
        self.assertTrue(self.get_success(timestamp))
        timestamp = self.store.user_last_seen_monthly_active(user2)
        self.assertTrue(self.get_success(timestamp))

        # Test that users are never removed from the db.
        self.hs.config.max_mau_value = 0

        self.reactor.advance(FORTY_DAYS)
        self.hs.config.max_mau_value = 5

        self.store.reap_monthly_active_users()
        self.pump()

        active_count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(active_count), user_num)

        # Test that regular users are removed from the db
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
        self.assertEquals(self.get_success(count), self.hs.config.max_mau_value)

        self.reactor.advance(FORTY_DAYS)
        self.store.reap_monthly_active_users()
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(count), 0)

    def test_reap_monthly_active_users_reserved_users(self):
        """ Tests that reaping correctly handles reaping where reserved users are
        present"""

        self.hs.config.max_mau_value = 5
        initial_users = 5
        reserved_user_number = initial_users - 1
        threepids = []
        for i in range(initial_users):
            user = "@user%d:server" % i
            email = "user%d@example.com" % i
            self.get_success(self.store.upsert_monthly_active_user(user))
            threepids.append({"medium": "email", "address": email})
            # Need to ensure that the most recent entries in the
            # monthly_active_users table are reserved
            now = int(self.hs.get_clock().time_msec())
            if i != 0:
                self.get_success(
                    self.store.register_user(user_id=user, password_hash=None)
                )
                self.get_success(
                    self.store.user_add_threepid(user, "email", email, now, now)
                )

        self.hs.config.mau_limits_reserved_threepids = threepids
        self.store.db.runInteraction(
            "initialise", self.store._initialise_reserved_users, threepids
        )
        count = self.store.get_monthly_active_count()
        self.assertTrue(self.get_success(count), initial_users)

        users = self.store.get_registered_reserved_users()
        self.assertEquals(len(self.get_success(users)), reserved_user_number)

        self.get_success(self.store.reap_monthly_active_users())
        count = self.store.get_monthly_active_count()
        self.assertEquals(self.get_success(count), self.hs.config.max_mau_value)

    def test_populate_monthly_users_is_guest(self):
        # Test that guest users are not added to mau list
        user_id = "@user_id:host"
        self.store.register_user(user_id=user_id, password_hash=None, make_guest=True)
        self.store.upsert_monthly_active_user = Mock()
        self.store.populate_monthly_active_users(user_id)
        self.pump()
        self.store.upsert_monthly_active_user.assert_not_called()

    def test_populate_monthly_users_should_update(self):
        self.store.upsert_monthly_active_user = Mock()

        self.store.is_trial_user = Mock(return_value=defer.succeed(False))

        self.store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(None)
        )
        self.store.populate_monthly_active_users("user_id")
        self.pump()
        self.store.upsert_monthly_active_user.assert_called_once()

    def test_populate_monthly_users_should_not_update(self):
        self.store.upsert_monthly_active_user = Mock()

        self.store.is_trial_user = Mock(return_value=defer.succeed(False))
        self.store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(self.hs.get_clock().time_msec())
        )
        self.store.populate_monthly_active_users("user_id")
        self.pump()
        self.store.upsert_monthly_active_user.assert_not_called()

    def test_get_reserved_real_user_account(self):
        # Test no reserved users, or reserved threepids
        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEquals(len(users), 0)
        # Test reserved users but no registered users

        user1 = "@user1:example.com"
        user2 = "@user2:example.com"

        user1_email = "user1@example.com"
        user2_email = "user2@example.com"
        threepids = [
            {"medium": "email", "address": user1_email},
            {"medium": "email", "address": user2_email},
        ]
        self.hs.config.mau_limits_reserved_threepids = threepids
        self.store.db.runInteraction(
            "initialise", self.store._initialise_reserved_users, threepids
        )

        self.pump()
        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEquals(len(users), 0)

        # Test reserved registed users
        self.store.register_user(user_id=user1, password_hash=None)
        self.store.register_user(user_id=user2, password_hash=None)
        self.pump()

        now = int(self.hs.get_clock().time_msec())
        self.store.user_add_threepid(user1, "email", user1_email, now, now)
        self.store.user_add_threepid(user2, "email", user2_email, now, now)

        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEquals(len(users), len(threepids))

    def test_support_user_not_add_to_mau_limits(self):
        support_user_id = "@support:test"
        count = self.store.get_monthly_active_count()
        self.pump()
        self.assertEqual(self.get_success(count), 0)

        self.store.register_user(
            user_id=support_user_id, password_hash=None, user_type=UserTypes.SUPPORT
        )

        self.store.upsert_monthly_active_user(support_user_id)
        count = self.store.get_monthly_active_count()
        self.pump()
        self.assertEqual(self.get_success(count), 0)

    def test_track_monthly_users_without_cap(self):
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.mau_stats_only = True
        self.hs.config.max_mau_value = 1  # should not matter

        count = self.store.get_monthly_active_count()
        self.assertEqual(0, self.get_success(count))

        self.store.upsert_monthly_active_user("@user1:server")
        self.store.upsert_monthly_active_user("@user2:server")
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertEqual(2, self.get_success(count))

    def test_no_users_when_not_tracking(self):
        self.hs.config.limit_usage_by_mau = False
        self.hs.config.mau_stats_only = False
        self.store.upsert_monthly_active_user = Mock()

        self.store.populate_monthly_active_users("@user:sever")
        self.pump()

        self.store.upsert_monthly_active_user.assert_not_called()

    def test_get_monthly_active_count_by_service(self):
        appservice1_user1 = "@appservice1_user1:example.com"
        appservice1_user2 = "@appservice1_user2:example.com"

        appservice2_user1 = "@appservice2_user1:example.com"
        native_user1 = "@native_user1:example.com"

        service1 = "service1"
        service2 = "service2"
        native = "native"

        self.store.register_user(
            user_id=appservice1_user1, password_hash=None, appservice_id=service1
        )
        self.store.register_user(
            user_id=appservice1_user2, password_hash=None, appservice_id=service1
        )
        self.store.register_user(
            user_id=appservice2_user1, password_hash=None, appservice_id=service2
        )
        self.store.register_user(user_id=native_user1, password_hash=None)
        self.pump()

        count = self.store.get_monthly_active_count_by_service()
        self.assertEqual({}, self.get_success(count))

        self.store.upsert_monthly_active_user(native_user1)
        self.store.upsert_monthly_active_user(appservice1_user1)
        self.store.upsert_monthly_active_user(appservice1_user2)
        self.store.upsert_monthly_active_user(appservice2_user1)
        self.pump()

        count = self.store.get_monthly_active_count()
        self.assertEqual(4, self.get_success(count))

        count = self.store.get_monthly_active_count_by_service()
        result = self.get_success(count)

        self.assertEqual(2, result[service1])
        self.assertEqual(1, result[service2])
        self.assertEqual(1, result[native])
