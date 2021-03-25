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
from tests.test_utils import make_awaitable
from tests.unittest import default_config, override_config

FORTY_DAYS = 40 * 24 * 60 * 60


def gen_3pids(count):
    """Generate `count` threepids as a list."""
    return [
        {"medium": "email", "address": "user%i@matrix.org" % i} for i in range(count)
    ]


class MonthlyActiveUsersTestCase(unittest.HomeserverTestCase):
    def default_config(self):
        config = default_config("test")

        config.update({"limit_usage_by_mau": True, "max_mau_value": 50})

        # apply any additional config which was specified via the override_config
        # decorator.
        if self._extra_config is not None:
            config.update(self._extra_config)

        return config

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        # Advance the clock a bit
        reactor.advance(FORTY_DAYS)

    @override_config({"max_mau_value": 3, "mau_limit_reserved_threepids": gen_3pids(3)})
    def test_initialise_reserved_users(self):
        threepids = self.hs.config.mau_limits_reserved_threepids

        # register three users, of which two have reserved 3pids, and a third
        # which is a support user.
        user1 = "@user1:server"
        user1_email = threepids[0]["address"]
        user2 = "@user2:server"
        user2_email = threepids[1]["address"]
        user3 = "@user3:server"

        self.get_success(self.store.register_user(user_id=user1))
        self.get_success(self.store.register_user(user_id=user2))
        self.get_success(
            self.store.register_user(user_id=user3, user_type=UserTypes.SUPPORT)
        )

        now = int(self.hs.get_clock().time_msec())
        self.get_success(
            self.store.user_add_threepid(user1, "email", user1_email, now, now)
        )
        self.get_success(
            self.store.user_add_threepid(user2, "email", user2_email, now, now)
        )

        # XXX why are we doing this here? this function is only run at startup
        # so it is odd to re-run it here.
        self.get_success(
            self.store.db_pool.runInteraction(
                "initialise", self.store._initialise_reserved_users, threepids
            )
        )

        # the number of users we expect will be counted against the mau limit
        # -1 because user3 is a support user and does not count
        user_num = len(threepids) - 1

        # Check the number of active users. Ensure user3 (support user) is not counted
        active_count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(active_count, user_num)

        # Test each of the registered users is marked as active
        timestamp = self.get_success(self.store.user_last_seen_monthly_active(user1))
        self.assertGreater(timestamp, 0)
        timestamp = self.get_success(self.store.user_last_seen_monthly_active(user2))
        self.assertGreater(timestamp, 0)

        # Test that users with reserved 3pids are not removed from the MAU table
        # XXX some of this is redundant. poking things into the config shouldn't
        # work, and in any case it's not obvious what we expect to happen when
        # we advance the reactor.
        self.hs.config.max_mau_value = 0
        self.reactor.advance(FORTY_DAYS)
        self.hs.config.max_mau_value = 5

        self.get_success(self.store.reap_monthly_active_users())

        active_count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(active_count, user_num)

        # Add some more users and check they are counted as active
        ru_count = 2

        self.get_success(self.store.upsert_monthly_active_user("@ru1:server"))
        self.get_success(self.store.upsert_monthly_active_user("@ru2:server"))

        active_count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(active_count, user_num + ru_count)

        # now run the reaper and check that the number of active users is reduced
        # to max_mau_value
        self.get_success(self.store.reap_monthly_active_users())

        active_count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(active_count, 3)

    def test_can_insert_and_count_mau(self):
        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 0)

        d = self.store.upsert_monthly_active_user("@user:server")
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 1)

    def test_appservice_user_not_counted_in_mau(self):
        self.get_success(
            self.store.register_user(
                user_id="@appservice_user:server", appservice_id="wibble"
            )
        )
        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 0)

        d = self.store.upsert_monthly_active_user("@appservice_user:server")
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 0)

    def test_user_last_seen_monthly_active(self):
        user_id1 = "@user1:server"
        user_id2 = "@user2:server"
        user_id3 = "@user3:server"

        result = self.get_success(self.store.user_last_seen_monthly_active(user_id1))
        self.assertNotEqual(result, 0)

        self.get_success(self.store.upsert_monthly_active_user(user_id1))
        self.get_success(self.store.upsert_monthly_active_user(user_id2))

        result = self.get_success(self.store.user_last_seen_monthly_active(user_id1))
        self.assertGreater(result, 0)

        result = self.get_success(self.store.user_last_seen_monthly_active(user_id3))
        self.assertNotEqual(result, 0)

    @override_config({"max_mau_value": 5})
    def test_reap_monthly_active_users(self):
        initial_users = 10
        for i in range(initial_users):
            self.get_success(
                self.store.upsert_monthly_active_user("@user%d:server" % i)
            )

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, initial_users)

        d = self.store.reap_monthly_active_users()
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, self.hs.config.max_mau_value)

        self.reactor.advance(FORTY_DAYS)

        d = self.store.reap_monthly_active_users()
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 0)

    # Note that below says mau_limit (no s), this is the name of the config
    # value, although it gets stored on the config object as mau_limits.
    @override_config({"max_mau_value": 5, "mau_limit_reserved_threepids": gen_3pids(5)})
    def test_reap_monthly_active_users_reserved_users(self):
        """Tests that reaping correctly handles reaping where reserved users are
        present"""
        threepids = self.hs.config.mau_limits_reserved_threepids
        initial_users = len(threepids)
        reserved_user_number = initial_users - 1
        for i in range(initial_users):
            user = "@user%d:server" % i
            email = "user%d@matrix.org" % i

            self.get_success(self.store.upsert_monthly_active_user(user))

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

        d = self.store.db_pool.runInteraction(
            "initialise", self.store._initialise_reserved_users, threepids
        )
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, initial_users)

        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEqual(len(users), reserved_user_number)

        d = self.store.reap_monthly_active_users()
        self.get_success(d)

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, self.hs.config.max_mau_value)

    def test_populate_monthly_users_is_guest(self):
        # Test that guest users are not added to mau list
        user_id = "@user_id:host"

        d = self.store.register_user(
            user_id=user_id, password_hash=None, make_guest=True
        )
        self.get_success(d)

        self.store.upsert_monthly_active_user = Mock(return_value=make_awaitable(None))

        d = self.store.populate_monthly_active_users(user_id)
        self.get_success(d)

        self.store.upsert_monthly_active_user.assert_not_called()

    def test_populate_monthly_users_should_update(self):
        self.store.upsert_monthly_active_user = Mock(return_value=make_awaitable(None))

        self.store.is_trial_user = Mock(return_value=defer.succeed(False))

        self.store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(None)
        )
        d = self.store.populate_monthly_active_users("user_id")
        self.get_success(d)

        self.store.upsert_monthly_active_user.assert_called_once()

    def test_populate_monthly_users_should_not_update(self):
        self.store.upsert_monthly_active_user = Mock(return_value=make_awaitable(None))

        self.store.is_trial_user = Mock(return_value=defer.succeed(False))
        self.store.user_last_seen_monthly_active = Mock(
            return_value=defer.succeed(self.hs.get_clock().time_msec())
        )

        d = self.store.populate_monthly_active_users("user_id")
        self.get_success(d)

        self.store.upsert_monthly_active_user.assert_not_called()

    def test_get_reserved_real_user_account(self):
        # Test no reserved users, or reserved threepids
        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEqual(len(users), 0)

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
        d = self.store.db_pool.runInteraction(
            "initialise", self.store._initialise_reserved_users, threepids
        )
        self.get_success(d)

        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEqual(len(users), 0)

        # Test reserved registered users
        self.get_success(self.store.register_user(user_id=user1, password_hash=None))
        self.get_success(self.store.register_user(user_id=user2, password_hash=None))

        now = int(self.hs.get_clock().time_msec())
        self.get_success(
            self.store.user_add_threepid(user1, "email", user1_email, now, now)
        )
        self.get_success(
            self.store.user_add_threepid(user2, "email", user2_email, now, now)
        )

        users = self.get_success(self.store.get_registered_reserved_users())
        self.assertEqual(len(users), len(threepids))

    def test_support_user_not_add_to_mau_limits(self):
        support_user_id = "@support:test"

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 0)

        d = self.store.register_user(
            user_id=support_user_id, password_hash=None, user_type=UserTypes.SUPPORT
        )
        self.get_success(d)

        d = self.store.upsert_monthly_active_user(support_user_id)
        self.get_success(d)

        d = self.store.get_monthly_active_count()
        count = self.get_success(d)
        self.assertEqual(count, 0)

    # Note that the max_mau_value setting should not matter.
    @override_config(
        {"limit_usage_by_mau": False, "mau_stats_only": True, "max_mau_value": 1}
    )
    def test_track_monthly_users_without_cap(self):
        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(0, count)

        self.get_success(self.store.upsert_monthly_active_user("@user1:server"))
        self.get_success(self.store.upsert_monthly_active_user("@user2:server"))

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(2, count)

    @override_config({"limit_usage_by_mau": False, "mau_stats_only": False})
    def test_no_users_when_not_tracking(self):
        self.store.upsert_monthly_active_user = Mock(return_value=make_awaitable(None))

        self.get_success(self.store.populate_monthly_active_users("@user:sever"))

        self.store.upsert_monthly_active_user.assert_not_called()

    def test_get_monthly_active_count_by_service(self):
        appservice1_user1 = "@appservice1_user1:example.com"
        appservice1_user2 = "@appservice1_user2:example.com"

        appservice2_user1 = "@appservice2_user1:example.com"
        native_user1 = "@native_user1:example.com"

        service1 = "service1"
        service2 = "service2"
        native = "native"

        self.get_success(
            self.store.register_user(
                user_id=appservice1_user1, password_hash=None, appservice_id=service1
            )
        )
        self.get_success(
            self.store.register_user(
                user_id=appservice1_user2, password_hash=None, appservice_id=service1
            )
        )
        self.get_success(
            self.store.register_user(
                user_id=appservice2_user1, password_hash=None, appservice_id=service2
            )
        )
        self.get_success(
            self.store.register_user(user_id=native_user1, password_hash=None)
        )

        count = self.get_success(self.store.get_monthly_active_count_by_service())
        self.assertEqual(count, {})

        self.get_success(self.store.upsert_monthly_active_user(native_user1))
        self.get_success(self.store.upsert_monthly_active_user(appservice1_user1))
        self.get_success(self.store.upsert_monthly_active_user(appservice1_user2))
        self.get_success(self.store.upsert_monthly_active_user(appservice2_user1))

        count = self.get_success(self.store.get_monthly_active_count())
        self.assertEqual(count, 1)

        d = self.store.get_monthly_active_count_by_service()
        result = self.get_success(d)

        self.assertEqual(result[service1], 2)
        self.assertEqual(result[service2], 1)
        self.assertEqual(result[native], 1)
