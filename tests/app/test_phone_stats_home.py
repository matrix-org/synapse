import synapse
from synapse.app.phone_stats_home import start_phone_stats_home
from synapse.rest.client import login, room

from tests import unittest
from tests.unittest import HomeserverTestCase

FIVE_MINUTES_IN_SECONDS = 300
ONE_DAY_IN_SECONDS = 86400


class PhoneHomeTestCase(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    # Override the retention time for the user_ips table because otherwise it
    # gets pruned too aggressively for our R30 test.
    @unittest.override_config({"user_ips_max_age": "365d"})
    def test_r30_minimum_usage(self):
        """
        Tests the minimum amount of interaction necessary for the R30 metric
        to consider a user 'retained'.
        """

        # Register a user, log it in, create a room and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)

        # Check the R30 results do not count that user.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        # Advance 30 days (+ 1 second, because strict inequality causes issues if we are
        # bang on 30 days later).
        self.reactor.advance(30 * ONE_DAY_IN_SECONDS + 1)

        # (Make sure the user isn't somehow counted by this point.)
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        # Send a message (this counts as activity)
        self.helper.send(room_id, "message2", tok=access_token)

        # We have to wait some time for _update_client_ips_batch to get
        # called and update the user_ips table.
        self.reactor.advance(2 * 60 * 60)

        # *Now* the user is counted.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance 29 days. The user has now not posted for 29 days.
        self.reactor.advance(29 * ONE_DAY_IN_SECONDS)

        # The user is still counted.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance another day. The user has now not posted for 30 days.
        self.reactor.advance(ONE_DAY_IN_SECONDS)

        # The user is now no longer counted in R30.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

    def test_r30_minimum_usage_using_default_config(self):
        """
        Tests the minimum amount of interaction necessary for the R30 metric
        to consider a user 'retained'.

        N.B. This test does not override the `user_ips_max_age` config setting,
        which defaults to 28 days.
        """

        # Register a user, log it in, create a room and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)

        # Check the R30 results do not count that user.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        # Advance 30 days (+ 1 second, because strict inequality causes issues if we are
        # bang on 30 days later).
        self.reactor.advance(30 * ONE_DAY_IN_SECONDS + 1)

        # (Make sure the user isn't somehow counted by this point.)
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        # Send a message (this counts as activity)
        self.helper.send(room_id, "message2", tok=access_token)

        # We have to wait some time for _update_client_ips_batch to get
        # called and update the user_ips table.
        self.reactor.advance(2 * 60 * 60)

        # *Now* the user is counted.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance 27 days. The user has now not posted for 27 days.
        self.reactor.advance(27 * ONE_DAY_IN_SECONDS)

        # The user is still counted.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})

        # Advance another day. The user has now not posted for 28 days.
        self.reactor.advance(ONE_DAY_IN_SECONDS)

        # The user is now no longer counted in R30.
        # (This is because the user_ips table has been pruned, which by default
        # only preserves the last 28 days of entries.)
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

    def test_r30_user_must_be_retained_for_at_least_a_month(self):
        """
        Tests that a newly-registered user must be retained for a whole month
        before appearing in the R30 statistic, even if they post every day
        during that time!
        """
        # Register a user and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)

        # Check the user does not contribute to R30 yet.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 0})

        for _ in range(30):
            # This loop posts a message every day for 30 days
            self.reactor.advance(ONE_DAY_IN_SECONDS)
            self.helper.send(room_id, "I'm still here", tok=access_token)

            # Notice that the user *still* does not contribute to R30!
            r30_results = self.get_success(
                self.hs.get_datastores().main.count_r30_users()
            )
            self.assertEqual(r30_results, {"all": 0})

        self.reactor.advance(ONE_DAY_IN_SECONDS)
        self.helper.send(room_id, "Still here!", tok=access_token)

        # *Now* the user appears in R30.
        r30_results = self.get_success(self.hs.get_datastores().main.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "unknown": 1})


class PhoneHomeR30V2TestCase(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def _advance_to(self, desired_time_secs: float):
        now = self.hs.get_clock().time()
        assert now < desired_time_secs
        self.reactor.advance(desired_time_secs - now)

    def make_homeserver(self, reactor, clock):
        hs = super(PhoneHomeR30V2TestCase, self).make_homeserver(reactor, clock)

        # We don't want our tests to actually report statistics, so check
        # that it's not enabled
        assert not hs.config.metrics.report_stats

        # This starts the needed data collection that we rely on to calculate
        # R30v2 metrics.
        start_phone_stats_home(hs)
        return hs

    def test_r30v2_minimum_usage(self):
        """
        Tests the minimum amount of interaction necessary for the R30v2 metric
        to consider a user 'retained'.
        """

        # Register a user, log it in, create a room and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=access_token)
        self.helper.send(room_id, "message", tok=access_token)
        first_post_at = self.hs.get_clock().time()

        # Give time for user_daily_visits table to be updated.
        # (user_daily_visits is updated every 5 minutes using a looping call.)
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        store = self.hs.get_datastores().main

        # Check the R30 results do not count that user.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        # Advance 31 days.
        # (R30v2 includes users with **more** than 30 days between the two visits,
        #  and user_daily_visits records the timestamp as the start of the day.)
        self.reactor.advance(31 * ONE_DAY_IN_SECONDS)
        # Also advance 5 minutes to let another user_daily_visits update occur
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        # (Make sure the user isn't somehow counted by this point.)
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        # Send a message (this counts as activity)
        self.helper.send(room_id, "message2", tok=access_token)

        # We have to wait a few minutes for the user_daily_visits table to
        # be updated by a background process.
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        # *Now* the user is counted.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 1, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        # Advance to JUST under 60 days after the user's first post
        self._advance_to(first_post_at + 60 * ONE_DAY_IN_SECONDS - 5)

        # Check the user is still counted.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 1, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        # Advance into the next day. The user's first activity is now more than 60 days old.
        self._advance_to(first_post_at + 60 * ONE_DAY_IN_SECONDS + 5)

        # Check the user is now no longer counted in R30.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

    def test_r30v2_user_must_be_retained_for_at_least_a_month(self):
        """
        Tests that a newly-registered user must be retained for a whole month
        before appearing in the R30v2 statistic, even if they post every day
        during that time!
        """

        # set a custom user-agent to impersonate Element/Android.
        headers = (
            (
                "User-Agent",
                "Element/1.1 (Linux; U; Android 9; MatrixAndroidSDK_X 0.0.1)",
            ),
        )

        # Register a user and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!", custom_headers=headers)
        room_id = self.helper.create_room_as(
            room_creator=user_id, tok=access_token, custom_headers=headers
        )
        self.helper.send(room_id, "message", tok=access_token, custom_headers=headers)

        # Give time for user_daily_visits table to be updated.
        # (user_daily_visits is updated every 5 minutes using a looping call.)
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        store = self.hs.get_datastores().main

        # Check the user does not contribute to R30 yet.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        for _ in range(30):
            # This loop posts a message every day for 30 days
            self.reactor.advance(ONE_DAY_IN_SECONDS - FIVE_MINUTES_IN_SECONDS)
            self.helper.send(
                room_id, "I'm still here", tok=access_token, custom_headers=headers
            )

            # give time for user_daily_visits to update
            self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

            # Notice that the user *still* does not contribute to R30!
            r30_results = self.get_success(store.count_r30v2_users())
            self.assertEqual(
                r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
            )

        # advance yet another day with more activity
        self.reactor.advance(ONE_DAY_IN_SECONDS)
        self.helper.send(
            room_id, "Still here!", tok=access_token, custom_headers=headers
        )

        # give time for user_daily_visits to update
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        # *Now* the user appears in R30.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 1, "android": 1, "electron": 0, "ios": 0, "web": 0}
        )

    def test_r30v2_returning_dormant_users_not_counted(self):
        """
        Tests that dormant users (users inactive for a long time) do not
        contribute to R30v2 when they return for just a single day.
        This is a key difference between R30 and R30v2.
        """

        # set a custom user-agent to impersonate Element/iOS.
        headers = (
            (
                "User-Agent",
                "Riot/1.4 (iPhone; iOS 13; Scale/4.00)",
            ),
        )

        # Register a user and send a message
        user_id = self.register_user("u1", "secret!")
        access_token = self.login("u1", "secret!", custom_headers=headers)
        room_id = self.helper.create_room_as(
            room_creator=user_id, tok=access_token, custom_headers=headers
        )
        self.helper.send(room_id, "message", tok=access_token, custom_headers=headers)

        # the user goes inactive for 2 months
        self.reactor.advance(60 * ONE_DAY_IN_SECONDS)

        # the user returns for one day, perhaps just to check out a new feature
        self.helper.send(room_id, "message", tok=access_token, custom_headers=headers)

        # Give time for user_daily_visits table to be updated.
        # (user_daily_visits is updated every 5 minutes using a looping call.)
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        store = self.hs.get_datastores().main

        # Check that the user does not contribute to R30v2, even though it's been
        # more than 30 days since registration.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )

        # Check that this is a situation where old R30 differs:
        # old R30 DOES count this as 'retained'.
        r30_results = self.get_success(store.count_r30_users())
        self.assertEqual(r30_results, {"all": 1, "ios": 1})

        # Now we want to check that the user will still be able to appear in
        # R30v2 as long as the user performs some other activity between
        # 30 and 60 days later.
        self.reactor.advance(32 * ONE_DAY_IN_SECONDS)
        self.helper.send(room_id, "message", tok=access_token, custom_headers=headers)

        # (give time for tables to update)
        self.reactor.advance(FIVE_MINUTES_IN_SECONDS)

        # Check the user now satisfies the requirements to appear in R30v2.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 1, "ios": 1, "android": 0, "electron": 0, "web": 0}
        )

        # Advance to 59.5 days after the user's first R30v2-eligible activity.
        self.reactor.advance(27.5 * ONE_DAY_IN_SECONDS)

        # Check the user still appears in R30v2.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 1, "ios": 1, "android": 0, "electron": 0, "web": 0}
        )

        # Advance to 60.5 days after the user's first R30v2-eligible activity.
        self.reactor.advance(ONE_DAY_IN_SECONDS)

        # Check the user no longer appears in R30v2.
        r30_results = self.get_success(store.count_r30v2_users())
        self.assertEqual(
            r30_results, {"all": 0, "android": 0, "electron": 0, "ios": 0, "web": 0}
        )
