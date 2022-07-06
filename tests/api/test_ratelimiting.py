from synapse.api.ratelimiting import LimitExceededError, Ratelimiter
from synapse.appservice import ApplicationService
from synapse.types import create_requester

from tests import unittest


class TestRatelimiter(unittest.HomeserverTestCase):
    def test_allowed_via_can_do_action(self):
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", _time_now_s=0)
        )
        self.assertTrue(allowed)
        self.assertEqual(10.0, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", _time_now_s=5)
        )
        self.assertFalse(allowed)
        self.assertEqual(10.0, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", _time_now_s=10)
        )
        self.assertTrue(allowed)
        self.assertEqual(20.0, time_allowed)

    def test_allowed_appservice_ratelimited_via_can_requester_do_action(self):
        appservice = ApplicationService(
            None,
            id="foo",
            rate_limited=True,
            sender="@as:example.com",
        )
        as_requester = create_requester("@user:example.com", app_service=appservice)

        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=0)
        )
        self.assertTrue(allowed)
        self.assertEqual(10.0, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=5)
        )
        self.assertFalse(allowed)
        self.assertEqual(10.0, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=10)
        )
        self.assertTrue(allowed)
        self.assertEqual(20.0, time_allowed)

    def test_allowed_appservice_via_can_requester_do_action(self):
        appservice = ApplicationService(
            None,
            id="foo",
            rate_limited=False,
            sender="@as:example.com",
        )
        as_requester = create_requester("@user:example.com", app_service=appservice)

        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=0)
        )
        self.assertTrue(allowed)
        self.assertEqual(-1, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=5)
        )
        self.assertTrue(allowed)
        self.assertEqual(-1, time_allowed)

        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(as_requester, _time_now_s=10)
        )
        self.assertTrue(allowed)
        self.assertEqual(-1, time_allowed)

    def test_allowed_via_ratelimit(self):
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )

        # Shouldn't raise
        self.get_success_or_raise(limiter.ratelimit(None, key="test_id", _time_now_s=0))

        # Should raise
        with self.assertRaises(LimitExceededError) as context:
            self.get_success_or_raise(
                limiter.ratelimit(None, key="test_id", _time_now_s=5)
            )
        self.assertEqual(context.exception.retry_after_ms, 5000)

        # Shouldn't raise
        self.get_success_or_raise(
            limiter.ratelimit(None, key="test_id", _time_now_s=10)
        )

    def test_allowed_via_can_do_action_and_overriding_parameters(self):
        """Test that we can override options of can_do_action that would otherwise fail
        an action
        """
        # Create a Ratelimiter with a very low allowed rate_hz and burst_count
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )

        # First attempt should be allowed
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(
                None,
                ("test_id",),
                _time_now_s=0,
            )
        )
        self.assertTrue(allowed)
        self.assertEqual(10.0, time_allowed)

        # Second attempt, 1s later, will fail
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(
                None,
                ("test_id",),
                _time_now_s=1,
            )
        )
        self.assertFalse(allowed)
        self.assertEqual(10.0, time_allowed)

        # But, if we allow 10 actions/sec for this request, we should be allowed
        # to continue.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, ("test_id",), _time_now_s=1, rate_hz=10.0)
        )
        self.assertTrue(allowed)
        self.assertEqual(1.1, time_allowed)

        # Similarly if we allow a burst of 10 actions
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, ("test_id",), _time_now_s=1, burst_count=10)
        )
        self.assertTrue(allowed)
        self.assertEqual(1.0, time_allowed)

    def test_allowed_via_ratelimit_and_overriding_parameters(self):
        """Test that we can override options of the ratelimit method that would otherwise
        fail an action
        """
        # Create a Ratelimiter with a very low allowed rate_hz and burst_count
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )

        # First attempt should be allowed
        self.get_success_or_raise(
            limiter.ratelimit(None, key=("test_id",), _time_now_s=0)
        )

        # Second attempt, 1s later, will fail
        with self.assertRaises(LimitExceededError) as context:
            self.get_success_or_raise(
                limiter.ratelimit(None, key=("test_id",), _time_now_s=1)
            )
        self.assertEqual(context.exception.retry_after_ms, 9000)

        # But, if we allow 10 actions/sec for this request, we should be allowed
        # to continue.
        self.get_success_or_raise(
            limiter.ratelimit(None, key=("test_id",), _time_now_s=1, rate_hz=10.0)
        )

        # Similarly if we allow a burst of 10 actions
        self.get_success_or_raise(
            limiter.ratelimit(None, key=("test_id",), _time_now_s=1, burst_count=10)
        )

    def test_pruning(self):
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=1
        )
        self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id_1", _time_now_s=0)
        )

        self.assertIn("test_id_1", limiter.actions)

        self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id_2", _time_now_s=10)
        )

        self.assertNotIn("test_id_1", limiter.actions)

    def test_db_user_override(self):
        """Test that users that have ratelimiting disabled in the DB aren't
        ratelimited.
        """
        store = self.hs.get_datastores().main

        user_id = "@user:test"
        requester = create_requester(user_id)

        self.get_success(
            store.db_pool.simple_insert(
                table="ratelimit_override",
                values={
                    "user_id": user_id,
                    "messages_per_second": None,
                    "burst_count": None,
                },
                desc="test_db_user_override",
            )
        )

        limiter = Ratelimiter(store=store, clock=None, rate_hz=0.1, burst_count=1)

        # Shouldn't raise
        for _ in range(20):
            self.get_success_or_raise(limiter.ratelimit(requester, _time_now_s=0))

    def test_multiple_actions(self):
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=3
        )
        # Test that 4 actions aren't allowed with a maximum burst of 3.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", n_actions=4, _time_now_s=0)
        )
        self.assertFalse(allowed)

        # Test that 3 actions are allowed with a maximum burst of 3.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", n_actions=3, _time_now_s=0)
        )
        self.assertTrue(allowed)
        self.assertEqual(10.0, time_allowed)

        # Test that, after doing these 3 actions, we can't do any more actions without
        # waiting.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", n_actions=1, _time_now_s=0)
        )
        self.assertFalse(allowed)
        self.assertEqual(10.0, time_allowed)

        # Test that after waiting we would be able to do only 1 action.
        # Note that we don't actually do it (update=False) here.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(
                None,
                key="test_id",
                update=False,
                n_actions=1,
                _time_now_s=10,
            )
        )
        self.assertTrue(allowed)
        # We would be able to do the 5th action at t=20.
        self.assertEqual(20.0, time_allowed)

        # Attempt (but fail) to perform TWO actions at t=10.
        # Those would be the 4th and 5th actions.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", n_actions=2, _time_now_s=10)
        )
        self.assertFalse(allowed)
        # The returned time allowed for the next action is now even though we weren't
        # allowed to perform the action because whilst we don't allow 2 actions,
        # we could still do 1.
        self.assertEqual(10.0, time_allowed)

        # Test that after waiting until t=20, we can do perform 2 actions.
        # These are the 4th and 5th actions.
        allowed, time_allowed = self.get_success_or_raise(
            limiter.can_do_action(None, key="test_id", n_actions=2, _time_now_s=20)
        )
        self.assertTrue(allowed)
        # We would be able to do the 6th action at t=30.
        self.assertEqual(30.0, time_allowed)

    def test_rate_limit_burst_only_given_once(self) -> None:
        """
        Regression test against a bug that meant that you could build up
        extra tokens by timing requests.
        """
        limiter = Ratelimiter(
            store=self.hs.get_datastores().main, clock=None, rate_hz=0.1, burst_count=3
        )

        def consume_at(time: float) -> bool:
            success, _ = self.get_success_or_raise(
                limiter.can_do_action(requester=None, key="a", _time_now_s=time)
            )
            return success

        # Use all our 3 burst tokens
        self.assertTrue(consume_at(0.0))
        self.assertTrue(consume_at(0.1))
        self.assertTrue(consume_at(0.2))

        # Wait to recover 1 token (10 seconds at 0.1 Hz).
        self.assertTrue(consume_at(10.1))

        # Check that we get rate limited after using that token.
        self.assertFalse(consume_at(11.1))
