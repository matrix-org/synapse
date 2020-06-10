from synapse.api.ratelimiting import LimitExceededError, Ratelimiter

from tests import unittest


class TestRatelimiter(unittest.TestCase):
    def test_allowed_via_can_do_action(self):
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)
        allowed, time_allowed = limiter.can_do_action(key="test_id", _time_now_s=0)
        self.assertTrue(allowed)
        self.assertEquals(10.0, time_allowed)

        allowed, time_allowed = limiter.can_do_action(key="test_id", _time_now_s=5)
        self.assertFalse(allowed)
        self.assertEquals(10.0, time_allowed)

        allowed, time_allowed = limiter.can_do_action(key="test_id", _time_now_s=10)
        self.assertTrue(allowed)
        self.assertEquals(20.0, time_allowed)

    def test_allowed_via_ratelimit(self):
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)

        # Shouldn't raise
        limiter.ratelimit(key="test_id", _time_now_s=0)

        # Should raise
        with self.assertRaises(LimitExceededError) as context:
            limiter.ratelimit(key="test_id", _time_now_s=5)
        self.assertEqual(context.exception.retry_after_ms, 5000)

        # Shouldn't raise
        limiter.ratelimit(key="test_id", _time_now_s=10)

    def test_allowed_via_can_do_action_and_overriding_parameters(self):
        """Test that we can override options of can_do_action that would otherwise fail
        an action
        """
        # Create a Ratelimiter with a very low allowed rate_hz and burst_count
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)

        # First attempt should be allowed
        allowed, time_allowed = limiter.can_do_action(("test_id",), _time_now_s=0,)
        self.assertTrue(allowed)
        self.assertEqual(10.0, time_allowed)

        # Second attempt, 1s later, will fail
        allowed, time_allowed = limiter.can_do_action(("test_id",), _time_now_s=1,)
        self.assertFalse(allowed)
        self.assertEqual(10.0, time_allowed)

        # But, if we allow 10 actions/sec for this request, we should be allowed
        # to continue.
        allowed, time_allowed = limiter.can_do_action(
            ("test_id",), _time_now_s=1, rate_hz=10.0
        )
        self.assertTrue(allowed)
        self.assertEqual(1.1, time_allowed)

        # Similarly if we allow a burst of 10 actions
        allowed, time_allowed = limiter.can_do_action(
            ("test_id",), _time_now_s=1, burst_count=10
        )
        self.assertTrue(allowed)
        self.assertEqual(1.0, time_allowed)

    def test_allowed_via_ratelimit_and_overriding_parameters(self):
        """Test that we can override options of the ratelimit method that would otherwise
        fail an action
        """
        # Create a Ratelimiter with a very low allowed rate_hz and burst_count
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)

        # First attempt should be allowed
        limiter.ratelimit(key=("test_id",), _time_now_s=0)

        # Second attempt, 1s later, will fail
        with self.assertRaises(LimitExceededError) as context:
            limiter.ratelimit(key=("test_id",), _time_now_s=1)
        self.assertEqual(context.exception.retry_after_ms, 9000)

        # But, if we allow 10 actions/sec for this request, we should be allowed
        # to continue.
        limiter.ratelimit(key=("test_id",), _time_now_s=1, rate_hz=10.0)

        # Similarly if we allow a burst of 10 actions
        limiter.ratelimit(key=("test_id",), _time_now_s=1, burst_count=10)

    def test_pruning(self):
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)
        limiter.can_do_action(key="test_id_1", _time_now_s=0)

        self.assertIn("test_id_1", limiter.actions)

        limiter.can_do_action(key="test_id_2", _time_now_s=10)

        self.assertNotIn("test_id_1", limiter.actions)
