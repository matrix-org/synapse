from synapse.api.ratelimiting import LimitExceededError, Ratelimiter

from tests import unittest


class TestRatelimiter(unittest.TestCase):
    def test_allowed(self):
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
        self.assertRaises(
            LimitExceededError, limiter.ratelimit, key="test_id", _time_now_s=5,
        )

        # Shouldn't raise
        limiter.ratelimit(key="test_id", _time_now_s=10)

    def test_allowed_by_overriding_parameters(self):
        """Test that we can override options of a Ratelimiter that would otherwise fail
        an action
        """
        # Create a Ratelimiter with a very low allowed rate_hz and burst_count
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)

        # First attempt should be allowed
        time_now = 0
        expected_allowed = 10.0

        # Shouldn't raise
        limiter.ratelimit(("test_id",), _time_now_s=time_now, update=False)

        allowed, time_allowed = limiter.can_do_action(
            key=("test_id",), _time_now_s=time_now,
        )
        self.assertTrue(allowed)
        self.assertEquals(expected_allowed, time_allowed)

        # Second attempt, 1s later, will fail
        time_now = 1
        expected_allowed = 10.0

        # We expect a LimitExceededError to be raised
        try:
            limiter.ratelimit(("test_id",), _time_now_s=time_now, update=False)

            # We shouldn't reach here
            self.assertTrue(False, "LimitExceededError was not raised")
        except LimitExceededError as e:
            self.assertEquals(e.retry_after_ms / 1000, expected_allowed - time_now)

        allowed, time_allowed = limiter.can_do_action(
            key=("test_id",), _time_now_s=time_now,
        )
        self.assertFalse(allowed)
        self.assertEquals(expected_allowed, time_allowed)

        # But, if we allow 10 actions/sec in this specific instance, we should be allowed
        # to continue. burst_count is still 1.0
        time_now = 1
        expected_allowed = 1.1  # Changing rate_hz scales our time_allowed

        # Shouldn't raise
        limiter.ratelimit(
            key=("test_id",), _time_now_s=time_now, rate_hz=10, update=False
        )

        allowed, time_allowed = limiter.can_do_action(
            key=("test_id",), _time_now_s=time_now, rate_hz=10,
        )
        self.assertTrue(allowed)
        self.assertEquals(expected_allowed, time_allowed)

        # Similarly if we allow a burst of 10 actions, but a rate_hz of 0.1
        time_now = 1
        expected_allowed = 1.0
        limiter.ratelimit(
            key=("test_id",), _time_now_s=time_now, burst_count=10, update=False,
        )

        allowed, time_allowed = limiter.can_do_action(
            key=("test_id",), _time_now_s=time_now, burst_count=10,
        )
        self.assertTrue(allowed)
        self.assertEquals(expected_allowed, time_allowed)

    def test_pruning(self):
        limiter = Ratelimiter(clock=None, rate_hz=0.1, burst_count=1)
        _, _ = limiter.can_do_action(key="test_id_1", _time_now_s=0)

        self.assertIn("test_id_1", limiter.actions)

        _, _ = limiter.can_do_action(key="test_id_2", _time_now_s=10)

        self.assertNotIn("test_id_1", limiter.actions)
