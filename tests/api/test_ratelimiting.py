from synapse.api.ratelimiting import Ratelimiter

from tests import unittest


class TestRatelimiter(unittest.TestCase):
    def test_allowed(self):
        limiter = Ratelimiter(rate_hz=0.1, burst_count=1)
        allowed, time_allowed = limiter.can_do_action(key="test_id", time_now_s=0)
        self.assertTrue(allowed)
        self.assertEquals(10.0, time_allowed)

        allowed, time_allowed = limiter.can_do_action(key="test_id", time_now_s=5)
        self.assertFalse(allowed)
        self.assertEquals(10.0, time_allowed)

        allowed, time_allowed = limiter.can_do_action(key="test_id", time_now_s=10)
        self.assertTrue(allowed)
        self.assertEquals(20.0, time_allowed)

    def test_pruning(self):
        limiter = Ratelimiter(rate_hz=0.1, burst_count=1)
        _, _ = limiter.can_do_action(key="test_id_1", time_now_s=0)

        self.assertIn("test_id_1", limiter.actions)

        _, _ = limiter.can_do_action(key="test_id_2", time_now_s=10)

        self.assertNotIn("test_id_1", limiter.actions)
