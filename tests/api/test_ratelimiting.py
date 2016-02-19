from synapse.api.ratelimiting import Ratelimiter

from tests import unittest


class TestRatelimiter(unittest.TestCase):

    def test_allowed(self):
        limiter = Ratelimiter()
        allowed, time_allowed = limiter.send_message(
            user_id="test_id", time_now_s=0, msg_rate_hz=0.1, burst_count=1,
        )
        self.assertTrue(allowed)
        self.assertEquals(10., time_allowed)

        allowed, time_allowed = limiter.send_message(
            user_id="test_id", time_now_s=5, msg_rate_hz=0.1, burst_count=1,
        )
        self.assertFalse(allowed)
        self.assertEquals(10., time_allowed)

        allowed, time_allowed = limiter.send_message(
            user_id="test_id", time_now_s=10, msg_rate_hz=0.1, burst_count=1
        )
        self.assertTrue(allowed)
        self.assertEquals(20., time_allowed)

    def test_pruning(self):
        limiter = Ratelimiter()
        allowed, time_allowed = limiter.send_message(
            user_id="test_id_1", time_now_s=0, msg_rate_hz=0.1, burst_count=1,
        )

        self.assertIn("test_id_1", limiter.message_counts)

        allowed, time_allowed = limiter.send_message(
            user_id="test_id_2", time_now_s=10, msg_rate_hz=0.1, burst_count=1
        )

        self.assertNotIn("test_id_1", limiter.message_counts)
