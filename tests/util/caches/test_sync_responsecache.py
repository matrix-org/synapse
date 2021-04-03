from synapse.util.caches.sync_response_cache import SyncResponseCache

from tests.server import get_clock
from tests.unittest import TestCase

# A random callback that returns an object
CALLBACK = lambda: OBJ

# An object, can be equalized to itself
OBJ = {0}

# The key used on the caches throughout this file
KEY = 0

# Easy conditionals
YES = lambda _: True
NO = lambda _: False


class SyncResponseCacheTestCase(TestCase):
    """
    A TestCase class for SyncResponseCache.

    The test-case function naming has some logic to it in it's parts, here's some notes about it:
        first: Denotes tests that test wrap_conditional as a "first caller"
        later: Denotes tests that test wrap_conditional as a non-"first caller"
        multi: Denotes tests that have multiple consequent calls to wrap*
        approve: Denotes tests where the conditional approves of the results (letting cache).
        disapprove: Denotes tests where the conditional disapproves of the result (expiring it).
        hit: Denotes tests which expected outcome is a cache hit.
        miss: Denotes tests which expected outcome is a cache miss.
    """

    def setUp(self):
        self.reactor, self.clock = get_clock()
        self.cache = SyncResponseCache(self.clock, "keeping_cache", timeout_ms=1000)

    # Extra helper functions

    def is_hit(self):
        self.assertEqual(
            OBJ,
            self.successResultOf(self.cache.get(KEY)),
            "cache should not be expired",
        )

    def is_miss(self):
        self.assertIsNone(self.cache.get(KEY), "cache should be expired")

    def pump(self):
        self.reactor.pump((1,))

    # Like CALLBACK, but waits a second, and is async
    async def delayed_callback(self):
        await self.clock.sleep(1)
        return OBJ

    # Actual tests

    def test_cache_first_approve_hit(self):
        self.cache.wrap_conditional(KEY, YES, CALLBACK)

        self.is_hit()

    def test_cache_first_disapprove_miss(self):
        self.cache.wrap_conditional(KEY, NO, CALLBACK)

        self.is_miss()

    def test_cache_later_approve_hit(self):
        # first
        self.cache.wrap(KEY, CALLBACK)

        # second
        self.cache.wrap_conditional(KEY, YES, CALLBACK)

        self.is_hit()

    def test_cache_later_disapprove_hit(self):
        # first
        self.cache.wrap(KEY, CALLBACK)

        # second
        self.cache.wrap_conditional(KEY, NO, CALLBACK)

        self.is_hit()

    # Show how later calls to wrap_conditional dont change it's conditional outcome
    # These need self.delayed_callback, because else the first wrap* (by logic of run_in_background)
    # will also run the function *and* it's callbacks, including (Sync)ResponseCache.set::{{remove}}

    def test_cache_multi_first_approve_later_approve_hit(self):
        # first
        self.cache.wrap_conditional(KEY, YES, self.delayed_callback)

        # second
        self.cache.wrap_conditional(KEY, YES, self.delayed_callback)

        self.pump()

        self.is_hit()

    def test_cache_multi_first_approve_later_disapprove_hit(self):
        # first
        self.cache.wrap_conditional(KEY, YES, self.delayed_callback)

        # second
        self.cache.wrap_conditional(KEY, NO, self.delayed_callback)

        self.pump()

        self.is_hit()

    def test_cache_multi_first_disapprove_later_approve_miss(self):
        # first
        self.cache.wrap_conditional(KEY, NO, self.delayed_callback)

        # second
        self.cache.wrap_conditional(KEY, YES, self.delayed_callback)

        self.pump()

        self.is_miss()

    def test_cache_multi_first_disapprove_later_disapprove_miss(self):
        # first
        self.cache.wrap_conditional(KEY, NO, self.delayed_callback)

        # second
        self.cache.wrap_conditional(KEY, NO, self.delayed_callback)

        self.pump()

        self.is_miss()
