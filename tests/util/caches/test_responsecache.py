# Copyright 2021 Vector Creations Ltd
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

from twisted.internet.task import Clock

from synapse.util import Clock as SynapseClock
from synapse.util.caches.response_cache import ResponseCache

from tests.unittest import TestCase

# few notes about test naming here:
# 'wait': denotes tests that have an element of "waiting" before its wrapped result becomes available
# 'expire': denotes tests that test expiry after assured existence


class DeferredCacheTestCase(TestCase):
    def setUp(self):
        self.reactor = Clock()
        self.synapse_clock = SynapseClock(self.reactor)

    @staticmethod
    async def instant_return(o: str) -> str:
        return o

    async def delayed_return(self, o: str) -> str:
        await self.synapse_clock.sleep(1)
        return o

    def test_cache_hit(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        expected_result = "howdy"

        wrap_d = cache.wrap(0, self.instant_return, expected_result)

        self.assertEqual(
            expected_result,
            self.successResultOf(wrap_d),
            "initial wrap result should be the same",
        )
        self.assertEqual(
            expected_result,
            self.successResultOf(cache.get(0)),
            "cache should have the result",
        )

    def test_cache_miss(self):
        cache = ResponseCache(self.synapse_clock, "trashing_cache", timeout_ms=0)

        expected_result = "howdy"

        wrap_d = cache.wrap(0, self.instant_return, expected_result)

        self.assertEqual(
            expected_result,
            self.successResultOf(wrap_d),
            "initial wrap result should be the same",
        )
        self.assertIsNone(cache.get(0), "cache should not have the result now")

    def test_cache_expire(self):
        cache = ResponseCache(self.synapse_clock, "short_cache", timeout_ms=1000)

        expected_result = "howdy"

        wrap_d = cache.wrap(0, self.instant_return, expected_result)

        self.assertEqual(expected_result, self.successResultOf(wrap_d))
        self.assertEqual(
            expected_result,
            self.successResultOf(cache.get(0)),
            "cache should still have the result",
        )

        # cache eviction timer is handled
        self.reactor.pump((2,))

        self.assertIsNone(cache.get(0), "cache should not have the result now")

    def test_cache_wait_hit(self):
        cache = ResponseCache(self.synapse_clock, "neutral_cache")

        expected_result = "howdy"

        wrap_d = cache.wrap(0, self.delayed_return, expected_result)
        self.assertNoResult(wrap_d)

        # function wakes up, returns result
        self.reactor.pump((2,))

        self.assertEqual(expected_result, self.successResultOf(wrap_d))

    def test_cache_wait_expire(self):
        cache = ResponseCache(self.synapse_clock, "short_cache", timeout_ms=3000)

        expected_result = "howdy"

        wrap_d = cache.wrap(0, self.delayed_return, expected_result)
        self.assertNoResult(wrap_d)

        # stop at 1 second to callback cache eviction callLater at that time, then another to set time at 2
        self.reactor.pump((1, 1))

        self.assertEqual(expected_result, self.successResultOf(wrap_d))
        self.assertEqual(
            expected_result,
            self.successResultOf(cache.get(0)),
            "cache should still have the result",
        )

        # (1 + 1 + 2) < 3.0, cache eviction timer is handled
        self.reactor.pump((2,))

        self.assertIsNone(cache.get(0), "cache should not have the result now")


class ConditionalDeferredCacheTestCase(DeferredCacheTestCase):
    def test_one_false(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"
        english_greeting = "greetings"

        def is_english_greeting(greeting) -> bool:
            return greeting == english_greeting

        wrap_d = cache.wrap_conditional(
            0, is_english_greeting, self.instant_return, texan_greeting
        )

        self.assertEqual(texan_greeting, self.successResultOf(wrap_d))
        self.assertIsNone(cache.get(0), "cache should not have the result")

    def test_one_true(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"

        def is_texan_greeting(greeting) -> bool:
            return greeting == texan_greeting

        wrap_d = cache.wrap_conditional(
            0, is_texan_greeting, self.instant_return, texan_greeting
        )

        self.assertEqual(texan_greeting, self.successResultOf(wrap_d))
        self.assertEqual(
            texan_greeting,
            self.successResultOf(cache.get(0)),
            "cache should have the result",
        )

    def test_one_false_with_empty(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"
        english_greeting = "greetings"

        def is_english_greeting(greeting) -> bool:
            return greeting == english_greeting

        wrap_d = cache.wrap_conditional(
            0, is_english_greeting, self.delayed_return, texan_greeting
        )
        wrap_empty = cache.wrap(0, self.delayed_return, texan_greeting)

        self.reactor.pump((1,))

        self.assertEqual(texan_greeting, self.successResultOf(wrap_d))
        self.assertEqual(texan_greeting, self.successResultOf(wrap_empty))
        self.assertIsNone(cache.get(0), "cache should not have the result")

    def test_one_true_with_empty(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"

        def is_texan_greeting(greeting) -> bool:
            return greeting == texan_greeting

        wrap_d = cache.wrap_conditional(
            0, is_texan_greeting, self.delayed_return, texan_greeting
        )
        wrap_empty = cache.wrap(0, self.delayed_return, texan_greeting)

        self.reactor.pump((1,))

        self.assertEqual(texan_greeting, self.successResultOf(wrap_d))
        self.assertEqual(texan_greeting, self.successResultOf(wrap_empty))
        self.assertEqual(
            texan_greeting,
            self.successResultOf(cache.get(0)),
            "cache should have the result",
        )

    def test_multiple_mixed(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"
        english_greeting = "greetings"

        def is_english_greeting(greeting) -> bool:
            return greeting == english_greeting

        def is_texan_greeting(greeting) -> bool:
            return greeting == texan_greeting

        negative_wrap = cache.wrap_conditional(
            0, is_english_greeting, self.delayed_return, texan_greeting
        )

        positive_wraps = {
            cache.wrap_conditional(
                0, is_texan_greeting, self.delayed_return, texan_greeting
            )
            for _ in range(5)
        }

        self.reactor.pump((1,))

        for wrap in positive_wraps | {negative_wrap}:
            self.assertEqual(
                texan_greeting,
                self.successResultOf(wrap),
                "wrap deferred {!r} should have {!r}".format(wrap, texan_greeting),
            )

        self.assertIsNone(cache.get(0), "cache should not have the result")

    def test_multiple_true(self):
        cache = ResponseCache(self.synapse_clock, "keeping_cache", timeout_ms=9001)

        texan_greeting = "howdy"

        def is_texan_greeting(greeting) -> bool:
            return greeting == texan_greeting

        positive_wraps = {
            cache.wrap_conditional(
                0, is_texan_greeting, self.delayed_return, texan_greeting
            )
            for _ in range(6)
        }

        self.reactor.pump((1,))

        for wrap in positive_wraps:
            self.assertEqual(
                texan_greeting,
                self.successResultOf(wrap),
                "wrap deferred {!r} should have {!r}".format(wrap, texan_greeting),
            )

        self.assertEqual(
            texan_greeting,
            self.successResultOf(cache.get(0)),
            "cache should have the result",
        )
