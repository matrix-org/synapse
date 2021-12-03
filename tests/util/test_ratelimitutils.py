# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import Optional

from synapse.config.homeserver import HomeServerConfig
from synapse.util.ratelimitutils import FederationRateLimiter

from tests.server import get_clock
from tests.unittest import TestCase
from tests.utils import default_config


class FederationRateLimiterTestCase(TestCase):
    def test_ratelimit(self):
        """A simple test with the default values"""
        reactor, clock = get_clock()
        rc_config = build_rc_config()
        ratelimiter = FederationRateLimiter(clock, rc_config)

        with ratelimiter.ratelimit("testhost") as d1:
            # shouldn't block
            self.successResultOf(d1)

    def test_concurrent_limit(self):
        """Test what happens when we hit the concurrent limit"""
        reactor, clock = get_clock()
        rc_config = build_rc_config({"rc_federation": {"concurrent": 2}})
        ratelimiter = FederationRateLimiter(clock, rc_config)

        with ratelimiter.ratelimit("testhost") as d1:
            # shouldn't block
            self.successResultOf(d1)

            cm2 = ratelimiter.ratelimit("testhost")
            d2 = cm2.__enter__()
            # also shouldn't block
            self.successResultOf(d2)

            cm3 = ratelimiter.ratelimit("testhost")
            d3 = cm3.__enter__()
            # this one should block, though ...
            self.assertNoResult(d3)

            # ... until we complete an earlier request
            cm2.__exit__(None, None, None)
            self.successResultOf(d3)

    def test_sleep_limit(self):
        """Test what happens when we hit the sleep limit"""
        reactor, clock = get_clock()
        rc_config = build_rc_config(
            {"rc_federation": {"sleep_limit": 2, "sleep_delay": 500}}
        )
        ratelimiter = FederationRateLimiter(clock, rc_config)

        with ratelimiter.ratelimit("testhost") as d1:
            # shouldn't block
            self.successResultOf(d1)

        with ratelimiter.ratelimit("testhost") as d2:
            # nor this
            self.successResultOf(d2)

        with ratelimiter.ratelimit("testhost") as d3:
            # this one should block, though ...
            self.assertNoResult(d3)
            sleep_time = _await_resolution(reactor, d3)
            self.assertAlmostEqual(sleep_time, 500, places=3)


def _await_resolution(reactor, d):
    """advance the clock until the deferred completes.

    Returns the number of milliseconds it took to complete.
    """
    start_time = reactor.seconds()
    while not d.called:
        reactor.advance(0.01)
    return (reactor.seconds() - start_time) * 1000


def build_rc_config(settings: Optional[dict] = None):
    config_dict = default_config("test")
    config_dict.update(settings or {})
    config = HomeServerConfig()
    config.parse_config_dict(config_dict, "", "")
    return config.ratelimiting.rc_federation
