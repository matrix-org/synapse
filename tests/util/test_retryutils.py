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
from synapse.util.retryutils import NotRetryingDestination, get_retry_limiter

from tests.unittest import HomeserverTestCase


class RetryLimiterTestCase(HomeserverTestCase):
    def test_new_destination(self) -> None:
        """A happy-path case with a new destination and a successful operation"""
        store = self.hs.get_datastores().main
        limiter = self.get_success(get_retry_limiter("test_dest", self.clock, store))

        # advance the clock a bit before making the request
        self.pump(1)

        with limiter:
            pass

        new_timings = self.get_success(store.get_destination_retry_timings("test_dest"))
        self.assertIsNone(new_timings)

    def test_limiter(self) -> None:
        """General test case which walks through the process of a failing request"""
        store = self.hs.get_datastores().main

        limiter = self.get_success(get_retry_limiter("test_dest", self.clock, store))

        min_retry_interval_ms = (
            self.hs.config.federation.destination_min_retry_interval_ms
        )
        retry_multiplier = self.hs.config.federation.destination_retry_multiplier

        self.pump(1)
        try:
            with limiter:
                self.pump(1)
                failure_ts = self.clock.time_msec()
                raise AssertionError("argh")
        except AssertionError:
            pass

        self.pump()

        new_timings = self.get_success(store.get_destination_retry_timings("test_dest"))
        assert new_timings is not None
        self.assertEqual(new_timings.failure_ts, failure_ts)
        self.assertEqual(new_timings.retry_last_ts, failure_ts)
        self.assertEqual(new_timings.retry_interval, min_retry_interval_ms)

        # now if we try again we should get a failure
        self.get_failure(
            get_retry_limiter("test_dest", self.clock, store), NotRetryingDestination
        )

        #
        # advance the clock and try again
        #

        self.pump(min_retry_interval_ms)
        limiter = self.get_success(get_retry_limiter("test_dest", self.clock, store))

        self.pump(1)
        try:
            with limiter:
                self.pump(1)
                retry_ts = self.clock.time_msec()
                raise AssertionError("argh")
        except AssertionError:
            pass

        self.pump()

        new_timings = self.get_success(store.get_destination_retry_timings("test_dest"))
        assert new_timings is not None
        self.assertEqual(new_timings.failure_ts, failure_ts)
        self.assertEqual(new_timings.retry_last_ts, retry_ts)
        self.assertGreaterEqual(
            new_timings.retry_interval, min_retry_interval_ms * retry_multiplier * 0.5
        )
        self.assertLessEqual(
            new_timings.retry_interval, min_retry_interval_ms * retry_multiplier * 2.0
        )

        #
        # one more go, with success
        #
        self.reactor.advance(min_retry_interval_ms * retry_multiplier * 2.0)
        limiter = self.get_success(get_retry_limiter("test_dest", self.clock, store))

        self.pump(1)
        with limiter:
            self.pump(1)

        # wait for the update to land
        self.pump()

        new_timings = self.get_success(store.get_destination_retry_timings("test_dest"))
        self.assertIsNone(new_timings)
