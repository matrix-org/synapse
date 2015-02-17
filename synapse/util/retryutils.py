# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from twisted.internet import defer

import logging


logger = logging.getLogger(__name__)


class NotRetryingDestination(Exception):
    def __init__(self, retry_last_ts, retry_interval, destination):
        msg = "Not retrying server %s." % (destination,)
        super(NotRetryingDestination, self).__init__(msg)

        self.retry_last_ts = retry_last_ts
        self.retry_interval = retry_interval
        self.destination = destination


@defer.inlineCallbacks
def get_retry_limiter(destination, clock, store, **kwargs):
    retry_last_ts, retry_interval = (0, 0)

    retry_timings = yield store.get_destination_retry_timings(
        destination
    )

    if retry_timings:
        retry_last_ts, retry_interval = (
            retry_timings.retry_last_ts, retry_timings.retry_interval
        )

        now = int(clock.time_msec())

        if retry_last_ts + retry_interval > now:
            raise NotRetryingDestination(
                retry_last_ts=retry_last_ts,
                retry_interval=retry_interval,
                destination=destination,
            )

    defer.returnValue(
        RetryDestinationLimiter(
            destination,
            clock,
            store,
            retry_interval,
            **kwargs
        )
    )


class RetryDestinationLimiter(object):
    def __init__(self, destination, clock, store, retry_interval,
                 min_retry_interval=20000, max_retry_interval=60 * 60 * 1000,
                 multiplier_retry_interval=2):
        self.clock = clock
        self.store = store
        self.destination = destination

        self.retry_interval = retry_interval
        self.min_retry_interval = min_retry_interval
        self.max_retry_interval = max_retry_interval
        self.multiplier_retry_interval = multiplier_retry_interval

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        def err(failure):
            logger.exception(
                "Failed to store set_destination_retry_timings",
                failure.value
            )

        if exc_type is None and exc_val is None and exc_tb is None:
            # We connected successfully.
            retry_last_ts = 0
            self.retry_interval = 0
        else:
            # We couldn't connect.
            if self.retry_interval:
                self.retry_interval *= self.multiplier_retry_interval

                if self.retry_interval >= self.max_retry_interval:
                    self.retry_interval = self.max_retry_interval
            else:
                self.retry_interval = self.min_retry_interval

            retry_last_ts = int(self._clock.time_msec()),

        self.store.set_destination_retry_timings(
            self.destination, retry_last_ts, self.retry_interval
        ).addErrback(err)
