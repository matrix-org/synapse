# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.errors import CodeMessageException

import logging
import random


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
    """For a given destination check if we have previously failed to
    send a request there and are waiting before retrying the destination.
    If we are not ready to retry the destination, this will raise a
    NotRetryingDestination exception. Otherwise, will return a Context Manager
    that will mark the destination as down if an exception is thrown (excluding
    CodeMessageException with code < 500)

    Example usage:

        try:
            limiter = yield get_retry_limiter(destination, clock, store)
            with limiter:
                response = yield do_request()
        except NotRetryingDestination:
            # We aren't ready to retry that destination.
            raise
    """
    retry_last_ts, retry_interval = (0, 0)

    retry_timings = yield store.get_destination_retry_timings(
        destination
    )

    if retry_timings:
        retry_last_ts, retry_interval = (
            retry_timings["retry_last_ts"], retry_timings["retry_interval"]
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
                 min_retry_interval=10 * 60 * 1000,
                 max_retry_interval=24 * 60 * 60 * 1000,
                 multiplier_retry_interval=5, backoff_on_404=False):
        """Marks the destination as "down" if an exception is thrown in the
        context, except for CodeMessageException with code < 500.

        If no exception is raised, marks the destination as "up".

        Args:
            destination (str)
            clock (Clock)
            store (DataStore)
            retry_interval (int): The next retry interval taken from the
                database in milliseconds, or zero if the last request was
                successful.
            min_retry_interval (int): The minimum retry interval to use after
                a failed request, in milliseconds.
            max_retry_interval (int): The maximum retry interval to use after
                a failed request, in milliseconds.
            multiplier_retry_interval (int): The multiplier to use to increase
                the retry interval after a failed request.
            backoff_on_404 (bool): Back off if we get a 404
        """
        self.clock = clock
        self.store = store
        self.destination = destination

        self.retry_interval = retry_interval
        self.min_retry_interval = min_retry_interval
        self.max_retry_interval = max_retry_interval
        self.multiplier_retry_interval = multiplier_retry_interval
        self.backoff_on_404 = backoff_on_404

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        valid_err_code = False
        if exc_type is not None and issubclass(exc_type, CodeMessageException):
            # Some error codes are perfectly fine for some APIs, whereas other
            # APIs may expect to never received e.g. a 404. It's important to
            # handle 404 as some remote servers will return a 404 when the HS
            # has been decommissioned.
            # If we get a 401, then we should probably back off since they
            # won't accept our requests for at least a while.
            # 429 is us being aggresively rate limited, so lets rate limit
            # ourselves.
            if exc_val.code == 404 and self.backoff_on_404:
                valid_err_code = False
            elif exc_val.code in (401, 429):
                valid_err_code = False
            elif exc_val.code < 500:
                valid_err_code = True
            else:
                valid_err_code = False

        if exc_type is None or valid_err_code:
            # We connected successfully.
            if not self.retry_interval:
                return

            retry_last_ts = 0
            self.retry_interval = 0
        else:
            # We couldn't connect.
            if self.retry_interval:
                self.retry_interval *= self.multiplier_retry_interval
                self.retry_interval *= int(random.uniform(0.8, 1.4))

                if self.retry_interval >= self.max_retry_interval:
                    self.retry_interval = self.max_retry_interval
            else:
                self.retry_interval = self.min_retry_interval

            retry_last_ts = int(self.clock.time_msec())

        @defer.inlineCallbacks
        def store_retry_timings():
            try:
                yield self.store.set_destination_retry_timings(
                    self.destination, retry_last_ts, self.retry_interval
                )
            except:
                logger.exception(
                    "Failed to store set_destination_retry_timings",
                )

        store_retry_timings()
