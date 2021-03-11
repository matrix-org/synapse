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
import logging
import random

import synapse.logging.context
from synapse.api.errors import CodeMessageException

logger = logging.getLogger(__name__)

# the initial backoff, after the first transaction fails
MIN_RETRY_INTERVAL = 10 * 60 * 1000

# how much we multiply the backoff by after each subsequent fail
RETRY_MULTIPLIER = 5

# a cap on the backoff. (Essentially none)
MAX_RETRY_INTERVAL = 2 ** 62


class NotRetryingDestination(Exception):
    def __init__(self, retry_last_ts, retry_interval, destination):
        """Raised by the limiter (and federation client) to indicate that we are
        are deliberately not attempting to contact a given server.

        Args:
            retry_last_ts (int): the unix ts in milliseconds of our last attempt
                to contact the server.  0 indicates that the last attempt was
                successful or that we've never actually attempted to connect.
            retry_interval (int): the time in milliseconds to wait until the next
                attempt.
            destination (str): the domain in question
        """

        msg = "Not retrying server %s." % (destination,)
        super().__init__(msg)

        self.retry_last_ts = retry_last_ts
        self.retry_interval = retry_interval
        self.destination = destination


async def get_retry_limiter(destination, clock, store, ignore_backoff=False, **kwargs):
    """For a given destination check if we have previously failed to
    send a request there and are waiting before retrying the destination.
    If we are not ready to retry the destination, this will raise a
    NotRetryingDestination exception. Otherwise, will return a Context Manager
    that will mark the destination as down if an exception is thrown (excluding
    CodeMessageException with code < 500)

    Args:
        destination (str): name of homeserver
        clock (synapse.util.clock): timing source
        store (synapse.storage.transactions.TransactionStore): datastore
        ignore_backoff (bool): true to ignore the historical backoff data and
            try the request anyway. We will still reset the retry_interval on success.

    Example usage:

        try:
            limiter = await get_retry_limiter(destination, clock, store)
            with limiter:
                response = await do_request()
        except NotRetryingDestination:
            # We aren't ready to retry that destination.
            raise
    """
    failure_ts = None
    retry_last_ts, retry_interval = (0, 0)

    retry_timings = await store.get_destination_retry_timings(destination)

    if retry_timings:
        failure_ts = retry_timings["failure_ts"]
        retry_last_ts, retry_interval = (
            retry_timings["retry_last_ts"],
            retry_timings["retry_interval"],
        )

        now = int(clock.time_msec())

        if not ignore_backoff and retry_last_ts + retry_interval > now:
            raise NotRetryingDestination(
                retry_last_ts=retry_last_ts,
                retry_interval=retry_interval,
                destination=destination,
            )

    # if we are ignoring the backoff data, we should also not increment the backoff
    # when we get another failure - otherwise a server can very quickly reach the
    # maximum backoff even though it might only have been down briefly
    backoff_on_failure = not ignore_backoff

    return RetryDestinationLimiter(
        destination,
        clock,
        store,
        failure_ts,
        retry_interval,
        backoff_on_failure=backoff_on_failure,
        **kwargs,
    )


class RetryDestinationLimiter:
    def __init__(
        self,
        destination,
        clock,
        store,
        failure_ts,
        retry_interval,
        backoff_on_404=False,
        backoff_on_failure=True,
    ):
        """Marks the destination as "down" if an exception is thrown in the
        context, except for CodeMessageException with code < 500.

        If no exception is raised, marks the destination as "up".

        Args:
            destination (str)
            clock (Clock)
            store (DataStore)
            failure_ts (int|None): when this destination started failing (in ms since
                the epoch), or zero if the last request was successful
            retry_interval (int): The next retry interval taken from the
                database in milliseconds, or zero if the last request was
                successful.
            backoff_on_404 (bool): Back off if we get a 404

            backoff_on_failure (bool): set to False if we should not increase the
                retry interval on a failure.
        """
        self.clock = clock
        self.store = store
        self.destination = destination

        self.failure_ts = failure_ts
        self.retry_interval = retry_interval
        self.backoff_on_404 = backoff_on_404
        self.backoff_on_failure = backoff_on_failure

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        valid_err_code = False
        if exc_type is None:
            valid_err_code = True
        elif not issubclass(exc_type, Exception):
            # avoid treating exceptions which don't derive from Exception as
            # failures; this is mostly so as not to catch defer._DefGen.
            valid_err_code = True
        elif issubclass(exc_type, CodeMessageException):
            # Some error codes are perfectly fine for some APIs, whereas other
            # APIs may expect to never received e.g. a 404. It's important to
            # handle 404 as some remote servers will return a 404 when the HS
            # has been decommissioned.
            # If we get a 401, then we should probably back off since they
            # won't accept our requests for at least a while.
            # 429 is us being aggressively rate limited, so lets rate limit
            # ourselves.
            if exc_val.code == 404 and self.backoff_on_404:
                valid_err_code = False
            elif exc_val.code in (401, 429):
                valid_err_code = False
            elif exc_val.code < 500:
                valid_err_code = True
            else:
                valid_err_code = False

        if valid_err_code:
            # We connected successfully.
            if not self.retry_interval:
                return

            logger.debug(
                "Connection to %s was successful; clearing backoff", self.destination
            )
            self.failure_ts = None
            retry_last_ts = 0
            self.retry_interval = 0
        elif not self.backoff_on_failure:
            return
        else:
            # We couldn't connect.
            if self.retry_interval:
                self.retry_interval = int(
                    self.retry_interval * RETRY_MULTIPLIER * random.uniform(0.8, 1.4)
                )

                if self.retry_interval >= MAX_RETRY_INTERVAL:
                    self.retry_interval = MAX_RETRY_INTERVAL
            else:
                self.retry_interval = MIN_RETRY_INTERVAL

            logger.info(
                "Connection to %s was unsuccessful (%s(%s)); backoff now %i",
                self.destination,
                exc_type,
                exc_val,
                self.retry_interval,
            )
            retry_last_ts = int(self.clock.time_msec())

            if self.failure_ts is None:
                self.failure_ts = retry_last_ts

        async def store_retry_timings():
            try:
                await self.store.set_destination_retry_timings(
                    self.destination,
                    self.failure_ts,
                    retry_last_ts,
                    self.retry_interval,
                )
            except Exception:
                logger.exception("Failed to store destination_retry_timings")

        # we deliberately do this in the background.
        synapse.logging.context.run_in_background(store_retry_timings)
