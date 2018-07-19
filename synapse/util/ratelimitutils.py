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

import collections
import contextlib
import logging

from twisted.internet import defer

from synapse.api.errors import LimitExceededError
from synapse.util.logcontext import (
    PreserveLoggingContext,
    make_deferred_yieldable,
    run_in_background,
)

logger = logging.getLogger(__name__)


class FederationRateLimiter(object):
    def __init__(self, clock, window_size, sleep_limit, sleep_msec,
                 reject_limit, concurrent_requests):
        """
        Args:
            clock (Clock)
            window_size (int): The window size in milliseconds.
            sleep_limit (int): The number of requests received in the last
                `window_size` milliseconds before we artificially start
                delaying processing of requests.
            sleep_msec (int): The number of milliseconds to delay processing
                of incoming requests by.
            reject_limit (int): The maximum number of requests that are can be
                queued for processing before we start rejecting requests with
                a 429 Too Many Requests response.
            concurrent_requests (int): The number of concurrent requests to
                process.
        """
        self.clock = clock

        self.window_size = window_size
        self.sleep_limit = sleep_limit
        self.sleep_msec = sleep_msec
        self.reject_limit = reject_limit
        self.concurrent_requests = concurrent_requests

        self.ratelimiters = {}

    def ratelimit(self, host):
        """Used to ratelimit an incoming request from given host

        Example usage:

            with rate_limiter.ratelimit(origin) as wait_deferred:
                yield wait_deferred
                # Handle request ...

        Args:
            host (str): Origin of incoming request.

        Returns:
            _PerHostRatelimiter
        """
        return self.ratelimiters.setdefault(
            host,
            _PerHostRatelimiter(
                clock=self.clock,
                window_size=self.window_size,
                sleep_limit=self.sleep_limit,
                sleep_msec=self.sleep_msec,
                reject_limit=self.reject_limit,
                concurrent_requests=self.concurrent_requests,
            )
        ).ratelimit()


class _PerHostRatelimiter(object):
    def __init__(self, clock, window_size, sleep_limit, sleep_msec,
                 reject_limit, concurrent_requests):
        self.clock = clock

        self.window_size = window_size
        self.sleep_limit = sleep_limit
        self.sleep_sec = sleep_msec / 1000.0
        self.reject_limit = reject_limit
        self.concurrent_requests = concurrent_requests

        # request_id objects for requests which have been slept
        self.sleeping_requests = set()

        # map from request_id object to Deferred for requests which are ready
        # for processing but have been queued
        self.ready_request_queue = collections.OrderedDict()

        # request id objects for requests which are in progress
        self.current_processing = set()

        # times at which we have recently (within the last window_size ms)
        # received requests.
        self.request_times = []

    @contextlib.contextmanager
    def ratelimit(self):
        # `contextlib.contextmanager` takes a generator and turns it into a
        # context manager. The generator should only yield once with a value
        # to be returned by manager.
        # Exceptions will be reraised at the yield.

        request_id = object()
        ret = self._on_enter(request_id)
        try:
            yield ret
        finally:
            self._on_exit(request_id)

    def _on_enter(self, request_id):
        time_now = self.clock.time_msec()

        # remove any entries from request_times which aren't within the window
        self.request_times[:] = [
            r for r in self.request_times
            if time_now - r < self.window_size
        ]

        # reject the request if we already have too many queued up (either
        # sleeping or in the ready queue).
        queue_size = len(self.ready_request_queue) + len(self.sleeping_requests)
        if queue_size > self.reject_limit:
            raise LimitExceededError(
                retry_after_ms=int(
                    self.window_size / self.sleep_limit
                ),
            )

        self.request_times.append(time_now)

        def queue_request():
            if len(self.current_processing) > self.concurrent_requests:
                queue_defer = defer.Deferred()
                self.ready_request_queue[request_id] = queue_defer
                logger.info(
                    "Ratelimiter: queueing request (queue now %i items)",
                    len(self.ready_request_queue),
                )

                return queue_defer
            else:
                return defer.succeed(None)

        logger.debug(
            "Ratelimit [%s]: len(self.request_times)=%d",
            id(request_id), len(self.request_times),
        )

        if len(self.request_times) > self.sleep_limit:
            logger.debug(
                "Ratelimiter: sleeping request for %f sec", self.sleep_sec,
            )
            ret_defer = run_in_background(self.clock.sleep, self.sleep_sec)

            self.sleeping_requests.add(request_id)

            def on_wait_finished(_):
                logger.debug(
                    "Ratelimit [%s]: Finished sleeping",
                    id(request_id),
                )
                self.sleeping_requests.discard(request_id)
                queue_defer = queue_request()
                return queue_defer

            ret_defer.addBoth(on_wait_finished)
        else:
            ret_defer = queue_request()

        def on_start(r):
            logger.debug(
                "Ratelimit [%s]: Processing req",
                id(request_id),
            )
            self.current_processing.add(request_id)
            return r

        def on_err(r):
            # XXX: why is this necessary? this is called before we start
            # processing the request so why would the request be in
            # current_processing?
            self.current_processing.discard(request_id)
            return r

        def on_both(r):
            # Ensure that we've properly cleaned up.
            self.sleeping_requests.discard(request_id)
            self.ready_request_queue.pop(request_id, None)
            return r

        ret_defer.addCallbacks(on_start, on_err)
        ret_defer.addBoth(on_both)
        return make_deferred_yieldable(ret_defer)

    def _on_exit(self, request_id):
        logger.debug(
            "Ratelimit [%s]: Processed req",
            id(request_id),
        )
        self.current_processing.discard(request_id)
        try:
            # start processing the next item on the queue.
            _, deferred = self.ready_request_queue.popitem(last=False)

            with PreserveLoggingContext():
                deferred.callback(None)
        except KeyError:
            pass
