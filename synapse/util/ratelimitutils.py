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

from synapse.api.errors import LimitExceededError

from synapse.util.async import sleep
from synapse.util.logcontext import preserve_fn

import collections
import contextlib
import logging


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
        self.sleep_msec = sleep_msec
        self.reject_limit = reject_limit
        self.concurrent_requests = concurrent_requests

        self.sleeping_requests = set()
        self.ready_request_queue = collections.OrderedDict()
        self.current_processing = set()
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
        self.request_times[:] = [
            r for r in self.request_times
            if time_now - r < self.window_size
        ]

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
                logger.debug("Ratelimit [%s]: Queue req", id(request_id))
                queue_defer = defer.Deferred()
                self.ready_request_queue[request_id] = queue_defer
                return queue_defer
            else:
                return defer.succeed(None)

        logger.debug(
            "Ratelimit [%s]: len(self.request_times)=%d",
            id(request_id), len(self.request_times),
        )

        if len(self.request_times) > self.sleep_limit:
            logger.debug(
                "Ratelimit [%s]: sleeping req",
                id(request_id),
            )
            ret_defer = preserve_fn(sleep)(self.sleep_msec / 1000.0)

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
            self.current_processing.discard(request_id)
            return r

        def on_both(r):
            # Ensure that we've properly cleaned up.
            self.sleeping_requests.discard(request_id)
            self.ready_request_queue.pop(request_id, None)
            return r

        ret_defer.addCallbacks(on_start, on_err)
        ret_defer.addBoth(on_both)
        return ret_defer

    def _on_exit(self, request_id):
        logger.debug(
            "Ratelimit [%s]: Processed req",
            id(request_id),
        )
        self.current_processing.discard(request_id)
        try:
            request_id, deferred = self.ready_request_queue.popitem()
            self.current_processing.add(request_id)
            deferred.callback(None)
        except KeyError:
            pass
