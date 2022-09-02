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
import threading
import typing
from typing import (
    Any,
    Callable,
    DefaultDict,
    Dict,
    Iterator,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from prometheus_client.core import Counter
from typing_extensions import ContextManager

from twisted.internet import defer

from synapse.api.errors import LimitExceededError
from synapse.config.ratelimiting import FederationRatelimitSettings
from synapse.logging.context import (
    PreserveLoggingContext,
    make_deferred_yieldable,
    run_in_background,
)
from synapse.logging.opentracing import start_active_span
from synapse.metrics import Histogram, LaterGauge
from synapse.util import Clock

if typing.TYPE_CHECKING:
    from contextlib import _GeneratorContextManager

logger = logging.getLogger(__name__)


# Track how much the ratelimiter is affecting requests
rate_limit_sleep_counter = Counter(
    "synapse_rate_limit_sleep",
    "Number of requests slept by the rate limiter",
    ["rate_limiter_name"],
)
rate_limit_reject_counter = Counter(
    "synapse_rate_limit_reject",
    "Number of requests rejected by the rate limiter",
    ["rate_limiter_name"],
)
queue_wait_timer = Histogram(
    "synapse_rate_limit_queue_wait_time_seconds",
    "Amount of time spent waiting for the rate limiter to let our request through.",
    ["rate_limiter_name"],
    buckets=(
        0.005,
        0.01,
        0.025,
        0.05,
        0.1,
        0.25,
        0.5,
        0.75,
        1.0,
        2.5,
        5.0,
        10.0,
        20.0,
        "+Inf",
    ),
)


_rate_limiter_instances: Set["FederationRateLimiter"] = set()
# Protects the _rate_limiter_instances set from concurrent access
_rate_limiter_instances_lock = threading.Lock()


def _get_counts_from_rate_limiter_instance(
    count_func: Callable[["FederationRateLimiter"], int]
) -> Mapping[Tuple[str, ...], int]:
    """Returns a count of something (slept/rejected hosts) by (metrics_name)"""
    # Cast to a list to prevent it changing while the Prometheus
    # thread is collecting metrics
    with _rate_limiter_instances_lock:
        rate_limiter_instances = list(_rate_limiter_instances)

    # Map from (metrics_name,) -> int, the number of something like slept hosts
    # or rejected hosts. The key type is Tuple[str], but we leave the length
    # unspecified for compatability with LaterGauge's annotations.
    counts: Dict[Tuple[str, ...], int] = {}
    for rate_limiter_instance in rate_limiter_instances:
        # Only track metrics if they provided a `metrics_name` to
        # differentiate this instance of the rate limiter.
        if rate_limiter_instance.metrics_name:
            key = (rate_limiter_instance.metrics_name,)
            counts[key] = count_func(rate_limiter_instance)

    return counts


# We track the number of affected hosts per time-period so we can
# differentiate one really noisy homeserver from a general
# ratelimit tuning problem across the federation.
LaterGauge(
    "synapse_rate_limit_sleep_affected_hosts",
    "Number of hosts that had requests put to sleep",
    ["rate_limiter_name"],
    lambda: _get_counts_from_rate_limiter_instance(
        lambda rate_limiter_instance: sum(
            ratelimiter.should_sleep()
            for ratelimiter in rate_limiter_instance.ratelimiters.values()
        )
    ),
)
LaterGauge(
    "synapse_rate_limit_reject_affected_hosts",
    "Number of hosts that had requests rejected",
    ["rate_limiter_name"],
    lambda: _get_counts_from_rate_limiter_instance(
        lambda rate_limiter_instance: sum(
            ratelimiter.should_reject()
            for ratelimiter in rate_limiter_instance.ratelimiters.values()
        )
    ),
)


class FederationRateLimiter:
    """Used to rate limit request per-host."""

    def __init__(
        self,
        clock: Clock,
        config: FederationRatelimitSettings,
        metrics_name: Optional[str] = None,
    ):
        """
        Args:
            clock
            config
            metrics_name: The name of the rate limiter so we can differentiate it
                from the rest in the metrics. If `None`, we don't track metrics
                for this rate limiter.

        """
        self.metrics_name = metrics_name

        def new_limiter() -> "_PerHostRatelimiter":
            return _PerHostRatelimiter(
                clock=clock, config=config, metrics_name=metrics_name
            )

        self.ratelimiters: DefaultDict[
            str, "_PerHostRatelimiter"
        ] = collections.defaultdict(new_limiter)

        with _rate_limiter_instances_lock:
            _rate_limiter_instances.add(self)

    def ratelimit(self, host: str) -> "_GeneratorContextManager[defer.Deferred[None]]":
        """Used to ratelimit an incoming request from a given host

        Example usage:

            with rate_limiter.ratelimit(origin) as wait_deferred:
                yield wait_deferred
                # Handle request ...

        Args:
            host (str): Origin of incoming request.

        Returns:
            context manager which returns a deferred.
        """
        return self.ratelimiters[host].ratelimit(host)


class _PerHostRatelimiter:
    def __init__(
        self,
        clock: Clock,
        config: FederationRatelimitSettings,
        metrics_name: Optional[str] = None,
    ):
        """
        Args:
            clock
            config
            metrics_name: The name of the rate limiter so we can differentiate it
                from the rest in the metrics. If `None`, we don't track metrics
                for this rate limiter.
                from the rest in the metrics
        """
        self.clock = clock
        self.metrics_name = metrics_name

        self.window_size = config.window_size
        self.sleep_limit = config.sleep_limit
        self.sleep_sec = config.sleep_delay / 1000.0
        self.reject_limit = config.reject_limit
        self.concurrent_requests = config.concurrent

        # request_id objects for requests which have been slept
        self.sleeping_requests: Set[object] = set()

        # map from request_id object to Deferred for requests which are ready
        # for processing but have been queued
        self.ready_request_queue: collections.OrderedDict[
            object, defer.Deferred[None]
        ] = collections.OrderedDict()

        # request id objects for requests which are in progress
        self.current_processing: Set[object] = set()

        # times at which we have recently (within the last window_size ms)
        # received requests.
        self.request_times: List[int] = []

    @contextlib.contextmanager
    def ratelimit(self, host: str) -> "Iterator[defer.Deferred[None]]":
        # `contextlib.contextmanager` takes a generator and turns it into a
        # context manager. The generator should only yield once with a value
        # to be returned by manager.
        # Exceptions will be reraised at the yield.

        self.host = host

        request_id = object()
        # Ideally we'd use `Deferred.fromCoroutine()` here, to save on redundant
        # type-checking, but we'd need Twisted >= 21.2.
        ret = defer.ensureDeferred(self._on_enter_with_tracing(request_id))
        try:
            yield ret
        finally:
            self._on_exit(request_id)

    def should_reject(self) -> bool:
        """
        Whether to reject the request if we already have too many queued up
        (either sleeping or in the ready queue).
        """
        queue_size = len(self.ready_request_queue) + len(self.sleeping_requests)
        return queue_size > self.reject_limit

    def should_sleep(self) -> bool:
        """
        Whether to sleep the request if we already have too many requests coming
        through within the window.
        """
        return len(self.request_times) > self.sleep_limit

    async def _on_enter_with_tracing(self, request_id: object) -> None:
        maybe_metrics_cm: ContextManager = contextlib.nullcontext()
        if self.metrics_name:
            maybe_metrics_cm = queue_wait_timer.labels(self.metrics_name).time()
        with start_active_span("ratelimit wait"), maybe_metrics_cm:
            await self._on_enter(request_id)

    def _on_enter(self, request_id: object) -> "defer.Deferred[None]":
        time_now = self.clock.time_msec()

        # remove any entries from request_times which aren't within the window
        self.request_times[:] = [
            r for r in self.request_times if time_now - r < self.window_size
        ]

        # reject the request if we already have too many queued up (either
        # sleeping or in the ready queue).
        if self.should_reject():
            logger.debug("Ratelimiter(%s): rejecting request", self.host)
            if self.metrics_name:
                rate_limit_reject_counter.labels(self.metrics_name).inc()
            raise LimitExceededError(
                retry_after_ms=int(self.window_size / self.sleep_limit)
            )

        self.request_times.append(time_now)

        def queue_request() -> "defer.Deferred[None]":
            if len(self.current_processing) >= self.concurrent_requests:
                queue_defer: defer.Deferred[None] = defer.Deferred()
                self.ready_request_queue[request_id] = queue_defer
                logger.info(
                    "Ratelimiter(%s): queueing request (queue now %i items)",
                    self.host,
                    len(self.ready_request_queue),
                )

                return queue_defer
            else:
                return defer.succeed(None)

        logger.debug(
            "Ratelimit(%s) [%s]: len(self.request_times)=%d",
            self.host,
            id(request_id),
            len(self.request_times),
        )

        if self.should_sleep():
            logger.debug(
                "Ratelimiter(%s) [%s]: sleeping request for %f sec",
                self.host,
                id(request_id),
                self.sleep_sec,
            )
            if self.metrics_name:
                rate_limit_sleep_counter.labels(self.metrics_name).inc()
            ret_defer = run_in_background(self.clock.sleep, self.sleep_sec)

            self.sleeping_requests.add(request_id)

            def on_wait_finished(_: Any) -> "defer.Deferred[None]":
                logger.debug(
                    "Ratelimit(%s) [%s]: Finished sleeping", self.host, id(request_id)
                )
                self.sleeping_requests.discard(request_id)
                queue_defer = queue_request()
                return queue_defer

            ret_defer.addBoth(on_wait_finished)
        else:
            ret_defer = queue_request()

        def on_start(r: object) -> object:
            logger.debug(
                "Ratelimit(%s) [%s]: Processing req", self.host, id(request_id)
            )
            self.current_processing.add(request_id)
            return r

        def on_err(r: object) -> object:
            # XXX: why is this necessary? this is called before we start
            # processing the request so why would the request be in
            # current_processing?
            self.current_processing.discard(request_id)
            return r

        def on_both(r: object) -> object:
            # Ensure that we've properly cleaned up.
            self.sleeping_requests.discard(request_id)
            self.ready_request_queue.pop(request_id, None)
            return r

        ret_defer.addCallbacks(on_start, on_err)
        ret_defer.addBoth(on_both)
        return make_deferred_yieldable(ret_defer)

    def _on_exit(self, request_id: object) -> None:
        logger.debug("Ratelimit(%s) [%s]: Processed req", self.host, id(request_id))
        self.current_processing.discard(request_id)
        try:
            # start processing the next item on the queue.
            _, deferred = self.ready_request_queue.popitem(last=False)

            with PreserveLoggingContext():
                deferred.callback(None)
        except KeyError:
            pass
