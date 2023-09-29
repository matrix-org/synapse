# Copyright 2016 OpenMarket Ltd
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
from functools import wraps
from types import TracebackType
from typing import Awaitable, Callable, Dict, Generator, Optional, Type, TypeVar

from prometheus_client import CollectorRegistry, Counter, Metric
from typing_extensions import Concatenate, ParamSpec, Protocol

from synapse.logging.context import (
    ContextResourceUsage,
    LoggingContext,
    current_context,
)
from synapse.metrics import InFlightGauge
from synapse.util import Clock

logger = logging.getLogger(__name__)

block_counter = Counter("synapse_util_metrics_block_count", "", ["block_name"])

block_timer = Counter("synapse_util_metrics_block_time_seconds", "", ["block_name"])

block_ru_utime = Counter(
    "synapse_util_metrics_block_ru_utime_seconds", "", ["block_name"]
)

block_ru_stime = Counter(
    "synapse_util_metrics_block_ru_stime_seconds", "", ["block_name"]
)

block_db_txn_count = Counter(
    "synapse_util_metrics_block_db_txn_count", "", ["block_name"]
)

# seconds spent waiting for db txns, excluding scheduling time, in this block
block_db_txn_duration = Counter(
    "synapse_util_metrics_block_db_txn_duration_seconds", "", ["block_name"]
)

# seconds spent waiting for a db connection, in this block
block_db_sched_duration = Counter(
    "synapse_util_metrics_block_db_sched_duration_seconds", "", ["block_name"]
)


# This is dynamically created in InFlightGauge.__init__.
class _InFlightMetric(Protocol):
    real_time_max: float
    real_time_sum: float


# Tracks the number of blocks currently active
in_flight: InFlightGauge[_InFlightMetric] = InFlightGauge(
    "synapse_util_metrics_block_in_flight",
    "",
    labels=["block_name"],
    sub_metrics=["real_time_max", "real_time_sum"],
)


P = ParamSpec("P")
R = TypeVar("R")


class HasClock(Protocol):
    clock: Clock


def measure_func(
    name: Optional[str] = None,
) -> Callable[[Callable[P, Awaitable[R]]], Callable[P, Awaitable[R]]]:
    """Decorate an async method with a `Measure` context manager.

    The Measure is created using `self.clock`; it should only be used to decorate
    methods in classes defining an instance-level `clock` attribute.

    Usage:

    @measure_func()
    async def foo(...):
        ...

    Which is analogous to:

    async def foo(...):
        with Measure(...):
            ...

    """

    def wrapper(
        func: Callable[Concatenate[HasClock, P], Awaitable[R]]
    ) -> Callable[P, Awaitable[R]]:
        block_name = func.__name__ if name is None else name

        @wraps(func)
        async def measured_func(self: HasClock, *args: P.args, **kwargs: P.kwargs) -> R:
            with Measure(self.clock, block_name):
                r = await func(self, *args, **kwargs)
            return r

        # There are some shenanigans here, because we're decorating a method but
        # explicitly making use of the `self` parameter. The key thing here is that the
        # return type within the return type for `measure_func` itself describes how the
        # decorated function will be called.
        return measured_func  # type: ignore[return-value]

    return wrapper  # type: ignore[return-value]


class Measure:
    __slots__ = [
        "clock",
        "name",
        "_logging_context",
        "start",
    ]

    def __init__(self, clock: Clock, name: str) -> None:
        """
        Args:
            clock: An object with a "time()" method, which returns the current
                time in seconds.
            name: The name of the metric to report.
        """
        self.clock = clock
        self.name = name
        curr_context = current_context()
        if not curr_context:
            logger.warning(
                "Starting metrics collection %r from sentinel context: metrics will be lost",
                name,
            )
            parent_context = None
        else:
            assert isinstance(curr_context, LoggingContext)
            parent_context = curr_context
        self._logging_context = LoggingContext(str(curr_context), parent_context)
        self.start: Optional[float] = None

    def __enter__(self) -> "Measure":
        if self.start is not None:
            raise RuntimeError("Measure() objects cannot be re-used")

        self.start = self.clock.time()
        self._logging_context.__enter__()
        in_flight.register((self.name,), self._update_in_flight)

        logger.debug("Entering block %s", self.name)

        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self.start is None:
            raise RuntimeError("Measure() block exited without being entered")

        logger.debug("Exiting block %s", self.name)

        duration = self.clock.time() - self.start
        usage = self.get_resource_usage()

        in_flight.unregister((self.name,), self._update_in_flight)
        self._logging_context.__exit__(exc_type, exc_val, exc_tb)

        try:
            block_counter.labels(self.name).inc()
            block_timer.labels(self.name).inc(duration)
            block_ru_utime.labels(self.name).inc(usage.ru_utime)
            block_ru_stime.labels(self.name).inc(usage.ru_stime)
            block_db_txn_count.labels(self.name).inc(usage.db_txn_count)
            block_db_txn_duration.labels(self.name).inc(usage.db_txn_duration_sec)
            block_db_sched_duration.labels(self.name).inc(usage.db_sched_duration_sec)
        except ValueError:
            logger.warning("Failed to save metrics! Usage: %s", usage)

    def get_resource_usage(self) -> ContextResourceUsage:
        """Get the resources used within this Measure block

        If the Measure block is still active, returns the resource usage so far.
        """
        return self._logging_context.get_resource_usage()

    def _update_in_flight(self, metrics: _InFlightMetric) -> None:
        """Gets called when processing in flight metrics"""
        assert self.start is not None
        duration = self.clock.time() - self.start

        metrics.real_time_max = max(metrics.real_time_max, duration)
        metrics.real_time_sum += duration

        # TODO: Add other in flight metrics.


class DynamicCollectorRegistry(CollectorRegistry):
    """
    Custom Prometheus Collector registry that calls a hook first, allowing you
    to update metrics on-demand.

    Don't forget to register this registry with the main registry!
    """

    def __init__(self) -> None:
        super().__init__()
        self._pre_update_hooks: Dict[str, Callable[[], None]] = {}

    def collect(self) -> Generator[Metric, None, None]:
        """
        Collects metrics, calling pre-update hooks first.
        """

        for pre_update_hook in self._pre_update_hooks.values():
            pre_update_hook()

        yield from super().collect()

    def register_hook(self, metric_name: str, hook: Callable[[], None]) -> None:
        """
        Registers a hook that is called before metric collection.
        """

        self._pre_update_hooks[metric_name] = hook
