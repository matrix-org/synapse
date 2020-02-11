# -*- coding: utf-8 -*-
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

from prometheus_client import Counter

from twisted.internet import defer

from synapse.metrics import InFlightGauge
from synapse.util.logcontext import LoggingContext

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

# Tracks the number of blocks currently active
in_flight = InFlightGauge(
    "synapse_util_metrics_block_in_flight",
    "",
    labels=["block_name"],
    sub_metrics=["real_time_max", "real_time_sum"],
)


def measure_func(name):
    def wrapper(func):
        @wraps(func)
        @defer.inlineCallbacks
        def measured_func(self, *args, **kwargs):
            with Measure(self.clock, name):
                r = yield func(self, *args, **kwargs)
            defer.returnValue(r)

        return measured_func

    return wrapper


class Measure(object):
    __slots__ = [
        "clock",
        "name",
        "start_context",
        "start",
        "created_context",
        "start_usage",
    ]

    def __init__(self, clock, name):
        self.clock = clock
        self.name = name
        self.start_context = None
        self.start = None
        self.created_context = False

    def __enter__(self):
        self.start = self.clock.time()
        self.start_context = LoggingContext.current_context()
        if not self.start_context:
            self.start_context = LoggingContext("Measure")
            self.start_context.__enter__()
            self.created_context = True

        self.start_usage = self.start_context.get_resource_usage()

        in_flight.register((self.name,), self._update_in_flight)

    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_type, Exception) or not self.start_context:
            return

        in_flight.unregister((self.name,), self._update_in_flight)

        duration = self.clock.time() - self.start

        block_counter.labels(self.name).inc()
        block_timer.labels(self.name).inc(duration)

        context = LoggingContext.current_context()

        if context != self.start_context:
            logger.warn(
                "Context has unexpectedly changed from '%s' to '%s'. (%r)",
                self.start_context,
                context,
                self.name,
            )
            return

        if not context:
            logger.warn("Expected context. (%r)", self.name)
            return

        current = context.get_resource_usage()
        usage = current - self.start_usage
        try:
            block_ru_utime.labels(self.name).inc(usage.ru_utime)
            block_ru_stime.labels(self.name).inc(usage.ru_stime)
            block_db_txn_count.labels(self.name).inc(usage.db_txn_count)
            block_db_txn_duration.labels(self.name).inc(usage.db_txn_duration_sec)
            block_db_sched_duration.labels(self.name).inc(usage.db_sched_duration_sec)
        except ValueError:
            logger.warn(
                "Failed to save metrics! OLD: %r, NEW: %r", self.start_usage, current
            )

        if self.created_context:
            self.start_context.__exit__(exc_type, exc_val, exc_tb)

    def _update_in_flight(self, metrics):
        """Gets called when processing in flight metrics
        """
        duration = self.clock.time() - self.start

        metrics.real_time_max = max(metrics.real_time_max, duration)
        metrics.real_time_sum += duration

        # TODO: Add other in flight metrics.
