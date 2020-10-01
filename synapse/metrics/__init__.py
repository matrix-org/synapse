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

import functools
import gc
import itertools
import logging
import os
import platform
import threading
import time
from typing import Callable, Dict, Iterable, Optional, Tuple, Union

import attr
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.core import (
    REGISTRY,
    CounterMetricFamily,
    GaugeHistogramMetricFamily,
    GaugeMetricFamily,
)

from twisted.internet import reactor

import synapse
from synapse.metrics._exposition import (
    MetricsResource,
    generate_latest,
    start_http_server,
)
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)

METRICS_PREFIX = "/_synapse/metrics"

running_on_pypy = platform.python_implementation() == "PyPy"
all_gauges = {}  # type: Dict[str, Union[LaterGauge, InFlightGauge]]

HAVE_PROC_SELF_STAT = os.path.exists("/proc/self/stat")


class RegistryProxy:
    @staticmethod
    def collect():
        for metric in REGISTRY.collect():
            if not metric.name.startswith("__"):
                yield metric


@attr.s(slots=True, hash=True)
class LaterGauge:

    name = attr.ib(type=str)
    desc = attr.ib(type=str)
    labels = attr.ib(hash=False, type=Optional[Iterable[str]])
    # callback: should either return a value (if there are no labels for this metric),
    # or dict mapping from a label tuple to a value
    caller = attr.ib(type=Callable[[], Union[Dict[Tuple[str, ...], float], float]])

    def collect(self):

        g = GaugeMetricFamily(self.name, self.desc, labels=self.labels)

        try:
            calls = self.caller()
        except Exception:
            logger.exception("Exception running callback for LaterGauge(%s)", self.name)
            yield g
            return

        if isinstance(calls, dict):
            for k, v in calls.items():
                g.add_metric(k, v)
        else:
            g.add_metric([], calls)

        yield g

    def __attrs_post_init__(self):
        self._register()

    def _register(self):
        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


class InFlightGauge:
    """Tracks number of things (e.g. requests, Measure blocks, etc) in flight
    at any given time.

    Each InFlightGauge will create a metric called `<name>_total` that counts
    the number of in flight blocks, as well as a metrics for each item in the
    given `sub_metrics` as `<name>_<sub_metric>` which will get updated by the
    callbacks.

    Args:
        name (str)
        desc (str)
        labels (list[str])
        sub_metrics (list[str]): A list of sub metrics that the callbacks
            will update.
    """

    def __init__(self, name, desc, labels, sub_metrics):
        self.name = name
        self.desc = desc
        self.labels = labels
        self.sub_metrics = sub_metrics

        # Create a class which have the sub_metrics values as attributes, which
        # default to 0 on initialization. Used to pass to registered callbacks.
        self._metrics_class = attr.make_class(
            "_MetricsEntry", attrs={x: attr.ib(0) for x in sub_metrics}, slots=True
        )

        # Counts number of in flight blocks for a given set of label values
        self._registrations = {}  # type: Dict

        # Protects access to _registrations
        self._lock = threading.Lock()

        self._register_with_collector()

    def register(self, key, callback):
        """Registers that we've entered a new block with labels `key`.

        `callback` gets called each time the metrics are collected. The same
        value must also be given to `unregister`.

        `callback` gets called with an object that has an attribute per
        sub_metric, which should be updated with the necessary values. Note that
        the metrics object is shared between all callbacks registered with the
        same key.

        Note that `callback` may be called on a separate thread.
        """
        with self._lock:
            self._registrations.setdefault(key, set()).add(callback)

    def unregister(self, key, callback):
        """Registers that we've exited a block with labels `key`.
        """

        with self._lock:
            self._registrations.setdefault(key, set()).discard(callback)

    def collect(self):
        """Called by prometheus client when it reads metrics.

        Note: may be called by a separate thread.
        """
        in_flight = GaugeMetricFamily(
            self.name + "_total", self.desc, labels=self.labels
        )

        metrics_by_key = {}

        # We copy so that we don't mutate the list while iterating
        with self._lock:
            keys = list(self._registrations)

        for key in keys:
            with self._lock:
                callbacks = set(self._registrations[key])

            in_flight.add_metric(key, len(callbacks))

            metrics = self._metrics_class()
            metrics_by_key[key] = metrics
            for callback in callbacks:
                callback(metrics)

        yield in_flight

        for name in self.sub_metrics:
            gauge = GaugeMetricFamily(
                "_".join([self.name, name]), "", labels=self.labels
            )
            for key, metrics in metrics_by_key.items():
                gauge.add_metric(key, getattr(metrics, name))
            yield gauge

    def _register_with_collector(self):
        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


class GaugeBucketCollector:
    """Like a Histogram, but the buckets are Gauges which are updated atomically.

    The data is updated by calling `update_data` with an iterable of measurements.

    We assume that the data is updated less frequently than it is reported to
    Prometheus, and optimise for that case.
    """

    __slots__ = ("_name", "_documentation", "_bucket_bounds", "_metric")

    def __init__(
        self,
        name: str,
        documentation: str,
        buckets: Iterable[float],
        registry=REGISTRY,
    ):
        """
        Args:
            name: base name of metric to be exported to Prometheus. (a _bucket suffix
               will be added.)
            documentation: help text for the metric
            buckets: The top bounds of the buckets to report
            registry: metric registry to register with
        """
        self._name = name
        self._documentation = documentation

        # the tops of the buckets
        self._bucket_bounds = [float(b) for b in buckets]
        if self._bucket_bounds != sorted(self._bucket_bounds):
            raise ValueError("Buckets not in sorted order")

        if self._bucket_bounds[-1] != float("inf"):
            self._bucket_bounds.append(float("inf"))

        self._metric = self._values_to_metric([])
        registry.register(self)

    def collect(self):
        yield self._metric

    def update_data(self, values: Iterable[float]):
        """Update the data to be reported by the metric

        The existing data is cleared, and each measurement in the input is assigned
        to the relevant bucket.
        """
        self._metric = self._values_to_metric(values)

    def _values_to_metric(self, values: Iterable[float]) -> GaugeHistogramMetricFamily:
        total = 0.0
        bucket_values = [0 for _ in self._bucket_bounds]

        for v in values:
            # assign each value to a bucket
            for i, bound in enumerate(self._bucket_bounds):
                if v <= bound:
                    bucket_values[i] += 1
                    break

            # ... and increment the sum
            total += v

        # now, aggregate the bucket values so that they count the number of entries in
        # that bucket or below.
        accumulated_values = itertools.accumulate(bucket_values)

        return GaugeHistogramMetricFamily(
            self._name,
            self._documentation,
            buckets=list(
                zip((str(b) for b in self._bucket_bounds), accumulated_values)
            ),
            gsum_value=total,
        )


#
# Detailed CPU metrics
#


class CPUMetrics:
    def __init__(self):
        ticks_per_sec = 100
        try:
            # Try and get the system config
            ticks_per_sec = os.sysconf("SC_CLK_TCK")
        except (ValueError, TypeError, AttributeError):
            pass

        self.ticks_per_sec = ticks_per_sec

    def collect(self):
        if not HAVE_PROC_SELF_STAT:
            return

        with open("/proc/self/stat") as s:
            line = s.read()
            raw_stats = line.split(") ", 1)[1].split(" ")

            user = GaugeMetricFamily("process_cpu_user_seconds_total", "")
            user.add_metric([], float(raw_stats[11]) / self.ticks_per_sec)
            yield user

            sys = GaugeMetricFamily("process_cpu_system_seconds_total", "")
            sys.add_metric([], float(raw_stats[12]) / self.ticks_per_sec)
            yield sys


REGISTRY.register(CPUMetrics())

#
# Python GC metrics
#

gc_unreachable = Gauge("python_gc_unreachable_total", "Unreachable GC objects", ["gen"])
gc_time = Histogram(
    "python_gc_time",
    "Time taken to GC (sec)",
    ["gen"],
    buckets=[
        0.0025,
        0.005,
        0.01,
        0.025,
        0.05,
        0.10,
        0.25,
        0.50,
        1.00,
        2.50,
        5.00,
        7.50,
        15.00,
        30.00,
        45.00,
        60.00,
    ],
)


class GCCounts:
    def collect(self):
        cm = GaugeMetricFamily("python_gc_counts", "GC object counts", labels=["gen"])
        for n, m in enumerate(gc.get_count()):
            cm.add_metric([str(n)], m)

        yield cm


if not running_on_pypy:
    REGISTRY.register(GCCounts())


#
# PyPy GC / memory metrics
#


class PyPyGCStats:
    def collect(self):

        # @stats is a pretty-printer object with __str__() returning a nice table,
        # plus some fields that contain data from that table.
        # unfortunately, fields are pretty-printed themselves (i. e. '4.5MB').
        stats = gc.get_stats(memory_pressure=False)  # type: ignore
        # @s contains same fields as @stats, but as actual integers.
        s = stats._s  # type: ignore

        # also note that field naming is completely braindead
        # and only vaguely correlates with the pretty-printed table.
        # >>>> gc.get_stats(False)
        # Total memory consumed:
        #     GC used:            8.7MB (peak: 39.0MB)        # s.total_gc_memory, s.peak_memory
        #        in arenas:            3.0MB                  # s.total_arena_memory
        #        rawmalloced:          1.7MB                  # s.total_rawmalloced_memory
        #        nursery:              4.0MB                  # s.nursery_size
        #     raw assembler used: 31.0kB                      # s.jit_backend_used
        #     -----------------------------
        #     Total:              8.8MB                       # stats.memory_used_sum
        #
        #     Total memory allocated:
        #     GC allocated:            38.7MB (peak: 41.1MB)  # s.total_allocated_memory, s.peak_allocated_memory
        #        in arenas:            30.9MB                 # s.peak_arena_memory
        #        rawmalloced:          4.1MB                  # s.peak_rawmalloced_memory
        #        nursery:              4.0MB                  # s.nursery_size
        #     raw assembler allocated: 1.0MB                  # s.jit_backend_allocated
        #     -----------------------------
        #     Total:                   39.7MB                 # stats.memory_allocated_sum
        #
        #     Total time spent in GC:  0.073                  # s.total_gc_time

        pypy_gc_time = CounterMetricFamily(
            "pypy_gc_time_seconds_total", "Total time spent in PyPy GC", labels=[],
        )
        pypy_gc_time.add_metric([], s.total_gc_time / 1000)
        yield pypy_gc_time

        pypy_mem = GaugeMetricFamily(
            "pypy_memory_bytes",
            "Memory tracked by PyPy allocator",
            labels=["state", "class", "kind"],
        )
        # memory used by JIT assembler
        pypy_mem.add_metric(["used", "", "jit"], s.jit_backend_used)
        pypy_mem.add_metric(["allocated", "", "jit"], s.jit_backend_allocated)
        # memory used by GCed objects
        pypy_mem.add_metric(["used", "", "arenas"], s.total_arena_memory)
        pypy_mem.add_metric(["allocated", "", "arenas"], s.peak_arena_memory)
        pypy_mem.add_metric(["used", "", "rawmalloced"], s.total_rawmalloced_memory)
        pypy_mem.add_metric(["allocated", "", "rawmalloced"], s.peak_rawmalloced_memory)
        pypy_mem.add_metric(["used", "", "nursery"], s.nursery_size)
        pypy_mem.add_metric(["allocated", "", "nursery"], s.nursery_size)
        # totals
        pypy_mem.add_metric(["used", "totals", "gc"], s.total_gc_memory)
        pypy_mem.add_metric(["allocated", "totals", "gc"], s.total_allocated_memory)
        pypy_mem.add_metric(["used", "totals", "gc_peak"], s.peak_memory)
        pypy_mem.add_metric(["allocated", "totals", "gc_peak"], s.peak_allocated_memory)
        yield pypy_mem


if running_on_pypy:
    REGISTRY.register(PyPyGCStats())


#
# Twisted reactor metrics
#

tick_time = Histogram(
    "python_twisted_reactor_tick_time",
    "Tick time of the Twisted reactor (sec)",
    buckets=[0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.5, 1, 2, 5],
)
pending_calls_metric = Histogram(
    "python_twisted_reactor_pending_calls",
    "Pending calls",
    buckets=[1, 2, 5, 10, 25, 50, 100, 250, 500, 1000],
)

#
# Federation Metrics
#

sent_transactions_counter = Counter("synapse_federation_client_sent_transactions", "")

events_processed_counter = Counter("synapse_federation_client_events_processed", "")

event_processing_loop_counter = Counter(
    "synapse_event_processing_loop_count", "Event processing loop iterations", ["name"]
)

event_processing_loop_room_count = Counter(
    "synapse_event_processing_loop_room_count",
    "Rooms seen per event processing loop iteration",
    ["name"],
)


# Used to track where various components have processed in the event stream,
# e.g. federation sending, appservice sending, etc.
event_processing_positions = Gauge("synapse_event_processing_positions", "", ["name"])

# Used to track the current max events stream position
event_persisted_position = Gauge("synapse_event_persisted_position", "")

# Used to track the received_ts of the last event processed by various
# components
event_processing_last_ts = Gauge("synapse_event_processing_last_ts", "", ["name"])

# Used to track the lag processing events. This is the time difference
# between the last processed event's received_ts and the time it was
# finished being processed.
event_processing_lag = Gauge("synapse_event_processing_lag", "", ["name"])

event_processing_lag_by_event = Histogram(
    "synapse_event_processing_lag_by_event",
    "Time between an event being persisted and it being queued up to be sent to the relevant remote servers",
    ["name"],
)

# Build info of the running server.
build_info = Gauge(
    "synapse_build_info", "Build information", ["pythonversion", "version", "osversion"]
)
build_info.labels(
    " ".join([platform.python_implementation(), platform.python_version()]),
    get_version_string(synapse),
    " ".join([platform.system(), platform.release()]),
).set(1)

last_ticked = time.time()


class ReactorLastSeenMetric:
    def collect(self):
        cm = GaugeMetricFamily(
            "python_twisted_reactor_last_seen",
            "Seconds since the Twisted reactor was last seen",
        )
        cm.add_metric([], time.time() - last_ticked)
        yield cm


REGISTRY.register(ReactorLastSeenMetric())


def runUntilCurrentTimer(func):
    @functools.wraps(func)
    def f(*args, **kwargs):
        now = reactor.seconds()
        num_pending = 0

        # _newTimedCalls is one long list of *all* pending calls. Below loop
        # is based off of impl of reactor.runUntilCurrent
        for delayed_call in reactor._newTimedCalls:
            if delayed_call.time > now:
                break

            if delayed_call.delayed_time > 0:
                continue

            num_pending += 1

        num_pending += len(reactor.threadCallQueue)
        start = time.time()
        ret = func(*args, **kwargs)
        end = time.time()

        # record the amount of wallclock time spent running pending calls.
        # This is a proxy for the actual amount of time between reactor polls,
        # since about 25% of time is actually spent running things triggered by
        # I/O events, but that is harder to capture without rewriting half the
        # reactor.
        tick_time.observe(end - start)
        pending_calls_metric.observe(num_pending)

        # Update the time we last ticked, for the metric to test whether
        # Synapse's reactor has frozen
        global last_ticked
        last_ticked = end

        if running_on_pypy:
            return ret

        # Check if we need to do a manual GC (since its been disabled), and do
        # one if necessary.
        threshold = gc.get_threshold()
        counts = gc.get_count()
        for i in (2, 1, 0):
            if threshold[i] < counts[i]:
                if i == 0:
                    logger.debug("Collecting gc %d", i)
                else:
                    logger.info("Collecting gc %d", i)

                start = time.time()
                unreachable = gc.collect(i)
                end = time.time()

                gc_time.labels(i).observe(end - start)
                gc_unreachable.labels(i).set(unreachable)

        return ret

    return f


try:
    # Ensure the reactor has all the attributes we expect
    reactor.runUntilCurrent
    reactor._newTimedCalls
    reactor.threadCallQueue

    # runUntilCurrent is called when we have pending calls. It is called once
    # per iteratation after fd polling.
    reactor.runUntilCurrent = runUntilCurrentTimer(reactor.runUntilCurrent)

    # We manually run the GC each reactor tick so that we can get some metrics
    # about time spent doing GC,
    if not running_on_pypy:
        gc.disable()
except AttributeError:
    pass

__all__ = [
    "MetricsResource",
    "generate_latest",
    "start_http_server",
    "LaterGauge",
    "InFlightGauge",
    "BucketCollector",
]
