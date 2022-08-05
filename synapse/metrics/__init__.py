# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2022 The Matrix.org Foundation C.I.C.
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

import itertools
import logging
import os
import platform
import threading
from typing import (
    Callable,
    Dict,
    Generic,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)

import attr
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Metric
from prometheus_client.core import (
    REGISTRY,
    GaugeHistogramMetricFamily,
    GaugeMetricFamily,
)

from twisted.python.threadpool import ThreadPool

# This module is imported for its side effects; flake8 needn't warn that it's unused.
import synapse.metrics._reactor_metrics  # noqa: F401
from synapse.metrics._exposition import (
    MetricsResource,
    generate_latest,
    start_http_server,
)
from synapse.metrics._gc import MIN_TIME_BETWEEN_GCS, install_gc_manager
from synapse.metrics._types import Collector
from synapse.util import SYNAPSE_VERSION

logger = logging.getLogger(__name__)

METRICS_PREFIX = "/_synapse/metrics"

all_gauges: Dict[str, Collector] = {}

HAVE_PROC_SELF_STAT = os.path.exists("/proc/self/stat")


class _RegistryProxy:
    @staticmethod
    def collect() -> Iterable[Metric]:
        for metric in REGISTRY.collect():
            if not metric.name.startswith("__"):
                yield metric


# A little bit nasty, but collect() above is static so a Protocol doesn't work.
# _RegistryProxy matches the signature of a CollectorRegistry instance enough
# for it to be usable in the contexts in which we use it.
# TODO Do something nicer about this.
RegistryProxy = cast(CollectorRegistry, _RegistryProxy)


@attr.s(slots=True, hash=True, auto_attribs=True)
class LaterGauge(Collector):
    name: str
    desc: str
    labels: Optional[Sequence[str]] = attr.ib(hash=False)
    # callback: should either return a value (if there are no labels for this metric),
    # or dict mapping from a label tuple to a value
    caller: Callable[
        [], Union[Mapping[Tuple[str, ...], Union[int, float]], Union[int, float]]
    ]

    def collect(self) -> Iterable[Metric]:

        g = GaugeMetricFamily(self.name, self.desc, labels=self.labels)

        try:
            calls = self.caller()
        except Exception:
            logger.exception("Exception running callback for LaterGauge(%s)", self.name)
            yield g
            return

        if isinstance(calls, (int, float)):
            g.add_metric([], calls)
        else:
            for k, v in calls.items():
                g.add_metric(k, v)

        yield g

    def __attrs_post_init__(self) -> None:
        self._register()

    def _register(self) -> None:
        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


# `MetricsEntry` only makes sense when it is a `Protocol`,
# but `Protocol` can't be used as a `TypeVar` bound.
MetricsEntry = TypeVar("MetricsEntry")


class InFlightGauge(Generic[MetricsEntry], Collector):
    """Tracks number of things (e.g. requests, Measure blocks, etc) in flight
    at any given time.

    Each InFlightGauge will create a metric called `<name>_total` that counts
    the number of in flight blocks, as well as a metrics for each item in the
    given `sub_metrics` as `<name>_<sub_metric>` which will get updated by the
    callbacks.

    Args:
        name
        desc
        labels
        sub_metrics: A list of sub metrics that the callbacks will update.
    """

    def __init__(
        self,
        name: str,
        desc: str,
        labels: Sequence[str],
        sub_metrics: Sequence[str],
    ):
        self.name = name
        self.desc = desc
        self.labels = labels
        self.sub_metrics = sub_metrics

        # Create a class which have the sub_metrics values as attributes, which
        # default to 0 on initialization. Used to pass to registered callbacks.
        self._metrics_class: Type[MetricsEntry] = attr.make_class(
            "_MetricsEntry",
            attrs={x: attr.ib(default=0) for x in sub_metrics},
            slots=True,
        )

        # Counts number of in flight blocks for a given set of label values
        self._registrations: Dict[
            Tuple[str, ...], Set[Callable[[MetricsEntry], None]]
        ] = {}

        # Protects access to _registrations
        self._lock = threading.Lock()

        self._register_with_collector()

    def register(
        self,
        key: Tuple[str, ...],
        callback: Callable[[MetricsEntry], None],
    ) -> None:
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

    def unregister(
        self,
        key: Tuple[str, ...],
        callback: Callable[[MetricsEntry], None],
    ) -> None:
        """Registers that we've exited a block with labels `key`."""

        with self._lock:
            self._registrations.setdefault(key, set()).discard(callback)

    def collect(self) -> Iterable[Metric]:
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

    def _register_with_collector(self) -> None:
        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


class GaugeBucketCollector(Collector):
    """Like a Histogram, but the buckets are Gauges which are updated atomically.

    The data is updated by calling `update_data` with an iterable of measurements.

    We assume that the data is updated less frequently than it is reported to
    Prometheus, and optimise for that case.
    """

    __slots__ = (
        "_name",
        "_documentation",
        "_bucket_bounds",
        "_metric",
    )

    def __init__(
        self,
        name: str,
        documentation: str,
        buckets: Iterable[float],
        registry: CollectorRegistry = REGISTRY,
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

        # We initially set this to None. We won't report metrics until
        # this has been initialised after a successful data update
        self._metric: Optional[GaugeHistogramMetricFamily] = None

        registry.register(self)

    def collect(self) -> Iterable[Metric]:
        # Don't report metrics unless we've already collected some data
        if self._metric is not None:
            yield self._metric

    def update_data(self, values: Iterable[float]) -> None:
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


class CPUMetrics(Collector):
    def __init__(self) -> None:
        ticks_per_sec = 100
        try:
            # Try and get the system config
            ticks_per_sec = os.sysconf("SC_CLK_TCK")
        except (ValueError, TypeError, AttributeError):
            pass

        self.ticks_per_sec = ticks_per_sec

    def collect(self) -> Iterable[Metric]:
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
    SYNAPSE_VERSION,
    " ".join([platform.system(), platform.release()]),
).set(1)

# 3PID send info
threepid_send_requests = Histogram(
    "synapse_threepid_send_requests_with_tries",
    documentation="Number of requests for a 3pid token by try count. Note if"
    " there is a request with try count of 4, then there would have been one"
    " each for 1, 2 and 3",
    buckets=(1, 2, 3, 4, 5, 10),
    labelnames=("type", "reason"),
)

threadpool_total_threads = Gauge(
    "synapse_threadpool_total_threads",
    "Total number of threads currently in the threadpool",
    ["name"],
)

threadpool_total_working_threads = Gauge(
    "synapse_threadpool_working_threads",
    "Number of threads currently working in the threadpool",
    ["name"],
)

threadpool_total_min_threads = Gauge(
    "synapse_threadpool_min_threads",
    "Minimum number of threads configured in the threadpool",
    ["name"],
)

threadpool_total_max_threads = Gauge(
    "synapse_threadpool_max_threads",
    "Maximum number of threads configured in the threadpool",
    ["name"],
)


def register_threadpool(name: str, threadpool: ThreadPool) -> None:
    """Add metrics for the threadpool."""

    threadpool_total_min_threads.labels(name).set(threadpool.min)
    threadpool_total_max_threads.labels(name).set(threadpool.max)

    threadpool_total_threads.labels(name).set_function(lambda: len(threadpool.threads))
    threadpool_total_working_threads.labels(name).set_function(
        lambda: len(threadpool.working)
    )


__all__ = [
    "Collector",
    "MetricsResource",
    "generate_latest",
    "start_http_server",
    "LaterGauge",
    "InFlightGauge",
    "GaugeBucketCollector",
    "MIN_TIME_BETWEEN_GCS",
    "install_gc_manager",
]
