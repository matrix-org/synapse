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
import logging
import os
import platform
import threading
import time

import six

import attr
from prometheus_client import Counter, Gauge, Histogram
from prometheus_client.core import REGISTRY, GaugeMetricFamily, HistogramMetricFamily

from twisted.internet import reactor

logger = logging.getLogger(__name__)

running_on_pypy = platform.python_implementation() == "PyPy"
all_metrics = []
all_collectors = []
all_gauges = {}

HAVE_PROC_SELF_STAT = os.path.exists("/proc/self/stat")


class RegistryProxy(object):
    @staticmethod
    def collect():
        for metric in REGISTRY.collect():
            if not metric.name.startswith("__"):
                yield metric


@attr.s(hash=True)
class LaterGauge(object):

    name = attr.ib()
    desc = attr.ib()
    labels = attr.ib(hash=False)
    caller = attr.ib()

    def collect(self):

        g = GaugeMetricFamily(self.name, self.desc, labels=self.labels)

        try:
            calls = self.caller()
        except Exception:
            logger.exception("Exception running callback for LaterGauge(%s)", self.name)
            yield g
            return

        if isinstance(calls, dict):
            for k, v in six.iteritems(calls):
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


class InFlightGauge(object):
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
        self._registrations = {}

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
            for key, metrics in six.iteritems(metrics_by_key):
                gauge.add_metric(key, getattr(metrics, name))
            yield gauge

    def _register_with_collector(self):
        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


@attr.s(hash=True)
class BucketCollector(object):
    """
    Like a Histogram, but allows buckets to be point-in-time instead of
    incrementally added to.

    Args:
        name (str): Base name of metric to be exported to Prometheus.
        data_collector (callable -> dict): A synchronous callable that
            returns a dict mapping bucket to number of items in the
            bucket. If these buckets are not the same as the buckets
            given to this class, they will be remapped into them.
        buckets (list[float]): List of floats/ints of the buckets to
            give to Prometheus. +Inf is ignored, if given.

    """

    name = attr.ib()
    data_collector = attr.ib()
    buckets = attr.ib()

    def collect(self):

        # Fetch the data -- this must be synchronous!
        data = self.data_collector()

        buckets = {}

        res = []
        for x in data.keys():
            for i, bound in enumerate(self.buckets):
                if x <= bound:
                    buckets[bound] = buckets.get(bound, 0) + data[x]

        for i in self.buckets:
            res.append([str(i), buckets.get(i, 0)])

        res.append(["+Inf", sum(data.values())])

        metric = HistogramMetricFamily(
            self.name, "", buckets=res, sum_value=sum([x * y for x, y in data.items()])
        )
        yield metric

    def __attrs_post_init__(self):
        self.buckets = [float(x) for x in self.buckets if x != "+Inf"]
        if self.buckets != sorted(self.buckets):
            raise ValueError("Buckets not sorted")

        self.buckets = tuple(self.buckets)

        if self.name in all_gauges.keys():
            logger.warning("%s already registered, reregistering" % (self.name,))
            REGISTRY.unregister(all_gauges.pop(self.name))

        REGISTRY.register(self)
        all_gauges[self.name] = self


#
# Detailed CPU metrics
#


class CPUMetrics(object):
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


class GCCounts(object):
    def collect(self):
        cm = GaugeMetricFamily("python_gc_counts", "GC object counts", labels=["gen"])
        for n, m in enumerate(gc.get_count()):
            cm.add_metric([str(n)], m)

        yield cm


if not running_on_pypy:
    REGISTRY.register(GCCounts())

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

last_ticked = time.time()


class ReactorLastSeenMetric(object):
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
