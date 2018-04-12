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
import functools
import time
import gc
import platform

from twisted.internet import reactor

from .metric import (
    CounterMetric, CallbackMetric, DistributionMetric, CacheMetric,
    MemoryUsageMetric, GaugeMetric,
)
from .process_collector import register_process_collector


logger = logging.getLogger(__name__)


running_on_pypy = platform.python_implementation() == 'PyPy'
all_metrics = []
all_collectors = []


class Metrics(object):
    """ A single Metrics object gives a (mutable) slice view of the all_metrics
    dict, allowing callers to easily register new metrics that are namespaced
    nicely."""

    def __init__(self, name):
        self.name_prefix = name

    def make_subspace(self, name):
        return Metrics("%s_%s" % (self.name_prefix, name))

    def register_collector(self, func):
        all_collectors.append(func)

    def _register(self, metric_class, name, *args, **kwargs):
        full_name = "%s_%s" % (self.name_prefix, name)

        metric = metric_class(full_name, *args, **kwargs)

        all_metrics.append(metric)
        return metric

    def register_counter(self, *args, **kwargs):
        """
        Returns:
            CounterMetric
        """
        return self._register(CounterMetric, *args, **kwargs)

    def register_gauge(self, *args, **kwargs):
        """
        Returns:
            GaugeMetric
        """
        return self._register(GaugeMetric, *args, **kwargs)

    def register_callback(self, *args, **kwargs):
        """
        Returns:
            CallbackMetric
        """
        return self._register(CallbackMetric, *args, **kwargs)

    def register_distribution(self, *args, **kwargs):
        """
        Returns:
            DistributionMetric
        """
        return self._register(DistributionMetric, *args, **kwargs)

    def register_cache(self, *args, **kwargs):
        """
        Returns:
            CacheMetric
        """
        return self._register(CacheMetric, *args, **kwargs)


def register_memory_metrics(hs):
    try:
        import psutil
        process = psutil.Process()
        process.memory_info().rss
    except (ImportError, AttributeError):
        logger.warn(
            "psutil is not installed or incorrect version."
            " Disabling memory metrics."
        )
        return
    metric = MemoryUsageMetric(hs, psutil)
    all_metrics.append(metric)


def get_metrics_for(pkg_name):
    """ Returns a Metrics instance for conveniently creating metrics
    namespaced with the given name prefix. """

    # Convert a "package.name" to "package_name" because Prometheus doesn't
    # let us use . in metric names
    return Metrics(pkg_name.replace(".", "_"))


def render_all():
    strs = []

    for collector in all_collectors:
        collector()

    for metric in all_metrics:
        try:
            strs += metric.render()
        except Exception:
            strs += ["# FAILED to render"]
            logger.exception("Failed to render metric")

    strs.append("")  # to generate a final CRLF

    return "\n".join(strs)


register_process_collector(get_metrics_for("process"))


python_metrics = get_metrics_for("python")

gc_time = python_metrics.register_distribution("gc_time", labels=["gen"])
gc_unreachable = python_metrics.register_counter("gc_unreachable_total", labels=["gen"])
python_metrics.register_callback(
    "gc_counts", lambda: {(i,): v for i, v in enumerate(gc.get_count())}, labels=["gen"]
)

reactor_metrics = get_metrics_for("python.twisted.reactor")
tick_time = reactor_metrics.register_distribution("tick_time")
pending_calls_metric = reactor_metrics.register_distribution("pending_calls")

synapse_metrics = get_metrics_for("synapse")

# Used to track where various components have processed in the event stream,
# e.g. federation sending, appservice sending, etc.
event_processing_positions = synapse_metrics.register_gauge(
    "event_processing_positions", labels=["name"],
)

# Used to track the current max events stream position
event_persisted_position = synapse_metrics.register_gauge(
    "event_persisted_position",
)

# Used to track the received_ts of the last event processed by various
# components
event_processing_last_ts = synapse_metrics.register_gauge(
    "event_processing_last_ts", labels=["name"],
)

# Used to track the lag processing events. This is the time difference
# between the last processed event's received_ts and the time it was
# finished being processed.
event_processing_lag = synapse_metrics.register_gauge(
    "event_processing_lag", labels=["name"],
)


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
        start = time.time() * 1000
        ret = func(*args, **kwargs)
        end = time.time() * 1000

        # record the amount of wallclock time spent running pending calls.
        # This is a proxy for the actual amount of time between reactor polls,
        # since about 25% of time is actually spent running things triggered by
        # I/O events, but that is harder to capture without rewriting half the
        # reactor.
        tick_time.inc_by(end - start)
        pending_calls_metric.inc_by(num_pending)

        if running_on_pypy:
            return ret

        # Check if we need to do a manual GC (since its been disabled), and do
        # one if necessary.
        threshold = gc.get_threshold()
        counts = gc.get_count()
        for i in (2, 1, 0):
            if threshold[i] < counts[i]:
                logger.info("Collecting gc %d", i)

                start = time.time() * 1000
                unreachable = gc.collect(i)
                end = time.time() * 1000

                gc_time.inc_by(end - start, i)
                gc_unreachable.inc_by(unreachable, i)

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
