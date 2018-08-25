# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

import threading

import six

from prometheus_client.core import REGISTRY, Counter, GaugeMetricFamily

from twisted.internet import defer

from synapse.util.logcontext import LoggingContext, PreserveLoggingContext

_background_process_start_count = Counter(
    "synapse_background_process_start_count",
    "Number of background processes started",
    ["name"],
)

# we set registry=None in all of these to stop them getting registered with
# the default registry. Instead we collect them all via the CustomCollector,
# which ensures that we can update them before they are collected.
#
_background_process_ru_utime = Counter(
    "synapse_background_process_ru_utime_seconds",
    "User CPU time used by background processes, in seconds",
    ["name"],
    registry=None,
)

_background_process_ru_stime = Counter(
    "synapse_background_process_ru_stime_seconds",
    "System CPU time used by background processes, in seconds",
    ["name"],
    registry=None,
)

_background_process_db_txn_count = Counter(
    "synapse_background_process_db_txn_count",
    "Number of database transactions done by background processes",
    ["name"],
    registry=None,
)

_background_process_db_txn_duration = Counter(
    "synapse_background_process_db_txn_duration_seconds",
    ("Seconds spent by background processes waiting for database "
     "transactions, excluding scheduling time"),
    ["name"],
    registry=None,
)

_background_process_db_sched_duration = Counter(
    "synapse_background_process_db_sched_duration_seconds",
    "Seconds spent by background processes waiting for database connections",
    ["name"],
    registry=None,
)

# map from description to a counter, so that we can name our logcontexts
# incrementally. (It actually duplicates _background_process_start_count, but
# it's much simpler to do so than to try to combine them.)
_background_process_counts = dict()  # type: dict[str, int]

# map from description to the currently running background processes.
#
# it's kept as a dict of sets rather than a big set so that we can keep track
# of process descriptions that no longer have any active processes.
_background_processes = dict()  # type: dict[str, set[_BackgroundProcess]]

# A lock that covers the above dicts
_bg_metrics_lock = threading.Lock()


class _Collector(object):
    """A custom metrics collector for the background process metrics.

    Ensures that all of the metrics are up-to-date with any in-flight processes
    before they are returned.
    """
    def collect(self):
        background_process_in_flight_count = GaugeMetricFamily(
            "synapse_background_process_in_flight_count",
            "Number of background processes in flight",
            labels=["name"],
        )

        # We copy the dict so that it doesn't change from underneath us
        with _bg_metrics_lock:
            _background_processes_copy = dict(_background_processes)

        for desc, processes in six.iteritems(_background_processes_copy):
            background_process_in_flight_count.add_metric(
                (desc,), len(processes),
            )
            for process in processes:
                process.update_metrics()

        yield background_process_in_flight_count

        # now we need to run collect() over each of the static Counters, and
        # yield each metric they return.
        for m in (
                _background_process_ru_utime,
                _background_process_ru_stime,
                _background_process_db_txn_count,
                _background_process_db_txn_duration,
                _background_process_db_sched_duration,
        ):
            for r in m.collect():
                yield r


REGISTRY.register(_Collector())


class _BackgroundProcess(object):
    def __init__(self, desc, ctx):
        self.desc = desc
        self._context = ctx
        self._reported_stats = None

    def update_metrics(self):
        """Updates the metrics with values from this process."""
        new_stats = self._context.get_resource_usage()
        if self._reported_stats is None:
            diff = new_stats
        else:
            diff = new_stats - self._reported_stats
        self._reported_stats = new_stats

        _background_process_ru_utime.labels(self.desc).inc(diff.ru_utime)
        _background_process_ru_stime.labels(self.desc).inc(diff.ru_stime)
        _background_process_db_txn_count.labels(self.desc).inc(
            diff.db_txn_count,
        )
        _background_process_db_txn_duration.labels(self.desc).inc(
            diff.db_txn_duration_sec,
        )
        _background_process_db_sched_duration.labels(self.desc).inc(
            diff.db_sched_duration_sec,
        )


def run_as_background_process(desc, func, *args, **kwargs):
    """Run the given function in its own logcontext, with resource metrics

    This should be used to wrap processes which are fired off to run in the
    background, instead of being associated with a particular request.

    It returns a Deferred which completes when the function completes, but it doesn't
    follow the synapse logcontext rules, which makes it appropriate for passing to
    clock.looping_call and friends (or for firing-and-forgetting in the middle of a
    normal synapse inlineCallbacks function).

    Args:
        desc (str): a description for this background process type
        func: a function, which may return a Deferred
        args: positional args for func
        kwargs: keyword args for func

    Returns: Deferred which returns the result of func, but note that it does not
        follow the synapse logcontext rules.
    """
    @defer.inlineCallbacks
    def run():
        with _bg_metrics_lock:
            count = _background_process_counts.get(desc, 0)
            _background_process_counts[desc] = count + 1

        _background_process_start_count.labels(desc).inc()

        with LoggingContext(desc) as context:
            context.request = "%s-%i" % (desc, count)
            proc = _BackgroundProcess(desc, context)

            with _bg_metrics_lock:
                _background_processes.setdefault(desc, set()).add(proc)

            try:
                yield func(*args, **kwargs)
            finally:
                proc.update_metrics()

                with _bg_metrics_lock:
                    _background_processes[desc].remove(proc)

    with PreserveLoggingContext():
        return run()
