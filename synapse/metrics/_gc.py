# Copyright 2015-2022 The Matrix.org Foundation C.I.C.
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


import gc
import logging
import platform
import time
from typing import Iterable

from prometheus_client.core import (
    REGISTRY,
    CounterMetricFamily,
    Gauge,
    GaugeMetricFamily,
    Histogram,
    Metric,
)

from twisted.internet import task

from synapse.metrics._types import Collector

"""Prometheus metrics for garbage collection"""


logger = logging.getLogger(__name__)

# The minimum time in seconds between GCs for each generation, regardless of the current GC
# thresholds and counts.
MIN_TIME_BETWEEN_GCS = (1.0, 10.0, 30.0)

running_on_pypy = platform.python_implementation() == "PyPy"

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


class GCCounts(Collector):
    def collect(self) -> Iterable[Metric]:
        cm = GaugeMetricFamily("python_gc_counts", "GC object counts", labels=["gen"])
        for n, m in enumerate(gc.get_count()):
            cm.add_metric([str(n)], m)

        yield cm


def install_gc_manager() -> None:
    """Disable automatic GC, and replace it with a task that runs every 100ms

    This means that (a) we can limit how often GC runs; (b) we can get some metrics
    about GC activity.

    It does nothing on PyPy.
    """

    if running_on_pypy:
        return

    REGISTRY.register(GCCounts())

    gc.disable()

    # The time (in seconds since the epoch) of the last time we did a GC for each generation.
    _last_gc = [0.0, 0.0, 0.0]

    def _maybe_gc() -> None:
        # Check if we need to do a manual GC (since its been disabled), and do
        # one if necessary. Note we go in reverse order as e.g. a gen 1 GC may
        # promote an object into gen 2, and we don't want to handle the same
        # object multiple times.
        threshold = gc.get_threshold()
        counts = gc.get_count()
        end = time.time()
        for i in (2, 1, 0):
            # We check if we need to do one based on a straightforward
            # comparison between the threshold and count. We also do an extra
            # check to make sure that we don't a GC too often.
            if threshold[i] < counts[i] and MIN_TIME_BETWEEN_GCS[i] < end - _last_gc[i]:
                if i == 0:
                    logger.debug("Collecting gc %d", i)
                else:
                    logger.info("Collecting gc %d", i)

                start = time.time()
                unreachable = gc.collect(i)
                end = time.time()

                _last_gc[i] = end

                gc_time.labels(i).observe(end - start)
                gc_unreachable.labels(i).set(unreachable)

    gc_task = task.LoopingCall(_maybe_gc)
    gc_task.start(0.1)


#
# PyPy GC / memory metrics
#


class PyPyGCStats(Collector):
    def collect(self) -> Iterable[Metric]:

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
            "pypy_gc_time_seconds_total",
            "Total time spent in PyPy GC",
            labels=[],
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
