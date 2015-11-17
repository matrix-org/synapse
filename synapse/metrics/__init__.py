# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

# Because otherwise 'resource' collides with synapse.metrics.resource
from __future__ import absolute_import

import logging
from resource import getrusage, RUSAGE_SELF
import functools
import os
import stat
import time

from twisted.internet import reactor

from .metric import (
    CounterMetric, CallbackMetric, DistributionMetric, CacheMetric
)


logger = logging.getLogger(__name__)


# We'll keep all the available metrics in a single toplevel dict, one shared
# for the entire process. We don't currently support per-HomeServer instances
# of metrics, because in practice any one python VM will host only one
# HomeServer anyway. This makes a lot of implementation neater
all_metrics = {}


class Metrics(object):
    """ A single Metrics object gives a (mutable) slice view of the all_metrics
    dict, allowing callers to easily register new metrics that are namespaced
    nicely."""

    def __init__(self, name):
        self.name_prefix = name

    def _register(self, metric_class, name, *args, **kwargs):
        full_name = "%s_%s" % (self.name_prefix, name)

        metric = metric_class(full_name, *args, **kwargs)

        all_metrics[full_name] = metric
        return metric

    def register_counter(self, *args, **kwargs):
        return self._register(CounterMetric, *args, **kwargs)

    def register_callback(self, *args, **kwargs):
        return self._register(CallbackMetric, *args, **kwargs)

    def register_distribution(self, *args, **kwargs):
        return self._register(DistributionMetric, *args, **kwargs)

    def register_cache(self, *args, **kwargs):
        return self._register(CacheMetric, *args, **kwargs)


def get_metrics_for(pkg_name):
    """ Returns a Metrics instance for conveniently creating metrics
    namespaced with the given name prefix. """

    # Convert a "package.name" to "package_name" because Prometheus doesn't
    # let us use . in metric names
    return Metrics(pkg_name.replace(".", "_"))


def render_all():
    strs = []

    # TODO(paul): Internal hack
    update_resource_metrics()

    for name in sorted(all_metrics.keys()):
        try:
            strs += all_metrics[name].render()
        except Exception:
            strs += ["# FAILED to render %s" % name]
            logger.exception("Failed to render %s metric", name)

    strs.append("")  # to generate a final CRLF

    return "\n".join(strs)


# Now register some standard process-wide state metrics, to give indications of
# process resource usage

rusage = None


def update_resource_metrics():
    global rusage
    rusage = getrusage(RUSAGE_SELF)

resource_metrics = get_metrics_for("process.resource")

# msecs
resource_metrics.register_callback("utime", lambda: rusage.ru_utime * 1000)
resource_metrics.register_callback("stime", lambda: rusage.ru_stime * 1000)

# kilobytes
resource_metrics.register_callback("maxrss", lambda: rusage.ru_maxrss * 1024)

TYPES = {
    stat.S_IFSOCK: "SOCK",
    stat.S_IFLNK: "LNK",
    stat.S_IFREG: "REG",
    stat.S_IFBLK: "BLK",
    stat.S_IFDIR: "DIR",
    stat.S_IFCHR: "CHR",
    stat.S_IFIFO: "FIFO",
}


def _process_fds():
    counts = {(k,): 0 for k in TYPES.values()}
    counts[("other",)] = 0

    # Not every OS will have a /proc/self/fd directory
    if not os.path.exists("/proc/self/fd"):
        return counts

    for fd in os.listdir("/proc/self/fd"):
        try:
            s = os.stat("/proc/self/fd/%s" % (fd))
            fmt = stat.S_IFMT(s.st_mode)
            if fmt in TYPES:
                t = TYPES[fmt]
            else:
                t = "other"

            counts[(t,)] += 1
        except OSError:
            # the dirh itself used by listdir() is usually missing by now
            pass

    return counts

get_metrics_for("process").register_callback("fds", _process_fds, labels=["type"])

reactor_metrics = get_metrics_for("reactor")
tick_time = reactor_metrics.register_distribution("tick_time")
pending_calls_metric = reactor_metrics.register_distribution("pending_calls")


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
        tick_time.inc_by(end - start)
        pending_calls_metric.inc_by(num_pending)
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
except AttributeError:
    pass
