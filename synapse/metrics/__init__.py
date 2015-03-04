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

import logging

from .metric import CounterMetric, CallbackMetric, CacheMetric


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

    def _register(self, metric):
        all_metrics[metric.name] = metric

    def register_counter(self, name, *args, **kwargs):
        full_name = "%s.%s" % (self.name_prefix, name)

        metric = CounterMetric(full_name, *args, **kwargs)

        self._register(metric)

        return metric

    def register_callback(self, name, callback, *args, **kwargs):
        full_name = "%s.%s" % (self.name_prefix, name)

        metric = CallbackMetric(full_name, *args, callback=callback, **kwargs)

        self._register(metric)

        return metric

    def register_cache(self, name, *args, **kwargs):
        full_name = "%s.%s" % (self.name_prefix, name)

        metric = CacheMetric(full_name, *args, **kwargs)

        self._register(metric)

        return metric

    def counted(self, func):
        """ A method decorator that registers a counter, to count invocations
        of this method. """
        counter = self.register_counter(func.__name__)

        def wrapped(*args, **kwargs):
            counter.inc()
            return func(*args, **kwargs)
        return wrapped


def get_metrics_for(name):
    """ Returns a Metrics instance for conveniently creating metrics
    namespaced with the given name prefix. """
    return Metrics(name)


def render_all():
    strs = []

    for name in sorted(all_metrics.keys()):
        try:
            strs += all_metrics[name].render()
        except Exception as e:
            strs += ["# FAILED to render %s" % name]
            logger.exception("Failed to render %s metric", name)

    return "\n".join(strs)
