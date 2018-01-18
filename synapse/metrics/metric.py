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


from itertools import chain
import logging

logger = logging.getLogger(__name__)


def flatten(items):
    """Flatten a list of lists

    Args:
        items: iterable[iterable[X]]

    Returns:
        list[X]: flattened list
    """
    return list(chain.from_iterable(items))


class BaseMetric(object):
    """Base class for metrics which report a single value per label set
    """

    def __init__(self, name, labels=[], alternative_names=[]):
        """
        Args:
            name (str): principal name for this metric
            labels (list(str)): names of the labels which will be reported
                for this metric
            alternative_names (iterable(str)): list of alternative names for
                 this metric. This can be useful to provide a migration path
                when renaming metrics.
        """
        self._names = [name] + list(alternative_names)
        self.labels = labels  # OK not to clone as we never write it

    def dimension(self):
        return len(self.labels)

    def is_scalar(self):
        return not len(self.labels)

    def _render_labelvalue(self, value):
        # TODO: escape backslashes, quotes and newlines
        return '"%s"' % (value)

    def _render_key(self, values):
        if self.is_scalar():
            return ""
        return "{%s}" % (
            ",".join(["%s=%s" % (k, self._render_labelvalue(v))
                      for k, v in zip(self.labels, values)])
        )

    def _render_for_labels(self, label_values, value):
        """Render this metric for a single set of labels

        Args:
            label_values (list[str]): values for each of the labels
            value: value of the metric at with these labels

        Returns:
            iterable[str]: rendered metric
        """
        rendered_labels = self._render_key(label_values)
        return (
            "%s%s %.12g" % (name, rendered_labels, value)
            for name in self._names
        )

    def render(self):
        """Render this metric

        Each metric is rendered as:

            name{label1="val1",label2="val2"} value

        https://prometheus.io/docs/instrumenting/exposition_formats/#text-format-details

        Returns:
            iterable[str]: rendered metrics
        """
        raise NotImplementedError()


class CounterMetric(BaseMetric):
    """The simplest kind of metric; one that stores a monotonically-increasing
    value that counts events or running totals.

    Example use cases for Counters:
    - Number of requests processed
    - Number of items that were inserted into a queue
    - Total amount of data that a system has processed
    Counters can only go up (and be reset when the process restarts).
    """

    def __init__(self, *args, **kwargs):
        super(CounterMetric, self).__init__(*args, **kwargs)

        # dict[list[str]]: value for each set of label values. the keys are the
        # label values, in the same order as the labels in self.labels.
        #
        # (if the metric is a scalar, the (single) key is the empty list).
        self.counts = {}

        # Scalar metrics are never empty
        if self.is_scalar():
            self.counts[()] = 0.

    def inc_by(self, incr, *values):
        if len(values) != self.dimension():
            raise ValueError(
                "Expected as many values to inc() as labels (%d)" % (self.dimension())
            )

        # TODO: should assert that the tag values are all strings

        if values not in self.counts:
            self.counts[values] = incr
        else:
            self.counts[values] += incr

    def inc(self, *values):
        self.inc_by(1, *values)

    def render(self):
        return flatten(
            self._render_for_labels(k, self.counts[k])
            for k in sorted(self.counts.keys())
        )


class CallbackMetric(BaseMetric):
    """A metric that returns the numeric value returned by a callback whenever
    it is rendered. Typically this is used to implement gauges that yield the
    size or other state of some in-memory object by actively querying it."""

    def __init__(self, name, callback, labels=[]):
        super(CallbackMetric, self).__init__(name, labels=labels)

        self.callback = callback

    def render(self):
        try:
            value = self.callback()
        except Exception:
            logger.exception("Failed to render %s", self.name)
            return ["# FAILED to render " + self.name]

        if self.is_scalar():
            return list(self._render_for_labels([], value))

        return flatten(
            self._render_for_labels(k, value[k])
            for k in sorted(value.keys())
        )


class DistributionMetric(object):
    """A combination of an event counter and an accumulator, which counts
    both the number of events and accumulates the total value. Typically this
    could be used to keep track of method-running times, or other distributions
    of values that occur in discrete occurances.

    TODO(paul): Try to export some heatmap-style stats?
    """

    def __init__(self, name, *args, **kwargs):
        self.counts = CounterMetric(name + ":count", **kwargs)
        self.totals = CounterMetric(name + ":total", **kwargs)

    def inc_by(self, inc, *values):
        self.counts.inc(*values)
        self.totals.inc_by(inc, *values)

    def render(self):
        return self.counts.render() + self.totals.render()


class CacheMetric(object):
    __slots__ = ("name", "cache_name", "hits", "misses", "size_callback")

    def __init__(self, name, size_callback, cache_name):
        self.name = name
        self.cache_name = cache_name

        self.hits = 0
        self.misses = 0

        self.size_callback = size_callback

    def inc_hits(self):
        self.hits += 1

    def inc_misses(self):
        self.misses += 1

    def render(self):
        size = self.size_callback()
        hits = self.hits
        total = self.misses + self.hits

        return [
            """%s:hits{name="%s"} %d""" % (self.name, self.cache_name, hits),
            """%s:total{name="%s"} %d""" % (self.name, self.cache_name, total),
            """%s:size{name="%s"} %d""" % (self.name, self.cache_name, size),
        ]


class MemoryUsageMetric(object):
    """Keeps track of the current memory usage, using psutil.

    The class will keep the current min/max/sum/counts of rss over the last
    WINDOW_SIZE_SEC, by polling UPDATE_HZ times per second
    """

    UPDATE_HZ = 2  # number of times to get memory per second
    WINDOW_SIZE_SEC = 30  # the size of the window in seconds

    def __init__(self, hs, psutil):
        clock = hs.get_clock()
        self.memory_snapshots = []

        self.process = psutil.Process()

        clock.looping_call(self._update_curr_values, 1000 / self.UPDATE_HZ)

    def _update_curr_values(self):
        max_size = self.UPDATE_HZ * self.WINDOW_SIZE_SEC
        self.memory_snapshots.append(self.process.memory_info().rss)
        self.memory_snapshots[:] = self.memory_snapshots[-max_size:]

    def render(self):
        if not self.memory_snapshots:
            return []

        max_rss = max(self.memory_snapshots)
        min_rss = min(self.memory_snapshots)
        sum_rss = sum(self.memory_snapshots)
        len_rss = len(self.memory_snapshots)

        return [
            "process_psutil_rss:max %d" % max_rss,
            "process_psutil_rss:min %d" % min_rss,
            "process_psutil_rss:total %d" % sum_rss,
            "process_psutil_rss:count %d" % len_rss,
        ]
