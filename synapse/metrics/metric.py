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


class BaseMetric(object):

    def __init__(self, name, keys=[]):
        self.name = name
        self.keys = keys # OK not to clone as we never write it

    def _render_key(self, values):
        # TODO: some kind of value escape
        return ",".join(["%s=%s" % kv for kv in zip(self.keys, values)])


class CounterMetric(BaseMetric):
    """The simplest kind of metric; one that stores a monotonically-increasing
    integer that counts events."""

    def __init__(self, *args, **kwargs):
        super(CounterMetric, self).__init__(*args, **kwargs)

        self.counts = {}

        # Scalar metrics are never empty
        if not len(self.keys):
            self.counts[()] = 0

    def inc(self, *values):
        if len(values) != len(self.keys):
            raise ValueError("Expected as many values to inc() as keys (%d)" %
                (len(self.keys))
            )

        # TODO: should assert that the tag values are all strings

        if values not in self.counts:
            self.counts[values] = 1
        else:
            self.counts[values] += 1

    def fetch(self):
        return dict(self.counts)

    def render(self):
        if not len(self.keys):
            return ["%s %d" % (self.name, self.counts[()])]

        return ["%s{%s} %d" % (self.name, self._render_key(k), self.counts[k])
                for k in sorted(self.counts.keys())]


class CacheCounterMetric(object):
    """A combination of two CounterMetrics, one to count cache hits and one to
    count misses.

    This metric generates standard metric name pairs, so that monitoring rules
    can easily be applied to measure hit ratio."""

    def __init__(self, name, keys=[]):
        self.name = name

        self.hits   = CounterMetric(name + ":hits",   keys=keys)
        self.misses = CounterMetric(name + ":misses", keys=keys)

    def inc_hits(self, *values):
        self.hits.inc(*values)

    def inc_misses(self, *values):
        self.misses.inc(*values)

    def render(self):
        return self.hits.render() + self.misses.render()
