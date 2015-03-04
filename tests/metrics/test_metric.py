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

from tests import unittest

from synapse.metrics.metric import (
    CounterMetric, CallbackMetric, CacheMetric
)


class CounterMetricTestCase(unittest.TestCase):

    def test_scalar(self):
        counter = CounterMetric("scalar")

        self.assertEquals(counter.render(), [
            "scalar 0",
        ])

        counter.inc()

        self.assertEquals(counter.render(), [
            "scalar 1",
        ])

        counter.inc()
        counter.inc()

        self.assertEquals(counter.render(), [
            "scalar 3"
        ])

    def test_vector(self):
        counter = CounterMetric("vector", keys=["method"])

        # Empty counter doesn't yet know what values it has
        self.assertEquals(counter.render(), [])

        counter.inc("GET")

        self.assertEquals(counter.render(), [
            "vector{method=GET} 1",
        ])

        counter.inc("GET")
        counter.inc("PUT")

        self.assertEquals(counter.render(), [
            "vector{method=GET} 2",
            "vector{method=PUT} 1",
        ])


class CallbackMetricTestCase(unittest.TestCase):

    def test_callback(self):
        d = dict()

        metric = CallbackMetric("size", lambda: len(d))

        self.assertEquals(metric.render(), [
            "size 0",
        ])

        d["key"] = "value"

        self.assertEquals(metric.render(), [
            "size 1",
        ])


class CacheMetricTestCase(unittest.TestCase):

    def test_cache(self):
        d = dict()

        metric = CacheMetric("cache", lambda: len(d))

        self.assertEquals(metric.render(), [
            "cache:hits 0",
            "cache:misses 0",
            "cache:size 0",
        ])

        metric.inc_misses()
        d["key"] = "value"

        self.assertEquals(metric.render(), [
            "cache:hits 0",
            "cache:misses 1",
            "cache:size 1",
        ])

        metric.inc_hits()

        self.assertEquals(metric.render(), [
            "cache:hits 1",
            "cache:misses 1",
            "cache:size 1",
        ])
