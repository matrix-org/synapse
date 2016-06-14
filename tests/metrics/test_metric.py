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

from tests import unittest

from synapse.metrics.metric import (
    CounterMetric, CallbackMetric, DistributionMetric, CacheMetric
)


class CounterMetricTestCase(unittest.TestCase):

    def test_scalar(self):
        counter = CounterMetric("scalar")

        self.assertEquals(counter.render(), [
            'scalar 0',
        ])

        counter.inc()

        self.assertEquals(counter.render(), [
            'scalar 1',
        ])

        counter.inc_by(2)

        self.assertEquals(counter.render(), [
            'scalar 3'
        ])

    def test_vector(self):
        counter = CounterMetric("vector", labels=["method"])

        # Empty counter doesn't yet know what values it has
        self.assertEquals(counter.render(), [])

        counter.inc("GET")

        self.assertEquals(counter.render(), [
            'vector{method="GET"} 1',
        ])

        counter.inc("GET")
        counter.inc("PUT")

        self.assertEquals(counter.render(), [
            'vector{method="GET"} 2',
            'vector{method="PUT"} 1',
        ])


class CallbackMetricTestCase(unittest.TestCase):

    def test_scalar(self):
        d = dict()

        metric = CallbackMetric("size", lambda: len(d))

        self.assertEquals(metric.render(), [
            'size 0',
        ])

        d["key"] = "value"

        self.assertEquals(metric.render(), [
            'size 1',
        ])

    def test_vector(self):
        vals = dict()

        metric = CallbackMetric("values", lambda: vals, labels=["type"])

        self.assertEquals(metric.render(), [])

        # Keys have to be tuples, even if they're 1-element
        vals[("foo",)] = 1
        vals[("bar",)] = 2

        self.assertEquals(metric.render(), [
            'values{type="bar"} 2',
            'values{type="foo"} 1',
        ])


class DistributionMetricTestCase(unittest.TestCase):

    def test_scalar(self):
        metric = DistributionMetric("thing")

        self.assertEquals(metric.render(), [
            'thing:count 0',
            'thing:total 0',
        ])

        metric.inc_by(500)

        self.assertEquals(metric.render(), [
            'thing:count 1',
            'thing:total 500',
        ])

    def test_vector(self):
        metric = DistributionMetric("queries", labels=["verb"])

        self.assertEquals(metric.render(), [])

        metric.inc_by(300, "SELECT")
        metric.inc_by(200, "SELECT")
        metric.inc_by(800, "INSERT")

        self.assertEquals(metric.render(), [
            'queries:count{verb="INSERT"} 1',
            'queries:count{verb="SELECT"} 2',
            'queries:total{verb="INSERT"} 800',
            'queries:total{verb="SELECT"} 500',
        ])


class CacheMetricTestCase(unittest.TestCase):

    def test_cache(self):
        d = dict()

        metric = CacheMetric("cache", lambda: len(d), "cache_name")

        self.assertEquals(metric.render(), [
            'cache:hits{name="cache_name"} 0',
            'cache:total{name="cache_name"} 0',
            'cache:size{name="cache_name"} 0',
        ])

        metric.inc_misses()
        d["key"] = "value"

        self.assertEquals(metric.render(), [
            'cache:hits{name="cache_name"} 0',
            'cache:total{name="cache_name"} 1',
            'cache:size{name="cache_name"} 1',
        ])

        metric.inc_hits()

        self.assertEquals(metric.render(), [
            'cache:hits{name="cache_name"} 1',
            'cache:total{name="cache_name"} 2',
            'cache:size{name="cache_name"} 1',
        ])
