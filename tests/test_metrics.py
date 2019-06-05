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


from synapse.metrics import InFlightGauge

from tests import unittest


def get_sample_labels_value(sample):
    """ Extract the labels and values of a sample.

    prometheus_client 0.5 changed the sample type to a named tuple with more
    members than the plain tuple had in 0.4 and earlier. This function can
    extract the labels and value from the sample for both sample types.

    Args:
        sample: The sample to get the labels and value from.
    Returns:
        A tuple of (labels, value) from the sample.
    """

    # If the sample has a labels and value attribute, use those.
    if hasattr(sample, "labels") and hasattr(sample, "value"):
        return sample.labels, sample.value
    # Otherwise fall back to treating it as a plain 3 tuple.
    else:
        _, labels, value = sample
        return labels, value


class TestMauLimit(unittest.TestCase):
    def test_basic(self):
        gauge = InFlightGauge(
            "test1", "", labels=["test_label"], sub_metrics=["foo", "bar"]
        )

        def handle1(metrics):
            metrics.foo += 2
            metrics.bar = max(metrics.bar, 5)

        def handle2(metrics):
            metrics.foo += 3
            metrics.bar = max(metrics.bar, 7)

        gauge.register(("key1",), handle1)

        self.assert_dict(
            {
                "test1_total": {("key1",): 1},
                "test1_foo": {("key1",): 2},
                "test1_bar": {("key1",): 5},
            },
            self.get_metrics_from_gauge(gauge),
        )

        gauge.unregister(("key1",), handle1)

        self.assert_dict(
            {
                "test1_total": {("key1",): 0},
                "test1_foo": {("key1",): 0},
                "test1_bar": {("key1",): 0},
            },
            self.get_metrics_from_gauge(gauge),
        )

        gauge.register(("key1",), handle1)
        gauge.register(("key2",), handle2)

        self.assert_dict(
            {
                "test1_total": {("key1",): 1, ("key2",): 1},
                "test1_foo": {("key1",): 2, ("key2",): 3},
                "test1_bar": {("key1",): 5, ("key2",): 7},
            },
            self.get_metrics_from_gauge(gauge),
        )

        gauge.unregister(("key2",), handle2)
        gauge.register(("key1",), handle2)

        self.assert_dict(
            {
                "test1_total": {("key1",): 2, ("key2",): 0},
                "test1_foo": {("key1",): 5, ("key2",): 0},
                "test1_bar": {("key1",): 7, ("key2",): 0},
            },
            self.get_metrics_from_gauge(gauge),
        )

    def get_metrics_from_gauge(self, gauge):
        results = {}

        for r in gauge.collect():
            results[r.name] = {
                tuple(labels[x] for x in gauge.labels): value
                for labels, value in map(get_sample_labels_value, r.samples)
            }

        return results
