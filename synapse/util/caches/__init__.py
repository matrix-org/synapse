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

from prometheus_client.core import GaugeMetricFamily, REGISTRY

import os

CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.5))

caches_by_name = {}
collectors_by_name = {}

def register_cache(name, cache_name, cache):

    # Check if the metric is already registered. Unregister it, if so.
    metric_name = "synapse_util_caches_%s:%s" % (name, cache_name,)
    if metric_name in collectors_by_name.keys():
        REGISTRY.unregister(collectors_by_name[metric_name])

    class CacheMetric(object):

        hits = 0
        misses = 0
        evicted_size = 0

        def inc_hits(self):
            self.hits += 1

        def inc_misses(self):
            self.misses += 1

        def inc_evictions(self, size=1):
            self.evicted_size += size

        def collect(self):
            cache_size = len(cache)

            gm = GaugeMetricFamily(metric_name, "", labels=["size", "hits", "misses", "total"])
            gm.add_metric(["size"], cache_size)
            gm.add_metric(["hits"], self.hits)
            gm.add_metric(["misses"], self.misses)
            gm.add_metric(["total"], self.hits + self.misses)
            yield gm

    metric = CacheMetric()
    REGISTRY.register(metric)
    caches_by_name[cache_name] = cache
    collectors_by_name[metric_name] = metric
    return metric

KNOWN_KEYS = {
    key: key for key in
    (
        "auth_events",
        "content",
        "depth",
        "event_id",
        "hashes",
        "origin",
        "origin_server_ts",
        "prev_events",
        "room_id",
        "sender",
        "signatures",
        "state_key",
        "type",
        "unsigned",
        "user_id",
    )
}


def intern_string(string):
    """Takes a (potentially) unicode string and interns it if it's ascii
    """
    if string is None:
        return None

    try:
        string = string.encode("ascii")
        return intern(string)
    except UnicodeEncodeError:
        return string


def intern_dict(dictionary):
    """Takes a dictionary and interns well known keys and their values
    """
    return {
        KNOWN_KEYS.get(key, key): _intern_known_values(key, value)
        for key, value in dictionary.items()
    }


def _intern_known_values(key, value):
    intern_keys = ("event_id", "room_id", "sender", "user_id", "type", "state_key",)

    if key in intern_keys:
        return intern_string(value)

    return value
