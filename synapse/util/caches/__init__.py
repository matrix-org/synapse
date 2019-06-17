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

import logging
import os

import six
from six.moves import intern

from prometheus_client.core import REGISTRY, Gauge, GaugeMetricFamily

logger = logging.getLogger(__name__)

CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.5))


def get_cache_factor_for(cache_name):
    env_var = "SYNAPSE_CACHE_FACTOR_" + cache_name.upper()
    factor = os.environ.get(env_var)
    if factor:
        return float(factor)

    return CACHE_SIZE_FACTOR


caches_by_name = {}
collectors_by_name = {}

cache_size = Gauge("synapse_util_caches_cache:size", "", ["name"])
cache_hits = Gauge("synapse_util_caches_cache:hits", "", ["name"])
cache_evicted = Gauge("synapse_util_caches_cache:evicted_size", "", ["name"])
cache_total = Gauge("synapse_util_caches_cache:total", "", ["name"])

response_cache_size = Gauge("synapse_util_caches_response_cache:size", "", ["name"])
response_cache_hits = Gauge("synapse_util_caches_response_cache:hits", "", ["name"])
response_cache_evicted = Gauge(
    "synapse_util_caches_response_cache:evicted_size", "", ["name"]
)
response_cache_total = Gauge("synapse_util_caches_response_cache:total", "", ["name"])


def register_cache(cache_type, cache_name, cache):

    # Check if the metric is already registered. Unregister it, if so.
    # This usually happens during tests, as at runtime these caches are
    # effectively singletons.
    metric_name = "cache_%s_%s" % (cache_type, cache_name)
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

        def describe(self):
            return []

        def collect(self):
            try:
                if cache_type == "response_cache":
                    response_cache_size.labels(cache_name).set(len(cache))
                    response_cache_hits.labels(cache_name).set(self.hits)
                    response_cache_evicted.labels(cache_name).set(self.evicted_size)
                    response_cache_total.labels(cache_name).set(self.hits + self.misses)
                else:
                    cache_size.labels(cache_name).set(len(cache))
                    cache_hits.labels(cache_name).set(self.hits)
                    cache_evicted.labels(cache_name).set(self.evicted_size)
                    cache_total.labels(cache_name).set(self.hits + self.misses)
            except Exception as e:
                logger.warn("Error calculating metrics for %s: %s", cache_name, e)
                raise

            yield GaugeMetricFamily("__unused", "")

    metric = CacheMetric()
    REGISTRY.register(metric)
    caches_by_name[cache_name] = cache
    collectors_by_name[metric_name] = metric
    return metric


KNOWN_KEYS = {
    key: key
    for key in (
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
        if six.PY2:
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
    intern_keys = ("event_id", "room_id", "sender", "user_id", "type", "state_key")

    if key in intern_keys:
        return intern_string(value)

    return value
