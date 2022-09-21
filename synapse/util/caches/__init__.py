# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019, 2020 The Matrix.org Foundation C.I.C.
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
import collections
import logging
import typing
from enum import Enum, auto
from sys import intern
from typing import Any, Callable, Dict, List, Optional, Sized, TypeVar

import attr
from prometheus_client import REGISTRY
from prometheus_client.core import Gauge

from synapse.config.cache import add_resizable_cache
from synapse.util.metrics import DynamicCollectorRegistry

logger = logging.getLogger(__name__)


# Whether to track estimated memory usage of the LruCaches.
TRACK_MEMORY_USAGE = False

# We track cache metrics in a special registry that lets us update the metrics
# just before they are returned from the scrape endpoint.
CACHE_METRIC_REGISTRY = DynamicCollectorRegistry()

caches_by_name: Dict[str, Sized] = {}

cache_size = Gauge(
    "synapse_util_caches_cache_size", "", ["name"], registry=CACHE_METRIC_REGISTRY
)
cache_hits = Gauge(
    "synapse_util_caches_cache_hits", "", ["name"], registry=CACHE_METRIC_REGISTRY
)
cache_evicted = Gauge(
    "synapse_util_caches_cache_evicted_size",
    "",
    ["name", "reason"],
    registry=CACHE_METRIC_REGISTRY,
)
cache_total = Gauge(
    "synapse_util_caches_cache", "", ["name"], registry=CACHE_METRIC_REGISTRY
)
cache_max_size = Gauge(
    "synapse_util_caches_cache_max_size", "", ["name"], registry=CACHE_METRIC_REGISTRY
)
cache_memory_usage = Gauge(
    "synapse_util_caches_cache_size_bytes",
    "Estimated memory usage of the caches",
    ["name"],
    registry=CACHE_METRIC_REGISTRY,
)

response_cache_size = Gauge(
    "synapse_util_caches_response_cache_size",
    "",
    ["name"],
    registry=CACHE_METRIC_REGISTRY,
)
response_cache_hits = Gauge(
    "synapse_util_caches_response_cache_hits",
    "",
    ["name"],
    registry=CACHE_METRIC_REGISTRY,
)
response_cache_evicted = Gauge(
    "synapse_util_caches_response_cache_evicted_size",
    "",
    ["name", "reason"],
    registry=CACHE_METRIC_REGISTRY,
)
response_cache_total = Gauge(
    "synapse_util_caches_response_cache", "", ["name"], registry=CACHE_METRIC_REGISTRY
)


# Register our custom cache metrics registry with the global registry
REGISTRY.register(CACHE_METRIC_REGISTRY)


class EvictionReason(Enum):
    size = auto()
    time = auto()
    invalidation = auto()


@attr.s(slots=True, auto_attribs=True)
class CacheMetric:

    _cache: Sized
    _cache_type: str
    _cache_name: str
    _collect_callback: Optional[Callable]

    hits: int = 0
    misses: int = 0
    eviction_size_by_reason: typing.Counter[EvictionReason] = attr.ib(
        factory=collections.Counter
    )
    memory_usage: Optional[int] = None

    def inc_hits(self) -> None:
        self.hits += 1

    def inc_misses(self) -> None:
        self.misses += 1

    def inc_evictions(self, reason: EvictionReason, size: int = 1) -> None:
        self.eviction_size_by_reason[reason] += size

    def inc_memory_usage(self, memory: int) -> None:
        if self.memory_usage is None:
            self.memory_usage = 0

        self.memory_usage += memory

    def dec_memory_usage(self, memory: int) -> None:
        assert self.memory_usage is not None
        self.memory_usage -= memory

    def clear_memory_usage(self) -> None:
        if self.memory_usage is not None:
            self.memory_usage = 0

    def describe(self) -> List[str]:
        return []

    def collect(self) -> None:
        try:
            if self._cache_type == "response_cache":
                response_cache_size.labels(self._cache_name).set(len(self._cache))
                response_cache_hits.labels(self._cache_name).set(self.hits)
                for reason in EvictionReason:
                    response_cache_evicted.labels(self._cache_name, reason.name).set(
                        self.eviction_size_by_reason[reason]
                    )
                response_cache_total.labels(self._cache_name).set(
                    self.hits + self.misses
                )
            else:
                cache_size.labels(self._cache_name).set(len(self._cache))
                cache_hits.labels(self._cache_name).set(self.hits)
                for reason in EvictionReason:
                    cache_evicted.labels(self._cache_name, reason.name).set(
                        self.eviction_size_by_reason[reason]
                    )
                cache_total.labels(self._cache_name).set(self.hits + self.misses)
                max_size = getattr(self._cache, "max_size", None)
                if max_size:
                    cache_max_size.labels(self._cache_name).set(max_size)

                if TRACK_MEMORY_USAGE:
                    # self.memory_usage can be None if nothing has been inserted
                    # into the cache yet.
                    cache_memory_usage.labels(self._cache_name).set(
                        self.memory_usage or 0
                    )
            if self._collect_callback:
                self._collect_callback()
        except Exception as e:
            logger.warning("Error calculating metrics for %s: %s", self._cache_name, e)
            raise


def register_cache(
    cache_type: str,
    cache_name: str,
    cache: Sized,
    collect_callback: Optional[Callable] = None,
    resizable: bool = True,
    resize_callback: Optional[Callable] = None,
) -> CacheMetric:
    """Register a cache object for metric collection and resizing.

    Args:
        cache_type: a string indicating the "type" of the cache. This is used
            only for deduplication so isn't too important provided it's constant.
        cache_name: name of the cache
        cache: cache itself, which must implement __len__(), and may optionally implement
             a max_size property
        collect_callback: If given, a function which is called during metric
            collection to update additional metrics.
        resizable: Whether this cache supports being resized, in which case either
            resize_callback must be provided, or the cache must support set_max_size().
        resize_callback: A function which can be called to resize the cache.

    Returns:
        CacheMetric: an object which provides inc_{hits,misses,evictions} methods
    """
    if resizable:
        if not resize_callback:
            resize_callback = cache.set_cache_factor  # type: ignore
        add_resizable_cache(cache_name, resize_callback)

    metric = CacheMetric(cache, cache_type, cache_name, collect_callback)
    metric_name = "cache_%s_%s" % (cache_type, cache_name)
    caches_by_name[cache_name] = cache
    CACHE_METRIC_REGISTRY.register_hook(metric_name, metric.collect)
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

T = TypeVar("T", Optional[str], str)


def intern_string(string: T) -> T:
    """Takes a (potentially) unicode string and interns it if it's ascii"""
    if string is None:
        return None

    try:
        return intern(string)
    except UnicodeEncodeError:
        return string


def intern_dict(dictionary: Dict[str, Any]) -> Dict[str, Any]:
    """Takes a dictionary and interns well known keys and their values"""
    return {
        KNOWN_KEYS.get(key, key): _intern_known_values(key, value)
        for key, value in dictionary.items()
    }


def _intern_known_values(key: str, value: Any) -> Any:
    intern_keys = ("event_id", "room_id", "sender", "user_id", "type", "state_key")

    if key in intern_keys:
        return intern_string(value)

    return value
