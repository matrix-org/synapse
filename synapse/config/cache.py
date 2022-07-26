# Copyright 2019-2021 Matrix.org Foundation C.I.C.
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
import re
import threading
from typing import Any, Callable, Dict, Optional

import attr

from synapse.types import JsonDict
from synapse.util.check_dependencies import check_requirements

from ._base import Config, ConfigError

logger = logging.getLogger(__name__)

# The prefix for all cache factor-related environment variables
_CACHE_PREFIX = "SYNAPSE_CACHE_FACTOR"

# Map from canonicalised cache name to cache.
_CACHES: Dict[str, Callable[[float], None]] = {}

# a lock on the contents of _CACHES
_CACHES_LOCK = threading.Lock()

_DEFAULT_FACTOR_SIZE = 0.5
_DEFAULT_EVENT_CACHE_SIZE = "10K"


@attr.s(slots=True, auto_attribs=True)
class CacheProperties:
    # The default factor size for all caches
    default_factor_size: float = float(
        os.environ.get(_CACHE_PREFIX, _DEFAULT_FACTOR_SIZE)
    )
    resize_all_caches_func: Optional[Callable[[], None]] = None


properties = CacheProperties()


def _canonicalise_cache_name(cache_name: str) -> str:
    """Gets the canonical form of the cache name.

    Since we specify cache names in config and environment variables we need to
    ignore case and special characters. For example, some caches have asterisks
    in their name to denote that they're not attached to a particular database
    function, and these asterisks need to be stripped out
    """

    cache_name = re.sub(r"[^A-Za-z_1-9]", "", cache_name)

    return cache_name.lower()


def add_resizable_cache(
    cache_name: str, cache_resize_callback: Callable[[float], None]
) -> None:
    """Register a cache whose size can dynamically change

    Args:
        cache_name: A reference to the cache
        cache_resize_callback: A callback function that will run whenever
            the cache needs to be resized
    """
    # Some caches have '*' in them which we strip out.
    cache_name = _canonicalise_cache_name(cache_name)

    # sometimes caches are initialised from background threads, so we need to make
    # sure we don't conflict with another thread running a resize operation
    with _CACHES_LOCK:
        _CACHES[cache_name] = cache_resize_callback

    # Ensure all loaded caches are sized appropriately
    #
    # This method should only run once the config has been read,
    # as it uses values read from it
    if properties.resize_all_caches_func:
        properties.resize_all_caches_func()


class CacheConfig(Config):
    section = "caches"
    _environ = os.environ

    event_cache_size: int
    cache_factors: Dict[str, float]
    global_factor: float
    track_memory_usage: bool
    expiry_time_msec: Optional[int]
    sync_response_cache_duration: int

    @staticmethod
    def reset() -> None:
        """Resets the caches to their defaults. Used for tests."""
        properties.default_factor_size = float(
            os.environ.get(_CACHE_PREFIX, _DEFAULT_FACTOR_SIZE)
        )
        properties.resize_all_caches_func = None
        with _CACHES_LOCK:
            _CACHES.clear()

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        """Populate this config object with values from `config`.

        This method does NOT resize existing or future caches: use `resize_all_caches`.
        We use two separate methods so that we can reject bad config before applying it.
        """
        self.event_cache_size = self.parse_size(
            config.get("event_cache_size", _DEFAULT_EVENT_CACHE_SIZE)
        )
        self.cache_factors = {}

        cache_config = config.get("caches") or {}
        self.global_factor = cache_config.get("global_factor", _DEFAULT_FACTOR_SIZE)
        if not isinstance(self.global_factor, (int, float)):
            raise ConfigError("caches.global_factor must be a number.")

        # Load cache factors from the config
        individual_factors = cache_config.get("per_cache_factors") or {}
        if not isinstance(individual_factors, dict):
            raise ConfigError("caches.per_cache_factors must be a dictionary")

        # Canonicalise the cache names *before* updating with the environment
        # variables.
        individual_factors = {
            _canonicalise_cache_name(key): val
            for key, val in individual_factors.items()
        }

        # Override factors from environment if necessary
        individual_factors.update(
            {
                _canonicalise_cache_name(key[len(_CACHE_PREFIX) + 1 :]): float(val)
                for key, val in self._environ.items()
                if key.startswith(_CACHE_PREFIX + "_")
            }
        )

        for cache, factor in individual_factors.items():
            if not isinstance(factor, (int, float)):
                raise ConfigError(
                    "caches.per_cache_factors.%s must be a number" % (cache,)
                )
            self.cache_factors[cache] = factor

        self.track_memory_usage = cache_config.get("track_memory_usage", False)
        if self.track_memory_usage:
            check_requirements("cache_memory")

        expire_caches = cache_config.get("expire_caches", True)
        cache_entry_ttl = cache_config.get("cache_entry_ttl", "30m")

        if expire_caches:
            self.expiry_time_msec = self.parse_duration(cache_entry_ttl)
        else:
            self.expiry_time_msec = None

        # Backwards compatibility support for the now-removed "expiry_time" config flag.
        expiry_time = cache_config.get("expiry_time")

        if expiry_time and expire_caches:
            logger.warning(
                "You have set two incompatible options, expiry_time and expire_caches. Please only use the "
                "expire_caches and cache_entry_ttl options and delete the expiry_time option as it is "
                "deprecated."
            )
        if expiry_time:
            logger.warning(
                "Expiry_time is a deprecated option, please use the expire_caches and cache_entry_ttl options "
                "instead."
            )
            self.expiry_time_msec = self.parse_duration(expiry_time)

        self.cache_autotuning = cache_config.get("cache_autotuning")
        if self.cache_autotuning:
            max_memory_usage = self.cache_autotuning.get("max_cache_memory_usage")
            self.cache_autotuning["max_cache_memory_usage"] = self.parse_size(
                max_memory_usage
            )

            target_mem_size = self.cache_autotuning.get("target_cache_memory_usage")
            self.cache_autotuning["target_cache_memory_usage"] = self.parse_size(
                target_mem_size
            )

            min_cache_ttl = self.cache_autotuning.get("min_cache_ttl")
            self.cache_autotuning["min_cache_ttl"] = self.parse_duration(min_cache_ttl)

        self.sync_response_cache_duration = self.parse_duration(
            cache_config.get("sync_response_cache_duration", "2m")
        )

    def resize_all_caches(self) -> None:
        """Ensure all cache sizes are up-to-date.

        For each cache, run the mapped callback function with either
        a specific cache factor or the default, global one.
        """
        # Set the global factor size, so that new caches are appropriately sized.
        properties.default_factor_size = self.global_factor

        # Store this function so that it can be called from other classes without
        # needing an instance of CacheConfig
        properties.resize_all_caches_func = self.resize_all_caches

        # block other threads from modifying _CACHES while we iterate it.
        with _CACHES_LOCK:
            for cache_name, callback in _CACHES.items():
                new_factor = self.cache_factors.get(cache_name, self.global_factor)
                callback(new_factor)
