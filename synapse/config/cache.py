# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation C.I.C.
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

import os
import re
import threading
from typing import Callable, Dict

from ._base import Config, ConfigError

# The prefix for all cache factor-related environment variables
_CACHE_PREFIX = "SYNAPSE_CACHE_FACTOR"

# Map from canonicalised cache name to cache.
_CACHES = {}  # type: Dict[str, Callable[[float], None]]

# a lock on the contents of _CACHES
_CACHES_LOCK = threading.Lock()

_DEFAULT_FACTOR_SIZE = 0.5
_DEFAULT_EVENT_CACHE_SIZE = "10K"


class CacheProperties:
    def __init__(self):
        # The default factor size for all caches
        self.default_factor_size = float(
            os.environ.get(_CACHE_PREFIX, _DEFAULT_FACTOR_SIZE)
        )
        self.resize_all_caches_func = None


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
):
    """Register a cache that's size can dynamically change

    Args:
        cache_name: A reference to the cache
        cache_resize_callback: A callback function that will be ran whenever
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

    @staticmethod
    def reset():
        """Resets the caches to their defaults. Used for tests."""
        properties.default_factor_size = float(
            os.environ.get(_CACHE_PREFIX, _DEFAULT_FACTOR_SIZE)
        )
        properties.resize_all_caches_func = None
        with _CACHES_LOCK:
            _CACHES.clear()

    def generate_config_section(self, **kwargs):
        return """\
        ## Caching ##

        # Caching can be configured through the following options.
        #
        # A cache 'factor' is a multiplier that can be applied to each of
        # Synapse's caches in order to increase or decrease the maximum
        # number of entries that can be stored.

        # The number of events to cache in memory. Not affected by
        # caches.global_factor.
        #
        #event_cache_size: 10K

        caches:
           # Controls the global cache factor, which is the default cache factor
           # for all caches if a specific factor for that cache is not otherwise
           # set.
           #
           # This can also be set by the "SYNAPSE_CACHE_FACTOR" environment
           # variable. Setting by environment variable takes priority over
           # setting through the config file.
           #
           # Defaults to 0.5, which will half the size of all caches.
           #
           #global_factor: 1.0

           # A dictionary of cache name to cache factor for that individual
           # cache. Overrides the global cache factor for a given cache.
           #
           # These can also be set through environment variables comprised
           # of "SYNAPSE_CACHE_FACTOR_" + the name of the cache in capital
           # letters and underscores. Setting by environment variable
           # takes priority over setting through the config file.
           # Ex. SYNAPSE_CACHE_FACTOR_GET_USERS_WHO_SHARE_ROOM_WITH_USER=2.0
           #
           # Some caches have '*' and other characters that are not
           # alphanumeric or underscores. These caches can be named with or
           # without the special characters stripped. For example, to specify
           # the cache factor for `*stateGroupCache*` via an environment
           # variable would be `SYNAPSE_CACHE_FACTOR_STATEGROUPCACHE=2.0`.
           #
           per_cache_factors:
             #get_users_who_share_room_with_user: 2.0
        """

    def read_config(self, config, **kwargs):
        self.event_cache_size = self.parse_size(
            config.get("event_cache_size", _DEFAULT_EVENT_CACHE_SIZE)
        )
        self.cache_factors = {}  # type: Dict[str, float]

        cache_config = config.get("caches") or {}
        self.global_factor = cache_config.get(
            "global_factor", properties.default_factor_size
        )
        if not isinstance(self.global_factor, (int, float)):
            raise ConfigError("caches.global_factor must be a number.")

        # Set the global one so that it's reflected in new caches
        properties.default_factor_size = self.global_factor

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

        # Resize all caches (if necessary) with the new factors we've loaded
        self.resize_all_caches()

        # Store this function so that it can be called from other classes without
        # needing an instance of Config
        properties.resize_all_caches_func = self.resize_all_caches

    def resize_all_caches(self):
        """Ensure all cache sizes are up to date

        For each cache, run the mapped callback function with either
        a specific cache factor or the default, global one.
        """
        # block other threads from modifying _CACHES while we iterate it.
        with _CACHES_LOCK:
            for cache_name, callback in _CACHES.items():
                new_factor = self.cache_factors.get(cache_name, self.global_factor)
                callback(new_factor)
