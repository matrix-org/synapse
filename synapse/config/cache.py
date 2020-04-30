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
from typing import Callable, Dict

from ._base import Config, ConfigError

# The prefix for all cache factor-related environment variables
_CACHES = {}
_CACHE_PREFIX = "SYNAPSE_CACHE_FACTOR"
_DEFAULT_FACTOR_SIZE = 0.5
_DEFAULT_EVENT_CACHE_SIZE = "10K"


class CacheProperties(object):
    def __init__(self):
        # The default factor size for all caches
        self.default_factor_size = float(
            os.environ.get(_CACHE_PREFIX, _DEFAULT_FACTOR_SIZE)
        )
        self.resize_all_caches_func = None


properties = CacheProperties()


def add_resizable_cache(cache_name: str, cache_resize_callback: Callable):
    """Register a cache that's size can dynamically change

    Args:
        cache_name: A reference to the cache
        cache_resize_callback: A callback function that will be ran whenever
            the cache needs to be resized
    """
    _CACHES[cache_name.lower()] = cache_resize_callback

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
        _CACHES.clear()

    def generate_config_section(self, **kwargs):
        return """\
        # Cache configuration
        #
        # 'global_factor' controls the global cache factor. This overrides the
        # "SYNAPSE_CACHE_FACTOR" environment variable.
        #
        # 'per_cache_factors' is a dictionary of cache name to cache factor for that
        # individual cache.
        #
        #caches:
        #  global_factor: 0.5
        #  per_cache_factors:
        #    get_users_who_share_room_with_user: 2
        #
        """

    def read_config(self, config, **kwargs):
        self.event_cache_size = self.parse_size(
            config.get("event_cache_size", _DEFAULT_EVENT_CACHE_SIZE)
        )
        self.cache_factors = {}  # type: Dict[str, float]

        cache_config = config.get("caches", {})
        self.global_factor = cache_config.get(
            "global_factor", properties.default_factor_size
        )
        if not isinstance(self.global_factor, (int, float)):
            raise ConfigError("caches.global_factor must be a number.")

        # Set the global one so that it's reflected in new caches
        properties.default_factor_size = self.global_factor

        # Load cache factors from the environment, but override them with the
        # ones in the config file if they exist
        individual_factors = {
            key[len(_CACHE_PREFIX) + 1 :].lower(): float(val)
            for key, val in self._environ.items()
            if key.startswith(_CACHE_PREFIX + "_")
        }
        individual_factors_config = cache_config.get("per_cache_factors", {}) or {}
        if not isinstance(individual_factors_config, dict):
            raise ConfigError("caches.per_cache_factors must be a dictionary")
        individual_factors.update(individual_factors_config)

        for cache, factor in individual_factors.items():
            if not isinstance(factor, (int, float)):
                raise ConfigError(
                    "caches.per_cache_factors.%s must be a number" % (cache.lower(),)
                )
            self.cache_factors[cache.lower()] = factor

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
        for cache_name, callback in _CACHES.items():
            new_factor = self.cache_factors.get(cache_name, self.global_factor)
            callback(new_factor)
