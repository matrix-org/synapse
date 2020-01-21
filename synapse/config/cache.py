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
from collections import defaultdict
from typing import DefaultDict

from ._base import Config, ConfigError

_CACHES = {}
_CACHE_PREFIX = "SYNAPSE_CACHE_FACTOR"
DEFAULT_CACHE_SIZE_FACTOR = float(os.environ.get(_CACHE_PREFIX, 0.5))

_DEFAULT_CONFIG = """\
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


def add_resizable_cache(cache_name, cache_resize_callback):
    _CACHES[cache_name.lower()] = cache_resize_callback
    cache_resize_callback(DEFAULT_CACHE_SIZE_FACTOR)


class CacheConfig(Config):
    section = "caches"
    _environ = os.environ

    def read_config(self, config, **kwargs):
        self.event_cache_size = self.parse_size(config.get("event_cache_size", "10K"))

        global DEFAULT_CACHE_SIZE_FACTOR

        cache_config = config.get("caches", {})

        self.global_factor = cache_config.get(
            "global_factor", DEFAULT_CACHE_SIZE_FACTOR
        )
        if not isinstance(self.global_factor, (int, float)):
            raise ConfigError("caches.global_factor must be a number.")

        # Set the global one so that it's reflected in new caches
        DEFAULT_CACHE_SIZE_FACTOR = self.global_factor

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

        self.cache_factors = defaultdict(
            lambda: self.global_factor
        )  # type: DefaultDict[str, float]

        for cache, factor in individual_factors.items():
            if not isinstance(factor, (int, float)):
                raise ConfigError(
                    "caches.per_cache_factors.%s must be a number" % (cache.lower(),)
                )
            self.cache_factors[cache.lower()] = factor
