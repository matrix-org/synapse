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

from twisted.logger import Logger

from ._base import Config, ConfigError

log = Logger()

_CACHES = {}
DEFAULT_CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.5))


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


class CacheConfig(Config):
    section = "caches"

    def read_config(self, config, **kwargs):
        global DEFAULT_CACHE_SIZE_FACTOR

        cache_config = config.get("caches", {})

        self.global_factor = cache_config.get(
            "global_factor", DEFAULT_CACHE_SIZE_FACTOR
        )
        if not isinstance(self.global_factor, (int, float)):
            raise ConfigError("caches.global_factor must be a number.")

        # Set the global one so that it's reflected in new caches
        DEFAULT_CACHE_SIZE_FACTOR = self.global_factor

        individual_factors = cache_config.get("per_cache_factors", {}) or {}
        if not isinstance(individual_factors, dict):
            raise ConfigError("caches.per_cache_factors must be a dictionary")

        self.cache_factors = defaultdict(
            lambda: self.global_factor
        )  # type: DefaultDict[str, float]

        for cache, factor in individual_factors.items():
            if not isinstance(factor, (int, float)):
                raise ConfigError(
                    "caches.per_cache_factors.%s must be a number" % (cache.lower(),)
                )
            self.cache_factors[cache.lower()] = factor

    def resize_caches(self):
        for cache_name, cache_resize_callback in _CACHES.items():
            cache_factor = self.cache_factors[cache_name]
            log.debug(
                "Setting cache factor for {cache_name} to {new_cache_factor}",
                cache_name=cache_name,
                new_cache_factor=cache_factor,
            )
            changed = cache_resize_callback(cache_factor)
            if changed:
                log.info(
                    "Cache factor for {cache_name} set to {new_cache_factor}",
                    cache_name=cache_name,
                    new_cache_factor=cache_factor,
                )

    def get_factor_for(self, cache_name):
        return self.cache_factors[cache_name.lower()]
