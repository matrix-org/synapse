# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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


logger = logging.getLogger(__name__)


class ExpiringCache(object):
    def __init__(self, cache_name, clock, max_len=0, expiry_ms=0,
                 reset_expiry_on_get=False):
        """
        Args:
            cache_name (str): Name of this cache, used for logging.
            clock (Clock)
            max_len (int): Max size of dict. If the dict grows larger than this
                then the oldest items get automatically evicted. Default is 0,
                which indicates there is no max limit.
            expiry_ms (int): How long before an item is evicted from the cache
                in milliseconds. Default is 0, indicating items never get
                evicted based on time.
            reset_expiry_on_get (bool): If true, will reset the expiry time for
                an item on access. Defaults to False.

        """
        self._cache_name = cache_name

        self._clock = clock

        self._max_len = max_len
        self._expiry_ms = expiry_ms

        self._reset_expiry_on_get = reset_expiry_on_get

        self._cache = {}

    def start(self):
        if not self._expiry_ms:
            # Don't bother starting the loop if things never expire
            return

        def f():
            self._prune_cache()

        self._clock.looping_call(f, self._expiry_ms/2)

    def __setitem__(self, key, value):
        now = self._clock.time_msec()
        self._cache[key] = _CacheEntry(now, value)

        # Evict if there are now too many items
        if self._max_len and len(self._cache.keys()) > self._max_len:
            sorted_entries = sorted(
                self._cache.items(),
                key=lambda k, v: v.time,
            )

            for k, _ in sorted_entries[self._max_len:]:
                self._cache.pop(k)

    def __getitem__(self, key):
        entry = self._cache[key]

        if self._reset_expiry_on_get:
            entry.time = self._clock.time_msec()

        return entry.value

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def _prune_cache(self):
        if not self._expiry_ms:
            # zero expiry time means don't expire. This should never get called
            # since we have this check in start too.
            return
        begin_length = len(self._cache)

        now = self._clock.time_msec()

        keys_to_delete = set()

        for key, cache_entry in self._cache.items():
            if now - cache_entry.time > self._expiry_ms:
                keys_to_delete.add(key)

        for k in keys_to_delete:
            self._cache.pop(k)

        logger.debug(
            "[%s] _prune_cache before: %d, after len: %d",
            self._cache_name, begin_length, len(self._cache.keys())
        )


class _CacheEntry(object):
    def __init__(self, time, value):
        self.time = time
        self.value = value
