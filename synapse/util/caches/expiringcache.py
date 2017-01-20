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

from synapse.util.caches import register_cache

from collections import OrderedDict
import logging


logger = logging.getLogger(__name__)


class ExpiringCache(object):
    def __init__(self, cache_name, clock, max_len=0, expiry_ms=0,
                 reset_expiry_on_get=False, iterable=False):
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
            iterable (bool): If true, the size is calculated by summing the
                sizes of all entries, rather than the number of entries.

        """
        self._cache_name = cache_name

        self._clock = clock

        self._max_len = max_len
        self._expiry_ms = expiry_ms

        self._reset_expiry_on_get = reset_expiry_on_get

        self._cache = OrderedDict()

        self.metrics = register_cache(cache_name, self)

        self.iterable = iterable

        self._size_estimate = 0

    def start(self):
        if not self._expiry_ms:
            # Don't bother starting the loop if things never expire
            return

        def f():
            self._prune_cache()

        self._clock.looping_call(f, self._expiry_ms / 2)

    def __setitem__(self, key, value):
        now = self._clock.time_msec()
        self._cache[key] = _CacheEntry(now, value)

        if self.iterable:
            self._size_estimate += len(value)

        # Evict if there are now too many items
        while self._max_len and len(self) > self._max_len:
            _key, value = self._cache.popitem(last=False)
            if self.iterable:
                self._size_estimate -= len(value.value)

    def __getitem__(self, key):
        try:
            entry = self._cache[key]
            self.metrics.inc_hits()
        except KeyError:
            self.metrics.inc_misses()
            raise

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
        begin_length = len(self)

        now = self._clock.time_msec()

        keys_to_delete = set()

        for key, cache_entry in self._cache.items():
            if now - cache_entry.time > self._expiry_ms:
                keys_to_delete.add(key)

        for k in keys_to_delete:
            value = self._cache.pop(k)
            if self.iterable:
                self._size_estimate -= len(value.value)

        logger.debug(
            "[%s] _prune_cache before: %d, after len: %d",
            self._cache_name, begin_length, len(self)
        )

    def __len__(self):
        if self.iterable:
            return self._size_estimate
        else:
            return len(self._cache)


class _CacheEntry(object):
    def __init__(self, time, value):
        self.time = time
        self.value = value
