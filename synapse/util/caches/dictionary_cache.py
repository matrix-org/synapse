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

from synapse.util.caches.lrucache import LruCache
from collections import namedtuple
from . import register_cache
import threading
import logging


logger = logging.getLogger(__name__)


class DictionaryEntry(namedtuple("DictionaryEntry", ("full", "value"))):
    def __len__(self):
        return len(self.value)


class DictionaryCache(object):
    """Caches key -> dictionary lookups, supporting caching partial dicts, i.e.
    fetching a subset of dictionary keys for a particular key.
    """

    def __init__(self, name, max_entries=1000):
        self.cache = LruCache(max_size=max_entries, size_callback=len)

        self.name = name
        self.sequence = 0
        self.thread = None
        # caches_by_name[name] = self.cache

        class Sentinel(object):
            __slots__ = []

        self.sentinel = Sentinel()
        self.metrics = register_cache(name, self.cache)

    def check_thread(self):
        expected_thread = self.thread
        if expected_thread is None:
            self.thread = threading.current_thread()
        else:
            if expected_thread is not threading.current_thread():
                raise ValueError(
                    "Cache objects can only be accessed from the main thread"
                )

    def get(self, key, dict_keys=None):
        entry = self.cache.get(key, self.sentinel)
        if entry is not self.sentinel:
            self.metrics.inc_hits()

            if dict_keys is None:
                return DictionaryEntry(entry.full, dict(entry.value))
            else:
                return DictionaryEntry(entry.full, {
                    k: entry.value[k]
                    for k in dict_keys
                    if k in entry.value
                })

        self.metrics.inc_misses()
        return DictionaryEntry(False, {})

    def invalidate(self, key):
        self.check_thread()

        # Increment the sequence number so that any SELECT statements that
        # raced with the INSERT don't update the cache (SYN-369)
        self.sequence += 1
        self.cache.pop(key, None)

    def invalidate_all(self):
        self.check_thread()
        self.sequence += 1
        self.cache.clear()

    def update(self, sequence, key, value, full=False):
        self.check_thread()
        if self.sequence == sequence:
            # Only update the cache if the caches sequence number matches the
            # number that the cache had before the SELECT was started (SYN-369)
            if full:
                self._insert(key, value)
            else:
                self._update_or_insert(key, value)

    def _update_or_insert(self, key, value):
        entry = self.cache.setdefault(key, DictionaryEntry(False, {}))
        entry.value.update(value)

    def _insert(self, key, value):
        self.cache[key] = DictionaryEntry(True, value)
