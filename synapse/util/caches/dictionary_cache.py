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
import enum
import logging
import threading
from typing import Any, Dict, Generic, Iterable, Optional, Set, TypeVar

import attr

from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)


# The type of the cache keys.
KT = TypeVar("KT")
# The type of the dictionary keys.
DKT = TypeVar("DKT")


@attr.s(slots=True)
class DictionaryEntry:
    """Returned when getting an entry from the cache

    Attributes:
        full: Whether the cache has the full or dict or just some keys.
            If not full then not all requested keys will necessarily be present
            in `value`
        known_absent: Keys that were looked up in the dict and were not
            there.
        value: The full or partial dict value
    """

    full = attr.ib(type=bool)
    known_absent = attr.ib()
    value = attr.ib()

    def __len__(self):
        return len(self.value)


class _Sentinel(enum.Enum):
    # defining a sentinel in this way allows mypy to correctly handle the
    # type of a dictionary lookup.
    sentinel = object()


class DictionaryCache(Generic[KT, DKT]):
    """Caches key -> dictionary lookups, supporting caching partial dicts, i.e.
    fetching a subset of dictionary keys for a particular key.
    """

    def __init__(self, name: str, max_entries: int = 1000):
        self.cache = LruCache(
            max_size=max_entries, cache_name=name, size_callback=len
        )  # type: LruCache[KT, DictionaryEntry]

        self.name = name
        self.sequence = 0
        self.thread = None  # type: Optional[threading.Thread]

    def check_thread(self) -> None:
        expected_thread = self.thread
        if expected_thread is None:
            self.thread = threading.current_thread()
        else:
            if expected_thread is not threading.current_thread():
                raise ValueError(
                    "Cache objects can only be accessed from the main thread"
                )

    def get(
        self, key: KT, dict_keys: Optional[Iterable[DKT]] = None
    ) -> DictionaryEntry:
        """Fetch an entry out of the cache

        Args:
            key
            dict_key: If given a set of keys then return only those keys
                that exist in the cache.

        Returns:
            DictionaryEntry
        """
        entry = self.cache.get(key, _Sentinel.sentinel)
        if entry is not _Sentinel.sentinel:
            if dict_keys is None:
                return DictionaryEntry(
                    entry.full, entry.known_absent, dict(entry.value)
                )
            else:
                return DictionaryEntry(
                    entry.full,
                    entry.known_absent,
                    {k: entry.value[k] for k in dict_keys if k in entry.value},
                )

        return DictionaryEntry(False, set(), {})

    def invalidate(self, key: KT) -> None:
        self.check_thread()

        # Increment the sequence number so that any SELECT statements that
        # raced with the INSERT don't update the cache (SYN-369)
        self.sequence += 1
        self.cache.pop(key, None)

    def invalidate_all(self) -> None:
        self.check_thread()
        self.sequence += 1
        self.cache.clear()

    def update(
        self,
        sequence: int,
        key: KT,
        value: Dict[DKT, Any],
        fetched_keys: Optional[Set[DKT]] = None,
    ) -> None:
        """Updates the entry in the cache

        Args:
            sequence
            key
            value: The value to update the cache with.
            fetched_keys: All of the dictionary keys which were
                fetched from the database.

                If None, this is the complete value for key K. Otherwise, it
                is used to infer a list of keys which we know don't exist in
                the full dict.
        """
        self.check_thread()
        if self.sequence == sequence:
            # Only update the cache if the caches sequence number matches the
            # number that the cache had before the SELECT was started (SYN-369)
            if fetched_keys is None:
                self._insert(key, value, set())
            else:
                self._update_or_insert(key, value, fetched_keys)

    def _update_or_insert(
        self, key: KT, value: Dict[DKT, Any], known_absent: Set[DKT]
    ) -> None:
        # We pop and reinsert as we need to tell the cache the size may have
        # changed

        entry = self.cache.pop(key, DictionaryEntry(False, set(), {}))
        entry.value.update(value)
        entry.known_absent.update(known_absent)
        self.cache[key] = entry

    def _insert(self, key: KT, value: Dict[DKT, Any], known_absent: Set[DKT]) -> None:
        self.cache[key] = DictionaryEntry(True, known_absent, value)
