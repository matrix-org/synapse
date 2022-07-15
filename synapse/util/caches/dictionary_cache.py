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
from typing import Any, Dict, Generic, Iterable, Optional, Set, Tuple, TypeVar, Union

import attr
from typing_extensions import Literal

from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.treecache import TreeCache, iterate_tree_cache_items

logger = logging.getLogger(__name__)


# The type of the cache keys.
KT = TypeVar("KT")
# The type of the dictionary keys.
DKT = TypeVar("DKT")
# The type of the dictionary values.
DV = TypeVar("DV")


# This class can't be generic because it uses slots with attrs.
# See: https://github.com/python-attrs/attrs/issues/313
@attr.s(slots=True, auto_attribs=True)
class DictionaryEntry:  # should be: Generic[DKT, DV].
    """Returned when getting an entry from the cache

    Attributes:
        full: Whether the cache has the full or dict or just some keys.
            If not full then not all requested keys will necessarily be present
            in `value`
        known_absent: Keys that were looked up in the dict and were not there.
        value: The full or partial dict value
    """

    full: bool
    known_absent: Set[Any]  # should be: Set[DKT]
    value: Dict[Any, Any]  # should be: Dict[DKT, DV]

    def __len__(self) -> int:
        return len(self.value)


class _FullCacheKey(enum.Enum):
    KEY = object()


class _Sentinel(enum.Enum):
    # defining a sentinel in this way allows mypy to correctly handle the
    # type of a dictionary lookup.
    sentinel = object()


class _PerKeyValue(Generic[DV]):
    __slots__ = ["value"]

    def __init__(self, value: Union[DV, Literal[_Sentinel.sentinel]]) -> None:
        self.value = value

    def __len__(self) -> int:
        return 1


class DictionaryCache(Generic[KT, DKT, DV]):
    """Caches key -> dictionary lookups, supporting caching partial dicts, i.e.
    fetching a subset of dictionary keys for a particular key.
    """

    def __init__(self, name: str, max_entries: int = 1000):
        self.cache: LruCache[
            Tuple[KT, Union[DKT, Literal[_FullCacheKey.KEY]]],
            Union[_PerKeyValue, Dict[DKT, DV]],
        ] = LruCache(
            max_size=max_entries,
            cache_name=name,
            cache_type=TreeCache,
            size_callback=len,
        )

        self.name = name
        self.sequence = 0
        self.thread: Optional[threading.Thread] = None

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
            dict_keys: If given a set of keys then return only those keys
                that exist in the cache.

        Returns:
            DictionaryEntry
        """

        if dict_keys is None:
            entry = self.cache.get((key, _FullCacheKey.KEY), _Sentinel.sentinel)
            if entry is not _Sentinel.sentinel:
                assert isinstance(entry, dict)
                return DictionaryEntry(True, set(), entry)

            all_entries = self.cache.get_multi(
                (key,),
                _Sentinel.sentinel,
            )
            if all_entries is _Sentinel.sentinel:
                return DictionaryEntry(False, set(), {})

            values = {}
            known_absent = set()
            for dict_key, dict_value in iterate_tree_cache_items((), all_entries):
                dict_key = dict_key[0]
                dict_value = dict_value.value

                assert isinstance(dict_value, _PerKeyValue)
                if dict_value.value is _Sentinel.sentinel:
                    known_absent.add(dict_key)
                else:
                    values[dict_key] = dict_value.value

            return DictionaryEntry(False, known_absent, values)

        values = {}
        known_absent = set()
        missing = set()
        for dict_key in dict_keys:
            entry = self.cache.get((key, dict_key), _Sentinel.sentinel)
            if entry is _Sentinel.sentinel:
                missing.add(dict_key)
                continue

            assert isinstance(entry, _PerKeyValue)

            if entry.value is _Sentinel.sentinel:
                known_absent.add(entry.value)
            else:
                values[dict_key] = entry.value

        if not missing:
            return DictionaryEntry(False, known_absent, values)

        entry = self.cache.get(
            (key, _FullCacheKey.KEY),
            _Sentinel.sentinel,
            update_last_access=False,
        )
        if entry is _Sentinel.sentinel:
            return DictionaryEntry(False, known_absent, values)

        assert isinstance(entry, dict)

        values = {}
        for dict_key in dict_keys:
            value = entry.get(dict_key, _Sentinel.sentinel)  # type: ignore[arg-type]
            self.cache[(key, dict_key)] = _PerKeyValue(value)

            if value is not _Sentinel.sentinel:
                values[dict_key] = value

        return DictionaryEntry(True, set(), values)

    def invalidate(self, key: KT) -> None:
        self.check_thread()

        # Increment the sequence number so that any SELECT statements that
        # raced with the INSERT don't update the cache (SYN-369)
        self.sequence += 1

        # Del-multi accepts truncated tuples.
        self.cache.del_multi((key,))  # type: ignore[arg-type]

    def invalidate_all(self) -> None:
        self.check_thread()
        self.sequence += 1
        self.cache.clear()

    def update(
        self,
        sequence: int,
        key: KT,
        value: Dict[DKT, DV],
        fetched_keys: Optional[Iterable[DKT]] = None,
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
                self._insert(key, value)
            else:
                self._update_or_insert(key, value, fetched_keys)

    def _update_or_insert(
        self, key: KT, value: Dict[DKT, DV], fetched_keys: Iterable[DKT]
    ) -> None:

        for dict_key, dict_value in value.items():
            self.cache[(key, dict_key)] = _PerKeyValue(dict_value)

        for dict_key in fetched_keys:
            if (key, dict_key) in self.cache:
                continue

            self.cache[(key, dict_key)] = _PerKeyValue(_Sentinel.sentinel)

    def _insert(self, key: KT, value: Dict[DKT, DV]) -> None:
        self.cache[(key, _FullCacheKey.KEY)] = value
