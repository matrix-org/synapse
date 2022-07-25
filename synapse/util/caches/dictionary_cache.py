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
from synapse.util.caches.treecache import TreeCache

logger = logging.getLogger(__name__)


# The type of the cache keys.
KT = TypeVar("KT")
# The type of the dictionary keys.
DKT = TypeVar("DKT")
# The type of the dictionary values.
DV = TypeVar("DV")


# This class can't be generic because it uses slots with attrs.
# See: https://github.com/python-attrs/attrs/issues/313
@attr.s(slots=True, frozen=True, auto_attribs=True)
class DictionaryEntry:  # should be: Generic[DKT, DV].
    """Returned when getting an entry from the cache

    If `full` is true then `known_absent` will be the empty set.

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
    """The key we use to cache the full dict."""

    KEY = object()


class _Sentinel(enum.Enum):
    # defining a sentinel in this way allows mypy to correctly handle the
    # type of a dictionary lookup.
    sentinel = object()


class _PerKeyValue(Generic[DV]):
    """The cached value of a dictionary key. If `value` is the sentinel,
    indicates that the requested key is known to *not* be in the full dict.
    """

    __slots__ = ["value"]

    def __init__(self, value: Union[DV, Literal[_Sentinel.sentinel]]) -> None:
        self.value = value

    def __len__(self) -> int:
        # We add a `__len__` implementation as we use this class in a cache
        # where the values are variable length.
        return 1


class DictionaryCache(Generic[KT, DKT, DV]):
    """Caches key -> dictionary lookups, supporting caching partial dicts, i.e.
    fetching a subset of dictionary keys for a particular key.

    This cache has two levels of key. First there is the "cache key" (of type
    `KT`), which maps to a dict. The keys to that dict are the "dict key" (of
    type `DKT`). The overall structure is therefore `KT->DKT->DV`. For
    example, it might look like:

       {
           1: { 1: "a", 2: "b" },
           2: { 1: "c" },
       }

    It is possible to look up either individual dict keys, or the *complete*
    dict for a given cache key.

    Each dict item, and the complete dict is treated as a separate LRU
    entry for the purpose of cache expiry. For example, given:
        dict_cache.get(1, None)  -> DictionaryEntry({1: "a", 2: "b"})
        dict_cache.get(1, [1])  -> DictionaryEntry({1: "a"})
        dict_cache.get(1, [2])  -> DictionaryEntry({2: "b"})

    ... then the cache entry for the complete dict will expire first,
    followed by the cache entry for the '1' dict key, and finally that
    for the '2' dict key.
    """

    def __init__(self, name: str, max_entries: int = 1000):
        # We use a single LruCache to store two different types of entries:
        #   1. Map from (key, dict_key) -> dict value (or sentinel, indicating
        #      the key doesn't exist in the dict); and
        #   2. Map from (key, _FullCacheKey.KEY) -> full dict.
        #
        # The former is used when explicit keys of the dictionary are looked up,
        # and the latter when the full dictionary is requested.
        #
        # If when explicit keys are requested and not in the cache, we then look
        # to see if we have the full dict and use that if we do. If found in the
        # full dict each key is added into the cache.
        #
        # This set up allows the `LruCache` to prune the full dict entries if
        # they haven't been used in a while, even when there have been recent
        # queries for subsets of the dict.
        #
        # Typing:
        #     * A key of `(KT, DKT)` has a value of `_PerKeyValue`
        #     * A key of `(KT, _FullCacheKey.KEY)` has a value of `Dict[DKT, DV]`
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
                that exist in the cache. If None then returns the full dict
                if it is in the cache.

        Returns:
            DictionaryEntry: If `dict_keys` is not None then `DictionaryEntry`
            will contain include the keys that are in the cache. If None then
            will either return the full dict if in the cache, or the empty
            dict (with `full` set to False) if it isn't.
        """
        if dict_keys is None:
            # The caller wants the full set of dictionary keys for this cache key
            return self._get_full_dict(key)

        # We are being asked for a subset of keys.

        # First go and check for each requested dict key in the cache, tracking
        # which we couldn't find.
        values = {}
        known_absent = set()
        missing = []
        for dict_key in dict_keys:
            entry = self.cache.get((key, dict_key), _Sentinel.sentinel)
            if entry is _Sentinel.sentinel:
                missing.append(dict_key)
                continue

            assert isinstance(entry, _PerKeyValue)

            if entry.value is _Sentinel.sentinel:
                known_absent.add(dict_key)
            else:
                values[dict_key] = entry.value

        # If we found everything we can return immediately.
        if not missing:
            return DictionaryEntry(False, known_absent, values)

        # We are missing some keys, so check if we happen to have the full dict in
        # the cache.
        #
        # We don't update the last access time for this cache fetch, as we
        # aren't explicitly interested in the full dict and so we don't want
        # requests for explicit dict keys to keep the full dict in the cache.
        entry = self.cache.get(
            (key, _FullCacheKey.KEY),
            _Sentinel.sentinel,
            update_last_access=False,
        )
        if entry is _Sentinel.sentinel:
            # Not in the cache, return the subset of keys we found.
            return DictionaryEntry(False, known_absent, values)

        # We have the full dict!
        assert isinstance(entry, dict)

        for dict_key in missing:
            # We explicitly add each dict key to the cache, so that cache hit
            # rates and LRU times for each key can be tracked separately.
            value = entry.get(dict_key, _Sentinel.sentinel)  # type: ignore[arg-type]
            self.cache[(key, dict_key)] = _PerKeyValue(value)

            if value is not _Sentinel.sentinel:
                values[dict_key] = value

        return DictionaryEntry(True, set(), values)

    def _get_full_dict(
        self,
        key: KT,
    ) -> DictionaryEntry:
        """Fetch the full dict for the given key."""

        # First we check if we have cached the full dict.
        entry = self.cache.get((key, _FullCacheKey.KEY), _Sentinel.sentinel)
        if entry is not _Sentinel.sentinel:
            assert isinstance(entry, dict)
            return DictionaryEntry(True, set(), entry)

        return DictionaryEntry(False, set(), {})

    def invalidate(self, key: KT) -> None:
        self.check_thread()

        # Increment the sequence number so that any SELECT statements that
        # raced with the INSERT don't update the cache (SYN-369)
        self.sequence += 1

        # We want to drop all information about the dict for the given key, so
        # we use `del_multi` to delete it all in one go.
        #
        # We ignore the type error here: `del_multi` accepts a truncated key
        # (when the key type is a tuple).
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
        """Updates the entry in the cache.

        Note: This does *not* invalidate any existing entries for the `key`.
        In particular, if we add an entry for the cached "full dict" with
        `fetched_keys=None`, existing entries for individual dict keys are
        not invalidated. Likewise, adding entries for individual keys does
        not invalidate any cached value for the full dict.

        In other words: if the underlying data is *changed*, the cache must
        be explicitly invalidated via `.invalidate()`.

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
                self.cache[(key, _FullCacheKey.KEY)] = value
            else:
                self._update_subset(key, value, fetched_keys)

    def _update_subset(
        self, key: KT, value: Dict[DKT, DV], fetched_keys: Iterable[DKT]
    ) -> None:
        """Add the given dictionary values as explicit keys in the cache.

        Args:
            key: top-level cache key
            value: The dictionary with all the values that we should cache
            fetched_keys: The full set of dict keys that were looked up. Any keys
                here not in `value` should be marked as "known absent".
        """

        for dict_key, dict_value in value.items():
            self.cache[(key, dict_key)] = _PerKeyValue(dict_value)

        for dict_key in fetched_keys:
            if dict_key in value:
                continue

            self.cache[(key, dict_key)] = _PerKeyValue(_Sentinel.sentinel)
