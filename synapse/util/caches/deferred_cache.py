# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

import abc
import enum
import threading
from typing import (
    Callable,
    Collection,
    Dict,
    Generic,
    MutableMapping,
    Optional,
    Set,
    Sized,
    Tuple,
    TypeVar,
    Union,
    cast,
)

from prometheus_client import Gauge

from twisted.internet import defer
from twisted.python.failure import Failure

from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.treecache import TreeCache, iterate_tree_cache_entry

cache_pending_metric = Gauge(
    "synapse_util_caches_cache_pending",
    "Number of lookups currently pending for this cache",
    ["name"],
)

T = TypeVar("T")
KT = TypeVar("KT")
VT = TypeVar("VT")


class _Sentinel(enum.Enum):
    # defining a sentinel in this way allows mypy to correctly handle the
    # type of a dictionary lookup.
    sentinel = object()


class DeferredCache(Generic[KT, VT]):
    """Wraps an LruCache, adding support for Deferred results.

    It expects that each entry added with set() will be a Deferred; likewise get()
    will return a Deferred.
    """

    __slots__ = (
        "cache",
        "thread",
        "_pending_deferred_cache",
    )

    def __init__(
        self,
        name: str,
        max_entries: int = 1000,
        tree: bool = False,
        iterable: bool = False,
        apply_cache_factor_from_config: bool = True,
        prune_unread_entries: bool = True,
    ):
        """
        Args:
            name: The name of the cache
            max_entries: Maximum amount of entries that the cache will hold
            tree: Use a TreeCache instead of a dict as the underlying cache type
            iterable: If True, count each item in the cached object as an entry,
                rather than each cached object
            apply_cache_factor_from_config: Whether cache factors specified in the
                config file affect `max_entries`
            prune_unread_entries: If True, cache entries that haven't been read recently
                will be evicted from the cache in the background. Set to False to
                opt-out of this behaviour.
        """
        cache_type = TreeCache if tree else dict

        # _pending_deferred_cache maps from the key value to a `CacheEntry` object.
        self._pending_deferred_cache: Union[
            TreeCache, "MutableMapping[KT, CacheEntry[KT, VT]]"
        ] = cache_type()

        def metrics_cb() -> None:
            cache_pending_metric.labels(name).set(len(self._pending_deferred_cache))

        # cache is used for completed results and maps to the result itself, rather than
        # a Deferred.
        self.cache: LruCache[KT, VT] = LruCache(
            max_size=max_entries,
            cache_name=name,
            cache_type=cache_type,
            size_callback=(
                (lambda d: len(cast(Sized, d)) or 1)
                # Argument 1 to "len" has incompatible type "VT"; expected "Sized"
                # We trust that `VT` is `Sized` when `iterable` is `True`
                if iterable
                else None
            ),
            metrics_collection_callback=metrics_cb,
            apply_cache_factor_from_config=apply_cache_factor_from_config,
            prune_unread_entries=prune_unread_entries,
        )

        self.thread: Optional[threading.Thread] = None

    @property
    def max_entries(self) -> int:
        return self.cache.max_size

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
        self,
        key: KT,
        callback: Optional[Callable[[], None]] = None,
        update_metrics: bool = True,
    ) -> defer.Deferred:
        """Looks the key up in the caches.

        For symmetry with set(), this method does *not* follow the synapse logcontext
        rules: the logcontext will not be cleared on return, and the Deferred will run
        its callbacks in the sentinel context. In other words: wrap the result with
        make_deferred_yieldable() before `await`ing it.

        Args:
            key:
            callback: Gets called when the entry in the cache is invalidated
            update_metrics (bool): whether to update the cache hit rate metrics

        Returns:
            A Deferred which completes with the result. Note that this may later fail
            if there is an ongoing set() operation which later completes with a failure.

        Raises:
            KeyError if the key is not found in the cache
        """
        val = self._pending_deferred_cache.get(key, _Sentinel.sentinel)
        if val is not _Sentinel.sentinel:
            val.add_invalidation_callback(key, callback)
            if update_metrics:
                m = self.cache.metrics
                assert m  # we always have a name, so should always have metrics
                m.inc_hits()
            return val.deferred(key)

        callbacks = (callback,) if callback else ()

        val2 = self.cache.get(
            key, _Sentinel.sentinel, callbacks=callbacks, update_metrics=update_metrics
        )
        if val2 is _Sentinel.sentinel:
            raise KeyError()
        else:
            return defer.succeed(val2)

    def get_bulk(
        self,
        keys: Collection[KT],
        callback: Optional[Callable[[], None]] = None,
    ) -> Tuple[Dict[KT, VT], Optional["defer.Deferred[Dict[KT, VT]]"], Collection[KT]]:
        """Bulk lookup of items in the cache.

        Returns:
            A 3-tuple of:
                1. a dict of key/value of items already cached;
                2. a deferred that resolves to a dict of key/value of items
                   we're already fetching; and
                3. a collection of keys that don't appear in the previous two.
        """

        # The cached results
        cached = {}

        # List of pending deferreds
        pending = []

        # Dict that gets filled out when the pending deferreds complete
        pending_results = {}

        # List of keys that aren't in either cache
        missing = []

        callbacks = (callback,) if callback else ()

        for key in keys:
            # Check if its in the main cache.
            immediate_value = self.cache.get(
                key,
                _Sentinel.sentinel,
                callbacks=callbacks,
            )
            if immediate_value is not _Sentinel.sentinel:
                cached[key] = immediate_value
                continue

            # Check if its in the pending cache
            pending_value = self._pending_deferred_cache.get(key, _Sentinel.sentinel)
            if pending_value is not _Sentinel.sentinel:
                pending_value.add_invalidation_callback(key, callback)

                def completed_cb(value: VT, key: KT) -> VT:
                    pending_results[key] = value
                    return value

                # Add a callback to fill out `pending_results` when that completes
                d = pending_value.deferred(key).addCallback(completed_cb, key)
                pending.append(d)
                continue

            # Not in either cache
            missing.append(key)

        # If we've got pending deferreds, squash them into a single one that
        # returns `pending_results`.
        pending_deferred = None
        if pending:
            pending_deferred = defer.gatherResults(
                pending, consumeErrors=True
            ).addCallback(lambda _: pending_results)

        return (cached, pending_deferred, missing)

    def get_immediate(
        self, key: KT, default: T, update_metrics: bool = True
    ) -> Union[VT, T]:
        """If we have a *completed* cached value, return it."""
        return self.cache.get(key, default, update_metrics=update_metrics)

    def set(
        self,
        key: KT,
        value: "defer.Deferred[VT]",
        callback: Optional[Callable[[], None]] = None,
    ) -> defer.Deferred:
        """Adds a new entry to the cache (or updates an existing one).

        The given `value` *must* be a Deferred.

        First any existing entry for the same key is invalidated. Then a new entry
        is added to the cache for the given key.

        Until the `value` completes, calls to `get()` for the key will also result in an
        incomplete Deferred, which will ultimately complete with the same result as
        `value`.

        If `value` completes successfully, subsequent calls to `get()` will then return
        a completed deferred with the same result. If it *fails*, the cache is
        invalidated and subequent calls to `get()` will raise a KeyError.

        If another call to `set()` happens before `value` completes, then (a) any
        invalidation callbacks registered in the interim will be called, (b) any
        `get()`s in the interim will continue to complete with the result from the
        *original* `value`, (c) any future calls to `get()` will complete with the
        result from the *new* `value`.

        It is expected that `value` does *not* follow the synapse logcontext rules - ie,
        if it is incomplete, it runs its callbacks in the sentinel context.

        Args:
            key: Key to be set
            value: a deferred which will complete with a result to add to the cache
            callback: An optional callback to be called when the entry is invalidated
        """
        self.check_thread()

        self._pending_deferred_cache.pop(key, None)

        # XXX: why don't we invalidate the entry in `self.cache` yet?

        # otherwise, we'll add an entry to the _pending_deferred_cache for now,
        # and add callbacks to add it to the cache properly later.
        entry = CacheEntrySingle[KT, VT](value)
        entry.add_invalidation_callback(key, callback)
        self._pending_deferred_cache[key] = entry
        deferred = entry.deferred(key).addCallbacks(
            self._completed_callback,
            self._error_callback,
            callbackArgs=(entry, key),
            errbackArgs=(entry, key),
        )

        # we return a new Deferred which will be called before any subsequent observers.
        return deferred

    def start_bulk_input(
        self,
        keys: Collection[KT],
        callback: Optional[Callable[[], None]] = None,
    ) -> "CacheMultipleEntries[KT, VT]":
        """Bulk set API for use when fetching multiple keys at once from the DB.

        Called *before* starting the fetch from the DB, and the caller *must*
        call either `complete_bulk(..)` or `error_bulk(..)` on the return value.
        """

        entry = CacheMultipleEntries[KT, VT]()
        entry.add_global_invalidation_callback(callback)

        for key in keys:
            self._pending_deferred_cache[key] = entry

        return entry

    def _completed_callback(
        self, value: VT, entry: "CacheEntry[KT, VT]", key: KT
    ) -> VT:
        """Called when a deferred is completed."""
        # We check if the current entry matches the entry associated with the
        # deferred. If they don't match then it got invalidated.
        current_entry = self._pending_deferred_cache.pop(key, None)
        if current_entry is not entry:
            if current_entry:
                self._pending_deferred_cache[key] = current_entry
            return value

        self.cache.set(key, value, entry.get_invalidation_callbacks(key))

        return value

    def _error_callback(
        self,
        failure: Failure,
        entry: "CacheEntry[KT, VT]",
        key: KT,
    ) -> Failure:
        """Called when a deferred errors."""

        # We check if the current entry matches the entry associated with the
        # deferred. If they don't match then it got invalidated.
        current_entry = self._pending_deferred_cache.pop(key, None)
        if current_entry is not entry:
            if current_entry:
                self._pending_deferred_cache[key] = current_entry
            return failure

        for cb in entry.get_invalidation_callbacks(key):
            cb()

        return failure

    def prefill(
        self, key: KT, value: VT, callback: Optional[Callable[[], None]] = None
    ) -> None:
        callbacks = (callback,) if callback else ()
        self.cache.set(key, value, callbacks=callbacks)
        self._pending_deferred_cache.pop(key, None)

    def invalidate(self, key: KT) -> None:
        """Delete a key, or tree of entries

        If the cache is backed by a regular dict, then "key" must be of
        the right type for this cache

        If the cache is backed by a TreeCache, then "key" must be a tuple, but
        may be of lower cardinality than the TreeCache - in which case the whole
        subtree is deleted.
        """
        self.check_thread()
        self.cache.del_multi(key)

        # if we have a pending lookup for this key, remove it from the
        # _pending_deferred_cache, which will (a) stop it being returned for
        # future queries and (b) stop it being persisted as a proper entry
        # in self.cache.
        entry = self._pending_deferred_cache.pop(key, None)
        if entry:
            # _pending_deferred_cache.pop should either return a CacheEntry, or, in the
            # case of a TreeCache, a dict of keys to cache entries. Either way calling
            # iterate_tree_cache_entry on it will do the right thing.
            for iter_entry in iterate_tree_cache_entry(entry):
                for cb in iter_entry.get_invalidation_callbacks(key):
                    cb()

    def invalidate_all(self) -> None:
        self.check_thread()
        self.cache.clear()
        for key, entry in self._pending_deferred_cache.items():
            for cb in entry.get_invalidation_callbacks(key):
                cb()

        self._pending_deferred_cache.clear()


class CacheEntry(Generic[KT, VT], metaclass=abc.ABCMeta):
    """Abstract class for entries in `DeferredCache[KT, VT]`"""

    @abc.abstractmethod
    def deferred(self, key: KT) -> "defer.Deferred[VT]":
        """Get a deferred that a caller can wait on to get the value at the
        given key"""
        ...

    @abc.abstractmethod
    def add_invalidation_callback(
        self, key: KT, callback: Optional[Callable[[], None]]
    ) -> None:
        """Add an invalidation callback"""
        ...

    @abc.abstractmethod
    def get_invalidation_callbacks(self, key: KT) -> Collection[Callable[[], None]]:
        """Get all invalidation callbacks"""
        ...


class CacheEntrySingle(CacheEntry[KT, VT]):
    """An implementation of `CacheEntry` wrapping a deferred that results in a
    single cache entry.
    """

    __slots__ = ["_deferred", "_callbacks"]

    def __init__(self, deferred: "defer.Deferred[VT]") -> None:
        self._deferred = ObservableDeferred(deferred, consumeErrors=True)
        self._callbacks: Set[Callable[[], None]] = set()

    def deferred(self, key: KT) -> "defer.Deferred[VT]":
        return self._deferred.observe()

    def add_invalidation_callback(
        self, key: KT, callback: Optional[Callable[[], None]]
    ) -> None:
        if callback is None:
            return

        self._callbacks.add(callback)

    def get_invalidation_callbacks(self, key: KT) -> Collection[Callable[[], None]]:
        return self._callbacks


class CacheMultipleEntries(CacheEntry[KT, VT]):
    """Cache entry that is used for bulk lookups and insertions."""

    __slots__ = ["_deferred", "_callbacks", "_global_callbacks"]

    def __init__(self) -> None:
        self._deferred: Optional[ObservableDeferred[Dict[KT, VT]]] = None
        self._callbacks: Dict[KT, Set[Callable[[], None]]] = {}
        self._global_callbacks: Set[Callable[[], None]] = set()

    def deferred(self, key: KT) -> "defer.Deferred[VT]":
        if not self._deferred:
            self._deferred = ObservableDeferred(defer.Deferred(), consumeErrors=True)
        return self._deferred.observe().addCallback(lambda res: res.get(key))

    def add_invalidation_callback(
        self, key: KT, callback: Optional[Callable[[], None]]
    ) -> None:
        if callback is None:
            return

        self._callbacks.setdefault(key, set()).add(callback)

    def get_invalidation_callbacks(self, key: KT) -> Collection[Callable[[], None]]:
        return self._callbacks.get(key, set()) | self._global_callbacks

    def add_global_invalidation_callback(
        self, callback: Optional[Callable[[], None]]
    ) -> None:
        """Add a callback for when any keys get invalidated."""
        if callback is None:
            return

        self._global_callbacks.add(callback)

    def complete_bulk(
        self,
        cache: DeferredCache[KT, VT],
        result: Dict[KT, VT],
    ) -> None:
        """Called when there is a result"""
        for key, value in result.items():
            cache._completed_callback(value, self, key)

        if self._deferred:
            self._deferred.callback(result)

    def error_bulk(
        self, cache: DeferredCache[KT, VT], keys: Collection[KT], failure: Failure
    ) -> None:
        """Called when bulk lookup failed."""
        for key in keys:
            cache._error_callback(failure, self, key)

        if self._deferred:
            self._deferred.errback(failure)
