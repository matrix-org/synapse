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

import threading
from functools import wraps
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Optional,
    Type,
    TypeVar,
    Union,
    cast,
    overload,
)

from typing_extensions import Literal

from synapse.config import cache as cache_config
from synapse.util.caches import CacheMetric, register_cache
from synapse.util.caches.treecache import TreeCache

# Function type: the type used for invalidation callbacks
FT = TypeVar("FT", bound=Callable[..., Any])

# Key and Value type for the cache
KT = TypeVar("KT")
VT = TypeVar("VT")

# a general type var, distinct from either KT or VT
T = TypeVar("T")


def enumerate_leaves(node, depth):
    if depth == 0:
        yield node
    else:
        for n in node.values():
            for m in enumerate_leaves(n, depth - 1):
                yield m


class _Node:
    __slots__ = ["prev_node", "next_node", "key", "value", "callbacks"]

    def __init__(self, prev_node, next_node, key, value, callbacks=set()):
        self.prev_node = prev_node
        self.next_node = next_node
        self.key = key
        self.value = value
        self.callbacks = callbacks


class LruCache(Generic[KT, VT]):
    """
    Least-recently-used cache, supporting prometheus metrics and invalidation callbacks.

    Supports del_multi only if cache_type=TreeCache
    If cache_type=TreeCache, all keys must be tuples.
    """

    def __init__(
        self,
        max_size: int,
        cache_name: Optional[str] = None,
        keylen: int = 1,
        cache_type: Type[Union[dict, TreeCache]] = dict,
        size_callback: Optional[Callable] = None,
        metrics_collection_callback: Optional[Callable[[], None]] = None,
        apply_cache_factor_from_config: bool = True,
    ):
        """
        Args:
            max_size: The maximum amount of entries the cache can hold

            cache_name: The name of this cache, for the prometheus metrics. If unset,
                no metrics will be reported on this cache.

            keylen: The length of the tuple used as the cache key. Ignored unless
                cache_type is `TreeCache`.

            cache_type (type):
                type of underlying cache to be used. Typically one of dict
                or TreeCache.

            size_callback (func(V) -> int | None):

            metrics_collection_callback:
                metrics collection callback. This is called early in the metrics
                collection process, before any of the metrics registered with the
                prometheus Registry are collected, so can be used to update any dynamic
                metrics.

                Ignored if cache_name is None.

            apply_cache_factor_from_config (bool): If true, `max_size` will be
                multiplied by a cache factor derived from the homeserver config
        """
        cache = cache_type()
        self.cache = cache  # Used for introspection.
        self.apply_cache_factor_from_config = apply_cache_factor_from_config

        # Save the original max size, and apply the default size factor.
        self._original_max_size = max_size
        # We previously didn't apply the cache factor here, and as such some caches were
        # not affected by the global cache factor. Add an option here to disable applying
        # the cache factor when a cache is created
        if apply_cache_factor_from_config:
            self.max_size = int(max_size * cache_config.properties.default_factor_size)
        else:
            self.max_size = int(max_size)

        # register_cache might call our "set_cache_factor" callback; there's nothing to
        # do yet when we get resized.
        self._on_resize = None  # type: Optional[Callable[[],None]]

        if cache_name is not None:
            metrics = register_cache(
                "lru_cache",
                cache_name,
                self,
                collect_callback=metrics_collection_callback,
            )  # type: Optional[CacheMetric]
        else:
            metrics = None

        # this is exposed for access from outside this class
        self.metrics = metrics

        list_root = _Node(None, None, None, None)
        list_root.next_node = list_root
        list_root.prev_node = list_root

        lock = threading.Lock()

        def evict():
            while cache_len() > self.max_size:
                todelete = list_root.prev_node
                evicted_len = delete_node(todelete)
                cache.pop(todelete.key, None)
                if metrics:
                    metrics.inc_evictions(evicted_len)

        def synchronized(f: FT) -> FT:
            @wraps(f)
            def inner(*args, **kwargs):
                with lock:
                    return f(*args, **kwargs)

            return cast(FT, inner)

        cached_cache_len = [0]
        if size_callback is not None:

            def cache_len():
                return cached_cache_len[0]

        else:

            def cache_len():
                return len(cache)

        self.len = synchronized(cache_len)

        def add_node(key, value, callbacks=set()):
            prev_node = list_root
            next_node = prev_node.next_node
            node = _Node(prev_node, next_node, key, value, callbacks)
            prev_node.next_node = node
            next_node.prev_node = node
            cache[key] = node

            if size_callback:
                cached_cache_len[0] += size_callback(node.value)

        def move_node_to_front(node):
            prev_node = node.prev_node
            next_node = node.next_node
            prev_node.next_node = next_node
            next_node.prev_node = prev_node
            prev_node = list_root
            next_node = prev_node.next_node
            node.prev_node = prev_node
            node.next_node = next_node
            prev_node.next_node = node
            next_node.prev_node = node

        def delete_node(node):
            prev_node = node.prev_node
            next_node = node.next_node
            prev_node.next_node = next_node
            next_node.prev_node = prev_node

            deleted_len = 1
            if size_callback:
                deleted_len = size_callback(node.value)
                cached_cache_len[0] -= deleted_len

            for cb in node.callbacks:
                cb()
            node.callbacks.clear()
            return deleted_len

        @overload
        def cache_get(
            key: KT,
            default: Literal[None] = None,
            callbacks: Iterable[Callable[[], None]] = ...,
            update_metrics: bool = ...,
        ) -> Optional[VT]:
            ...

        @overload
        def cache_get(
            key: KT,
            default: T,
            callbacks: Iterable[Callable[[], None]] = ...,
            update_metrics: bool = ...,
        ) -> Union[T, VT]:
            ...

        @synchronized
        def cache_get(
            key: KT,
            default: Optional[T] = None,
            callbacks: Iterable[Callable[[], None]] = [],
            update_metrics: bool = True,
        ):
            node = cache.get(key, None)
            if node is not None:
                move_node_to_front(node)
                node.callbacks.update(callbacks)
                if update_metrics and metrics:
                    metrics.inc_hits()
                return node.value
            else:
                if update_metrics and metrics:
                    metrics.inc_misses()
                return default

        @synchronized
        def cache_set(key: KT, value: VT, callbacks: Iterable[Callable[[], None]] = []):
            node = cache.get(key, None)
            if node is not None:
                # We sometimes store large objects, e.g. dicts, which cause
                # the inequality check to take a long time. So let's only do
                # the check if we have some callbacks to call.
                if node.callbacks and value != node.value:
                    for cb in node.callbacks:
                        cb()
                    node.callbacks.clear()

                # We don't bother to protect this by value != node.value as
                # generally size_callback will be cheap compared with equality
                # checks. (For example, taking the size of two dicts is quicker
                # than comparing them for equality.)
                if size_callback:
                    cached_cache_len[0] -= size_callback(node.value)
                    cached_cache_len[0] += size_callback(value)

                node.callbacks.update(callbacks)

                move_node_to_front(node)
                node.value = value
            else:
                add_node(key, value, set(callbacks))

            evict()

        @synchronized
        def cache_set_default(key: KT, value: VT) -> VT:
            node = cache.get(key, None)
            if node is not None:
                return node.value
            else:
                add_node(key, value)
                evict()
                return value

        @overload
        def cache_pop(key: KT, default: Literal[None] = None) -> Optional[VT]:
            ...

        @overload
        def cache_pop(key: KT, default: T) -> Union[T, VT]:
            ...

        @synchronized
        def cache_pop(key: KT, default: Optional[T] = None):
            node = cache.get(key, None)
            if node:
                delete_node(node)
                cache.pop(node.key, None)
                return node.value
            else:
                return default

        @synchronized
        def cache_del_multi(key: KT) -> None:
            """
            This will only work if constructed with cache_type=TreeCache
            """
            popped = cache.pop(key)
            if popped is None:
                return
            for leaf in enumerate_leaves(popped, keylen - len(cast(tuple, key))):
                delete_node(leaf)

        @synchronized
        def cache_clear() -> None:
            list_root.next_node = list_root
            list_root.prev_node = list_root
            for node in cache.values():
                for cb in node.callbacks:
                    cb()
            cache.clear()
            if size_callback:
                cached_cache_len[0] = 0

        @synchronized
        def cache_contains(key: KT) -> bool:
            return key in cache

        self.sentinel = object()

        # make sure that we clear out any excess entries after we get resized.
        self._on_resize = evict

        self.get = cache_get
        self.set = cache_set
        self.setdefault = cache_set_default
        self.pop = cache_pop
        # `invalidate` is exposed for consistency with DeferredCache, so that it can be
        # invalidated by the cache invalidation replication stream.
        self.invalidate = cache_pop
        if cache_type is TreeCache:
            self.del_multi = cache_del_multi
        self.len = synchronized(cache_len)
        self.contains = cache_contains
        self.clear = cache_clear

    def __getitem__(self, key):
        result = self.get(key, self.sentinel)
        if result is self.sentinel:
            raise KeyError()
        else:
            return result

    def __setitem__(self, key, value):
        self.set(key, value)

    def __delitem__(self, key, value):
        result = self.pop(key, self.sentinel)
        if result is self.sentinel:
            raise KeyError()

    def __len__(self):
        return self.len()

    def __contains__(self, key):
        return self.contains(key)

    def set_cache_factor(self, factor: float) -> bool:
        """
        Set the cache factor for this individual cache.

        This will trigger a resize if it changes, which may require evicting
        items from the cache.

        Returns:
            bool: Whether the cache changed size or not.
        """
        if not self.apply_cache_factor_from_config:
            return False

        new_size = int(self._original_max_size * factor)
        if new_size != self.max_size:
            self.max_size = new_size
            if self._on_resize:
                self._on_resize()
            return True
        return False
