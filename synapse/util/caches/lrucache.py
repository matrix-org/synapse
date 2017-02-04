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


from functools import wraps
import threading

from synapse.util.caches.treecache import TreeCache


def enumerate_leaves(node, depth):
    if depth == 0:
        yield node
    else:
        for n in node.values():
            for m in enumerate_leaves(n, depth - 1):
                yield m


class _Node(object):
    __slots__ = ["prev_node", "next_node", "key", "value", "callbacks"]

    def __init__(self, prev_node, next_node, key, value, callbacks=set()):
        self.prev_node = prev_node
        self.next_node = next_node
        self.key = key
        self.value = value
        self.callbacks = callbacks


class LruCache(object):
    """
    Least-recently-used cache.
    Supports del_multi only if cache_type=TreeCache
    If cache_type=TreeCache, all keys must be tuples.

    Can also set callbacks on objects when getting/setting which are fired
    when that key gets invalidated/evicted.
    """
    def __init__(self, max_size, keylen=1, cache_type=dict, size_callback=None):
        cache = cache_type()
        self.cache = cache  # Used for introspection.
        list_root = _Node(None, None, None, None)
        list_root.next_node = list_root
        list_root.prev_node = list_root

        lock = threading.Lock()

        def evict():
            while cache_len() > max_size:
                todelete = list_root.prev_node
                delete_node(todelete)
                cache.pop(todelete.key, None)

        def synchronized(f):
            @wraps(f)
            def inner(*args, **kwargs):
                with lock:
                    return f(*args, **kwargs)

            return inner

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

            if size_callback:
                cached_cache_len[0] -= size_callback(node.value)

            for cb in node.callbacks:
                cb()
            node.callbacks.clear()

        @synchronized
        def cache_get(key, default=None, callbacks=[]):
            node = cache.get(key, None)
            if node is not None:
                move_node_to_front(node)
                node.callbacks.update(callbacks)
                return node.value
            else:
                return default

        @synchronized
        def cache_set(key, value, callbacks=[]):
            node = cache.get(key, None)
            if node is not None:
                if value != node.value:
                    for cb in node.callbacks:
                        cb()
                    node.callbacks.clear()

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
        def cache_set_default(key, value):
            node = cache.get(key, None)
            if node is not None:
                return node.value
            else:
                add_node(key, value)
                evict()
                return value

        @synchronized
        def cache_pop(key, default=None):
            node = cache.get(key, None)
            if node:
                delete_node(node)
                cache.pop(node.key, None)
                return node.value
            else:
                return default

        @synchronized
        def cache_del_multi(key):
            """
            This will only work if constructed with cache_type=TreeCache
            """
            popped = cache.pop(key)
            if popped is None:
                return
            for leaf in enumerate_leaves(popped, keylen - len(key)):
                delete_node(leaf)

        @synchronized
        def cache_clear():
            list_root.next_node = list_root
            list_root.prev_node = list_root
            for node in cache.values():
                for cb in node.callbacks:
                    cb()
            cache.clear()
            if size_callback:
                cached_cache_len[0] = 0

        @synchronized
        def cache_contains(key):
            return key in cache

        self.sentinel = object()
        self.get = cache_get
        self.set = cache_set
        self.setdefault = cache_set_default
        self.pop = cache_pop
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
