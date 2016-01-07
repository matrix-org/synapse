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


class LruCache(object):
    """Least-recently-used cache."""
    def __init__(self, max_size):
        cache = {}
        list_root = []
        list_root[:] = [list_root, list_root, None, None]

        PREV, NEXT, KEY, VALUE = 0, 1, 2, 3

        lock = threading.Lock()

        def synchronized(f):
            @wraps(f)
            def inner(*args, **kwargs):
                with lock:
                    return f(*args, **kwargs)

            return inner

        def add_node(key, value):
            prev_node = list_root
            next_node = prev_node[NEXT]
            node = [prev_node, next_node, key, value]
            prev_node[NEXT] = node
            next_node[PREV] = node
            cache[key] = node

        def move_node_to_front(node):
            prev_node = node[PREV]
            next_node = node[NEXT]
            prev_node[NEXT] = next_node
            next_node[PREV] = prev_node
            prev_node = list_root
            next_node = prev_node[NEXT]
            node[PREV] = prev_node
            node[NEXT] = next_node
            prev_node[NEXT] = node
            next_node[PREV] = node

        def delete_node(node):
            prev_node = node[PREV]
            next_node = node[NEXT]
            prev_node[NEXT] = next_node
            next_node[PREV] = prev_node
            cache.pop(node[KEY], None)

        @synchronized
        def cache_get(key, default=None):
            node = cache.get(key, None)
            if node is not None:
                move_node_to_front(node)
                return node[VALUE]
            else:
                return default

        @synchronized
        def cache_set(key, value):
            node = cache.get(key, None)
            if node is not None:
                move_node_to_front(node)
                node[VALUE] = value
            else:
                add_node(key, value)
                if len(cache) > max_size:
                    delete_node(list_root[PREV])

        @synchronized
        def cache_set_default(key, value):
            node = cache.get(key, None)
            if node is not None:
                return node[VALUE]
            else:
                add_node(key, value)
                if len(cache) > max_size:
                    delete_node(list_root[PREV])
                return value

        @synchronized
        def cache_pop(key, default=None):
            node = cache.get(key, None)
            if node:
                delete_node(node)
                return node[VALUE]
            else:
                return default

        @synchronized
        def cache_clear():
            list_root[NEXT] = list_root
            list_root[PREV] = list_root
            cache.clear()

        @synchronized
        def cache_len():
            return len(cache)

        @synchronized
        def cache_contains(key):
            return key in cache

        self.sentinel = object()
        self.get = cache_get
        self.set = cache_set
        self.setdefault = cache_set_default
        self.pop = cache_pop
        self.len = cache_len
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
