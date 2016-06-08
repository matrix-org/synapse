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
import logging

from synapse.util.async import ObservableDeferred
from synapse.util import unwrapFirstError
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.treecache import TreeCache
from synapse.util.logcontext import (
    PreserveLoggingContext, preserve_context_over_deferred, preserve_context_over_fn
)

from . import DEBUG_CACHES, register_cache

from twisted.internet import defer

from collections import OrderedDict

import os
import functools
import inspect
import threading


logger = logging.getLogger(__name__)


_CacheSentinel = object()


CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.1))


class Cache(object):
    __slots__ = (
        "cache",
        "max_entries",
        "name",
        "keylen",
        "sequence",
        "thread",
        "metrics",
    )

    def __init__(self, name, max_entries=1000, keylen=1, lru=True, tree=False):
        if lru:
            cache_type = TreeCache if tree else dict
            self.cache = LruCache(
                max_size=max_entries, keylen=keylen, cache_type=cache_type
            )
            self.max_entries = None
        else:
            self.cache = OrderedDict()
            self.max_entries = max_entries

        self.name = name
        self.keylen = keylen
        self.sequence = 0
        self.thread = None
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

    def get(self, key, default=_CacheSentinel):
        val = self.cache.get(key, _CacheSentinel)
        if val is not _CacheSentinel:
            self.metrics.inc_hits()
            return val

        self.metrics.inc_misses()

        if default is _CacheSentinel:
            raise KeyError()
        else:
            return default

    def update(self, sequence, key, value):
        self.check_thread()
        if self.sequence == sequence:
            # Only update the cache if the caches sequence number matches the
            # number that the cache had before the SELECT was started (SYN-369)
            self.prefill(key, value)

    def prefill(self, key, value):
        if self.max_entries is not None:
            while len(self.cache) >= self.max_entries:
                self.cache.popitem(last=False)

        self.cache[key] = value

    def invalidate(self, key):
        self.check_thread()
        if not isinstance(key, tuple):
            raise TypeError(
                "The cache key must be a tuple not %r" % (type(key),)
            )

        # Increment the sequence number so that any SELECT statements that
        # raced with the INSERT don't update the cache (SYN-369)
        self.sequence += 1
        self.cache.pop(key, None)

    def invalidate_many(self, key):
        self.check_thread()
        if not isinstance(key, tuple):
            raise TypeError(
                "The cache key must be a tuple not %r" % (type(key),)
            )
        self.sequence += 1
        self.cache.del_multi(key)

    def invalidate_all(self):
        self.check_thread()
        self.sequence += 1
        self.cache.clear()


class CacheDescriptor(object):
    """ A method decorator that applies a memoizing cache around the function.

    This caches deferreds, rather than the results themselves. Deferreds that
    fail are removed from the cache.

    The function is presumed to take zero or more arguments, which are used in
    a tuple as the key for the cache. Hits are served directly from the cache;
    misses use the function body to generate the value.

    The wrapped function has an additional member, a callable called
    "invalidate". This can be used to remove individual entries from the cache.

    The wrapped function has another additional callable, called "prefill",
    which can be used to insert values into the cache specifically, without
    calling the calculation function.
    """
    def __init__(self, orig, max_entries=1000, num_args=1, lru=True, tree=False,
                 inlineCallbacks=False):
        max_entries = int(max_entries * CACHE_SIZE_FACTOR)

        self.orig = orig

        if inlineCallbacks:
            self.function_to_call = defer.inlineCallbacks(orig)
        else:
            self.function_to_call = orig

        self.max_entries = max_entries
        self.num_args = num_args
        self.lru = lru
        self.tree = tree

        self.arg_names = inspect.getargspec(orig).args[1:num_args + 1]

        if len(self.arg_names) < self.num_args:
            raise Exception(
                "Not enough explicit positional arguments to key off of for %r."
                " (@cached cannot key off of *args or **kwars)"
                % (orig.__name__,)
            )

    def __get__(self, obj, objtype=None):
        cache = Cache(
            name=self.orig.__name__,
            max_entries=self.max_entries,
            keylen=self.num_args,
            lru=self.lru,
            tree=self.tree,
        )

        @functools.wraps(self.orig)
        def wrapped(*args, **kwargs):
            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            cache_key = tuple(arg_dict[arg_nm] for arg_nm in self.arg_names)
            try:
                cached_result_d = cache.get(cache_key)

                observer = cached_result_d.observe()
                if DEBUG_CACHES:
                    @defer.inlineCallbacks
                    def check_result(cached_result):
                        actual_result = yield self.function_to_call(obj, *args, **kwargs)
                        if actual_result != cached_result:
                            logger.error(
                                "Stale cache entry %s%r: cached: %r, actual %r",
                                self.orig.__name__, cache_key,
                                cached_result, actual_result,
                            )
                            raise ValueError("Stale cache entry")
                        defer.returnValue(cached_result)
                    observer.addCallback(check_result)

                return preserve_context_over_deferred(observer)
            except KeyError:
                # Get the sequence number of the cache before reading from the
                # database so that we can tell if the cache is invalidated
                # while the SELECT is executing (SYN-369)
                sequence = cache.sequence

                ret = defer.maybeDeferred(
                    preserve_context_over_fn,
                    self.function_to_call,
                    obj, *args, **kwargs
                )

                def onErr(f):
                    cache.invalidate(cache_key)
                    return f

                ret.addErrback(onErr)

                ret = ObservableDeferred(ret, consumeErrors=True)
                cache.update(sequence, cache_key, ret)

                return preserve_context_over_deferred(ret.observe())

        wrapped.invalidate = cache.invalidate
        wrapped.invalidate_all = cache.invalidate_all
        wrapped.invalidate_many = cache.invalidate_many
        wrapped.prefill = cache.prefill
        wrapped.cache = cache

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class CacheListDescriptor(object):
    """Wraps an existing cache to support bulk fetching of keys.

    Given a list of keys it looks in the cache to find any hits, then passes
    the list of missing keys to the wrapped fucntion.
    """

    def __init__(self, orig, cached_method_name, list_name, num_args=1,
                 inlineCallbacks=False):
        """
        Args:
            orig (function)
            method_name (str); The name of the chached method.
            list_name (str): Name of the argument which is the bulk lookup list
            num_args (int)
            inlineCallbacks (bool): Whether orig is a generator that should
                be wrapped by defer.inlineCallbacks
        """
        self.orig = orig

        if inlineCallbacks:
            self.function_to_call = defer.inlineCallbacks(orig)
        else:
            self.function_to_call = orig

        self.num_args = num_args
        self.list_name = list_name

        self.arg_names = inspect.getargspec(orig).args[1:num_args + 1]
        self.list_pos = self.arg_names.index(self.list_name)

        self.cached_method_name = cached_method_name

        self.sentinel = object()

        if len(self.arg_names) < self.num_args:
            raise Exception(
                "Not enough explicit positional arguments to key off of for %r."
                " (@cached cannot key off of *args or **kwars)"
                % (orig.__name__,)
            )

        if self.list_name not in self.arg_names:
            raise Exception(
                "Couldn't see arguments %r for %r."
                % (self.list_name, cached_method_name,)
            )

    def __get__(self, obj, objtype=None):

        cache = getattr(obj, self.cached_method_name).cache

        @functools.wraps(self.orig)
        def wrapped(*args, **kwargs):
            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            keyargs = [arg_dict[arg_nm] for arg_nm in self.arg_names]
            list_args = arg_dict[self.list_name]

            # cached is a dict arg -> deferred, where deferred results in a
            # 2-tuple (`arg`, `result`)
            results = {}
            cached_defers = {}
            missing = []
            for arg in list_args:
                key = list(keyargs)
                key[self.list_pos] = arg

                try:
                    res = cache.get(tuple(key))
                    if not res.has_succeeded():
                        res = res.observe()
                        res.addCallback(lambda r, arg: (arg, r), arg)
                        cached_defers[arg] = res
                    else:
                        results[arg] = res.get_result()
                except KeyError:
                    missing.append(arg)

            if missing:
                sequence = cache.sequence
                args_to_call = dict(arg_dict)
                args_to_call[self.list_name] = missing

                ret_d = defer.maybeDeferred(
                    preserve_context_over_fn,
                    self.function_to_call,
                    **args_to_call
                )

                ret_d = ObservableDeferred(ret_d)

                # We need to create deferreds for each arg in the list so that
                # we can insert the new deferred into the cache.
                for arg in missing:
                    with PreserveLoggingContext():
                        observer = ret_d.observe()
                    observer.addCallback(lambda r, arg: r.get(arg, None), arg)

                    observer = ObservableDeferred(observer)

                    key = list(keyargs)
                    key[self.list_pos] = arg
                    cache.update(sequence, tuple(key), observer)

                    def invalidate(f, key):
                        cache.invalidate(key)
                        return f
                    observer.addErrback(invalidate, tuple(key))

                    res = observer.observe()
                    res.addCallback(lambda r, arg: (arg, r), arg)

                    cached_defers[arg] = res

            if cached_defers:
                def update_results_dict(res):
                    results.update(res)
                    return results

                return preserve_context_over_deferred(defer.gatherResults(
                    cached_defers.values(),
                    consumeErrors=True,
                ).addCallback(update_results_dict).addErrback(
                    unwrapFirstError
                ))
            else:
                return results

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


def cached(max_entries=1000, num_args=1, lru=True, tree=False):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        lru=lru,
        tree=tree,
    )


def cachedInlineCallbacks(max_entries=1000, num_args=1, lru=False, tree=False):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        lru=lru,
        tree=tree,
        inlineCallbacks=True,
    )


def cachedList(cached_method_name, list_name, num_args=1, inlineCallbacks=False):
    """Creates a descriptor that wraps a function in a `CacheListDescriptor`.

    Used to do batch lookups for an already created cache. A single argument
    is specified as a list that is iterated through to lookup keys in the
    original cache. A new list consisting of the keys that weren't in the cache
    get passed to the original function, the result of which is stored in the
    cache.

    Args:
        cache (Cache): The underlying cache to use.
        list_name (str): The name of the argument that is the list to use to
            do batch lookups in the cache.
        num_args (int): Number of arguments to use as the key in the cache.
        inlineCallbacks (bool): Should the function be wrapped in an
            `defer.inlineCallbacks`?

    Example:

        class Example(object):
            @cached(num_args=2)
            def do_something(self, first_arg):
                ...

            @cachedList(do_something.cache, list_name="second_args", num_args=2)
            def batch_do_something(self, first_arg, second_args):
                ...
    """
    return lambda orig: CacheListDescriptor(
        orig,
        cached_method_name=cached_method_name,
        list_name=list_name,
        num_args=num_args,
        inlineCallbacks=inlineCallbacks,
    )
