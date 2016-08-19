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

    def __init__(self, name, max_entries=1000, keylen=1, tree=False):
        cache_type = TreeCache if tree else dict
        self.cache = LruCache(
            max_size=max_entries, keylen=keylen, cache_type=cache_type
        )

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

    def get(self, key, default=_CacheSentinel, callback=None):
        val = self.cache.get(key, _CacheSentinel, callback=callback)
        if val is not _CacheSentinel:
            self.metrics.inc_hits()
            return val

        self.metrics.inc_misses()

        if default is _CacheSentinel:
            raise KeyError()
        else:
            return default

    def update(self, sequence, key, value, callback=None):
        self.check_thread()
        if self.sequence == sequence:
            # Only update the cache if the caches sequence number matches the
            # number that the cache had before the SELECT was started (SYN-369)
            self.prefill(key, value, callback=callback)

    def prefill(self, key, value, callback=None):
        self.cache.set(key, value, callback=callback)

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

    Cached functions can be "chained" (i.e. a cached function can call other cached
    functions and get appropriately invalidated when they called caches are
    invalidated) by adding a special "cache_context" argument to the function
    and passing that as a kwarg to all caches called. For example::

        @cachedInlineCallbacks(cache_context=True)
        def foo(self, key, cache_context):
            r1 = yield self.bar1(key, on_invalidate=cache_context.invalidate)
            r2 = yield self.bar2(key, on_invalidate=cache_context.invalidate)
            defer.returnValue(r1 + r2)

    """
    def __init__(self, orig, max_entries=1000, num_args=1, tree=False,
                 inlineCallbacks=False, cache_context=False):
        max_entries = int(max_entries * CACHE_SIZE_FACTOR)

        self.orig = orig

        if inlineCallbacks:
            self.function_to_call = defer.inlineCallbacks(orig)
        else:
            self.function_to_call = orig

        self.max_entries = max_entries
        self.num_args = num_args
        self.tree = tree

        all_args = inspect.getargspec(orig)
        self.arg_names = all_args.args[1:num_args + 1]

        if "cache_context" in all_args.args:
            if not cache_context:
                raise ValueError(
                    "Cannot have a 'cache_context' arg without setting"
                    " cache_context=True"
                )
            try:
                self.arg_names.remove("cache_context")
            except ValueError:
                pass
        elif cache_context:
            raise ValueError(
                "Cannot have cache_context=True without having an arg"
                " named `cache_context`"
            )

        self.add_cache_context = cache_context

        if len(self.arg_names) < self.num_args:
            raise Exception(
                "Not enough explicit positional arguments to key off of for %r."
                " (@cached cannot key off of *args or **kwargs)"
                % (orig.__name__,)
            )

    def __get__(self, obj, objtype=None):
        cache = Cache(
            name=self.orig.__name__,
            max_entries=self.max_entries,
            keylen=self.num_args,
            tree=self.tree,
        )

        @functools.wraps(self.orig)
        def wrapped(*args, **kwargs):
            # If we're passed a cache_context then we'll want to call its invalidate()
            # whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            # Add our own `cache_context` to argument list if the wrapped function
            # has asked for one
            self_context = _CacheContext(cache, None)
            if self.add_cache_context:
                kwargs["cache_context"] = self_context

            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            cache_key = tuple(arg_dict[arg_nm] for arg_nm in self.arg_names)

            self_context.key = cache_key

            try:
                cached_result_d = cache.get(cache_key, callback=invalidate_callback)

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
                cache.update(sequence, cache_key, ret, callback=invalidate_callback)

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
            # If we're passed a cache_context then we'll want to call its invalidate()
            # whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

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
                    res = cache.get(tuple(key), callback=invalidate_callback)
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
                    cache.update(
                        sequence, tuple(key), observer,
                        callback=invalidate_callback
                    )

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


class _CacheContext(object):
    __slots__ = ["cache", "key"]

    def __init__(self, cache, key):
        self.cache = cache
        self.key = key

    def invalidate(self):
        self.cache.invalidate(self.key)


def cached(max_entries=1000, num_args=1, tree=False, cache_context=False):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        tree=tree,
        cache_context=cache_context,
    )


def cachedInlineCallbacks(max_entries=1000, num_args=1, tree=False, cache_context=False):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        tree=tree,
        inlineCallbacks=True,
        cache_context=cache_context,
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
