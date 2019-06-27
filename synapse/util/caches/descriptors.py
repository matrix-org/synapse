# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
import functools
import inspect
import logging
import threading
from collections import namedtuple

import six
from six import itervalues, string_types

from twisted.internet import defer

from synapse.util import logcontext, unwrapFirstError
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches import get_cache_factor_for
from synapse.util.caches.lrucache import LruCache
from synapse.util.caches.treecache import TreeCache, iterate_tree_cache_entry
from synapse.util.stringutils import to_ascii

from . import register_cache

logger = logging.getLogger(__name__)


_CacheSentinel = object()


class CacheEntry(object):
    __slots__ = ["deferred", "callbacks", "invalidated"]

    def __init__(self, deferred, callbacks):
        self.deferred = deferred
        self.callbacks = set(callbacks)
        self.invalidated = False

    def invalidate(self):
        if not self.invalidated:
            self.invalidated = True
            for callback in self.callbacks:
                callback()
            self.callbacks.clear()


class Cache(object):
    __slots__ = (
        "cache",
        "max_entries",
        "name",
        "keylen",
        "thread",
        "metrics",
        "_pending_deferred_cache",
    )

    def __init__(self, name, max_entries=1000, keylen=1, tree=False, iterable=False):
        cache_type = TreeCache if tree else dict
        self._pending_deferred_cache = cache_type()

        self.cache = LruCache(
            max_size=max_entries,
            keylen=keylen,
            cache_type=cache_type,
            size_callback=(lambda d: len(d)) if iterable else None,
            evicted_callback=self._on_evicted,
        )

        self.name = name
        self.keylen = keylen
        self.thread = None
        self.metrics = register_cache("cache", name, self.cache)

    def _on_evicted(self, evicted_count):
        self.metrics.inc_evictions(evicted_count)

    def check_thread(self):
        expected_thread = self.thread
        if expected_thread is None:
            self.thread = threading.current_thread()
        else:
            if expected_thread is not threading.current_thread():
                raise ValueError(
                    "Cache objects can only be accessed from the main thread"
                )

    def get(self, key, default=_CacheSentinel, callback=None, update_metrics=True):
        """Looks the key up in the caches.

        Args:
            key(tuple)
            default: What is returned if key is not in the caches. If not
                specified then function throws KeyError instead
            callback(fn): Gets called when the entry in the cache is invalidated
            update_metrics (bool): whether to update the cache hit rate metrics

        Returns:
            Either a Deferred or the raw result
        """
        callbacks = [callback] if callback else []
        val = self._pending_deferred_cache.get(key, _CacheSentinel)
        if val is not _CacheSentinel:
            val.callbacks.update(callbacks)
            if update_metrics:
                self.metrics.inc_hits()
            return val.deferred

        val = self.cache.get(key, _CacheSentinel, callbacks=callbacks)
        if val is not _CacheSentinel:
            self.metrics.inc_hits()
            return val

        if update_metrics:
            self.metrics.inc_misses()

        if default is _CacheSentinel:
            raise KeyError()
        else:
            return default

    def set(self, key, value, callback=None):
        callbacks = [callback] if callback else []
        self.check_thread()
        entry = CacheEntry(deferred=value, callbacks=callbacks)

        existing_entry = self._pending_deferred_cache.pop(key, None)
        if existing_entry:
            existing_entry.invalidate()

        self._pending_deferred_cache[key] = entry

        def shuffle(result):
            existing_entry = self._pending_deferred_cache.pop(key, None)
            if existing_entry is entry:
                self.cache.set(key, result, entry.callbacks)
            else:
                # oops, the _pending_deferred_cache has been updated since
                # we started our query, so we are out of date.
                #
                # Better put back whatever we took out. (We do it this way
                # round, rather than peeking into the _pending_deferred_cache
                # and then removing on a match, to make the common case faster)
                if existing_entry is not None:
                    self._pending_deferred_cache[key] = existing_entry

                # we're not going to put this entry into the cache, so need
                # to make sure that the invalidation callbacks are called.
                # That was probably done when _pending_deferred_cache was
                # updated, but it's possible that `set` was called without
                # `invalidate` being previously called, in which case it may
                # not have been. Either way, let's double-check now.
                entry.invalidate()
            return result

        entry.deferred.addCallback(shuffle)

    def prefill(self, key, value, callback=None):
        callbacks = [callback] if callback else []
        self.cache.set(key, value, callbacks=callbacks)

    def invalidate(self, key):
        self.check_thread()
        self.cache.pop(key, None)

        # if we have a pending lookup for this key, remove it from the
        # _pending_deferred_cache, which will (a) stop it being returned
        # for future queries and (b) stop it being persisted as a proper entry
        # in self.cache.
        entry = self._pending_deferred_cache.pop(key, None)

        # run the invalidation callbacks now, rather than waiting for the
        # deferred to resolve.
        if entry:
            entry.invalidate()

    def invalidate_many(self, key):
        self.check_thread()
        if not isinstance(key, tuple):
            raise TypeError("The cache key must be a tuple not %r" % (type(key),))
        self.cache.del_multi(key)

        # if we have a pending lookup for this key, remove it from the
        # _pending_deferred_cache, as above
        entry_dict = self._pending_deferred_cache.pop(key, None)
        if entry_dict is not None:
            for entry in iterate_tree_cache_entry(entry_dict):
                entry.invalidate()

    def invalidate_all(self):
        self.check_thread()
        self.cache.clear()
        for entry in itervalues(self._pending_deferred_cache):
            entry.invalidate()
        self._pending_deferred_cache.clear()


class _CacheDescriptorBase(object):
    def __init__(self, orig, num_args, inlineCallbacks, cache_context=False):
        self.orig = orig

        if inlineCallbacks:
            self.function_to_call = defer.inlineCallbacks(orig)
        else:
            self.function_to_call = orig

        arg_spec = inspect.getargspec(orig)
        all_args = arg_spec.args

        if "cache_context" in all_args:
            if not cache_context:
                raise ValueError(
                    "Cannot have a 'cache_context' arg without setting"
                    " cache_context=True"
                )
        elif cache_context:
            raise ValueError(
                "Cannot have cache_context=True without having an arg"
                " named `cache_context`"
            )

        if num_args is None:
            num_args = len(all_args) - 1
            if cache_context:
                num_args -= 1

        if len(all_args) < num_args + 1:
            raise Exception(
                "Not enough explicit positional arguments to key off for %r: "
                "got %i args, but wanted %i. (@cached cannot key off *args or "
                "**kwargs)" % (orig.__name__, len(all_args), num_args)
            )

        self.num_args = num_args

        # list of the names of the args used as the cache key
        self.arg_names = all_args[1 : num_args + 1]

        # self.arg_defaults is a map of arg name to its default value for each
        # argument that has a default value
        if arg_spec.defaults:
            self.arg_defaults = dict(
                zip(all_args[-len(arg_spec.defaults) :], arg_spec.defaults)
            )
        else:
            self.arg_defaults = {}

        if "cache_context" in self.arg_names:
            raise Exception("cache_context arg cannot be included among the cache keys")

        self.add_cache_context = cache_context


class CacheDescriptor(_CacheDescriptorBase):
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

    Args:
        num_args (int): number of positional arguments (excluding ``self`` and
            ``cache_context``) to use as cache keys. Defaults to all named
            args of the function.
    """

    def __init__(
        self,
        orig,
        max_entries=1000,
        num_args=None,
        tree=False,
        inlineCallbacks=False,
        cache_context=False,
        iterable=False,
    ):

        super(CacheDescriptor, self).__init__(
            orig,
            num_args=num_args,
            inlineCallbacks=inlineCallbacks,
            cache_context=cache_context,
        )

        max_entries = int(max_entries * get_cache_factor_for(orig.__name__))

        self.max_entries = max_entries
        self.tree = tree
        self.iterable = iterable

    def __get__(self, obj, objtype=None):
        cache = Cache(
            name=self.orig.__name__,
            max_entries=self.max_entries,
            keylen=self.num_args,
            tree=self.tree,
            iterable=self.iterable,
        )

        def get_cache_key_gen(args, kwargs):
            """Given some args/kwargs return a generator that resolves into
            the cache_key.

            We loop through each arg name, looking up if its in the `kwargs`,
            otherwise using the next argument in `args`. If there are no more
            args then we try looking the arg name up in the defaults
            """
            pos = 0
            for nm in self.arg_names:
                if nm in kwargs:
                    yield kwargs[nm]
                elif pos < len(args):
                    yield args[pos]
                    pos += 1
                else:
                    yield self.arg_defaults[nm]

        # By default our cache key is a tuple, but if there is only one item
        # then don't bother wrapping in a tuple.  This is to save memory.
        if self.num_args == 1:
            nm = self.arg_names[0]

            def get_cache_key(args, kwargs):
                if nm in kwargs:
                    return kwargs[nm]
                elif len(args):
                    return args[0]
                else:
                    return self.arg_defaults[nm]

        else:

            def get_cache_key(args, kwargs):
                return tuple(get_cache_key_gen(args, kwargs))

        @functools.wraps(self.orig)
        def wrapped(*args, **kwargs):
            # If we're passed a cache_context then we'll want to call its invalidate()
            # whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            cache_key = get_cache_key(args, kwargs)

            # Add our own `cache_context` to argument list if the wrapped function
            # has asked for one
            if self.add_cache_context:
                kwargs["cache_context"] = _CacheContext(cache, cache_key)

            try:
                cached_result_d = cache.get(cache_key, callback=invalidate_callback)

                if isinstance(cached_result_d, ObservableDeferred):
                    observer = cached_result_d.observe()
                else:
                    observer = cached_result_d

            except KeyError:
                ret = defer.maybeDeferred(
                    logcontext.preserve_fn(self.function_to_call), obj, *args, **kwargs
                )

                def onErr(f):
                    cache.invalidate(cache_key)
                    return f

                ret.addErrback(onErr)

                # If our cache_key is a string on py2, try to convert to ascii
                # to save a bit of space in large caches. Py3 does this
                # internally automatically.
                if six.PY2 and isinstance(cache_key, string_types):
                    cache_key = to_ascii(cache_key)

                result_d = ObservableDeferred(ret, consumeErrors=True)
                cache.set(cache_key, result_d, callback=invalidate_callback)
                observer = result_d.observe()

            if isinstance(observer, defer.Deferred):
                return logcontext.make_deferred_yieldable(observer)
            else:
                return observer

        if self.num_args == 1:
            wrapped.invalidate = lambda key: cache.invalidate(key[0])
            wrapped.prefill = lambda key, val: cache.prefill(key[0], val)
        else:
            wrapped.invalidate = cache.invalidate
            wrapped.invalidate_all = cache.invalidate_all
            wrapped.invalidate_many = cache.invalidate_many
            wrapped.prefill = cache.prefill

        wrapped.invalidate_all = cache.invalidate_all
        wrapped.cache = cache
        wrapped.num_args = self.num_args

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class CacheListDescriptor(_CacheDescriptorBase):
    """Wraps an existing cache to support bulk fetching of keys.

    Given a list of keys it looks in the cache to find any hits, then passes
    the list of missing keys to the wrapped function.

    Once wrapped, the function returns either a Deferred which resolves to
    the list of results, or (if all results were cached), just the list of
    results.
    """

    def __init__(
        self, orig, cached_method_name, list_name, num_args=None, inlineCallbacks=False
    ):
        """
        Args:
            orig (function)
            cached_method_name (str): The name of the chached method.
            list_name (str): Name of the argument which is the bulk lookup list
            num_args (int): number of positional arguments (excluding ``self``,
                but including list_name) to use as cache keys. Defaults to all
                named args of the function.
            inlineCallbacks (bool): Whether orig is a generator that should
                be wrapped by defer.inlineCallbacks
        """
        super(CacheListDescriptor, self).__init__(
            orig, num_args=num_args, inlineCallbacks=inlineCallbacks
        )

        self.list_name = list_name

        self.list_pos = self.arg_names.index(self.list_name)
        self.cached_method_name = cached_method_name

        self.sentinel = object()

        if self.list_name not in self.arg_names:
            raise Exception(
                "Couldn't see arguments %r for %r."
                % (self.list_name, cached_method_name)
            )

    def __get__(self, obj, objtype=None):
        cached_method = getattr(obj, self.cached_method_name)
        cache = cached_method.cache
        num_args = cached_method.num_args

        @functools.wraps(self.orig)
        def wrapped(*args, **kwargs):
            # If we're passed a cache_context then we'll want to call its
            # invalidate() whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            keyargs = [arg_dict[arg_nm] for arg_nm in self.arg_names]
            list_args = arg_dict[self.list_name]

            results = {}

            def update_results_dict(res, arg):
                results[arg] = res

            # list of deferreds to wait for
            cached_defers = []

            missing = set()

            # If the cache takes a single arg then that is used as the key,
            # otherwise a tuple is used.
            if num_args == 1:

                def arg_to_cache_key(arg):
                    return arg

            else:
                keylist = list(keyargs)

                def arg_to_cache_key(arg):
                    keylist[self.list_pos] = arg
                    return tuple(keylist)

            for arg in list_args:
                try:
                    res = cache.get(arg_to_cache_key(arg), callback=invalidate_callback)
                    if not isinstance(res, ObservableDeferred):
                        results[arg] = res
                    elif not res.has_succeeded():
                        res = res.observe()
                        res.addCallback(update_results_dict, arg)
                        cached_defers.append(res)
                    else:
                        results[arg] = res.get_result()
                except KeyError:
                    missing.add(arg)

            if missing:
                # we need an observable deferred for each entry in the list,
                # which we put in the cache. Each deferred resolves with the
                # relevant result for that key.
                deferreds_map = {}
                for arg in missing:
                    deferred = defer.Deferred()
                    deferreds_map[arg] = deferred
                    key = arg_to_cache_key(arg)
                    observable = ObservableDeferred(deferred)
                    cache.set(key, observable, callback=invalidate_callback)

                def complete_all(res):
                    # the wrapped function has completed. It returns a
                    # a dict. We can now resolve the observable deferreds in
                    # the cache and update our own result map.
                    for e in missing:
                        val = res.get(e, None)
                        deferreds_map[e].callback(val)
                        results[e] = val

                def errback(f):
                    # the wrapped function has failed. Invalidate any cache
                    # entries we're supposed to be populating, and fail
                    # their deferreds.
                    for e in missing:
                        key = arg_to_cache_key(e)
                        cache.invalidate(key)
                        deferreds_map[e].errback(f)

                    # return the failure, to propagate to our caller.
                    return f

                args_to_call = dict(arg_dict)
                args_to_call[self.list_name] = list(missing)

                cached_defers.append(
                    defer.maybeDeferred(
                        logcontext.preserve_fn(self.function_to_call), **args_to_call
                    ).addCallbacks(complete_all, errback)
                )

            if cached_defers:
                d = defer.gatherResults(cached_defers, consumeErrors=True).addCallbacks(
                    lambda _: results, unwrapFirstError
                )
                return logcontext.make_deferred_yieldable(d)
            else:
                return results

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class _CacheContext(namedtuple("_CacheContext", ("cache", "key"))):
    # We rely on _CacheContext implementing __eq__ and __hash__ sensibly,
    # which namedtuple does for us (i.e. two _CacheContext are the same if
    # their caches and keys match). This is important in particular to
    # dedupe when we add callbacks to lru cache nodes, otherwise the number
    # of callbacks would grow.
    def invalidate(self):
        self.cache.invalidate(self.key)


def cached(
    max_entries=1000, num_args=None, tree=False, cache_context=False, iterable=False
):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        tree=tree,
        cache_context=cache_context,
        iterable=iterable,
    )


def cachedInlineCallbacks(
    max_entries=1000, num_args=None, tree=False, cache_context=False, iterable=False
):
    return lambda orig: CacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        tree=tree,
        inlineCallbacks=True,
        cache_context=cache_context,
        iterable=iterable,
    )


def cachedList(cached_method_name, list_name, num_args=None, inlineCallbacks=False):
    """Creates a descriptor that wraps a function in a `CacheListDescriptor`.

    Used to do batch lookups for an already created cache. A single argument
    is specified as a list that is iterated through to lookup keys in the
    original cache. A new list consisting of the keys that weren't in the cache
    get passed to the original function, the result of which is stored in the
    cache.

    Args:
        cached_method_name (str): The name of the single-item lookup method.
            This is only used to find the cache to use.
        list_name (str): The name of the argument that is the list to use to
            do batch lookups in the cache.
        num_args (int): Number of arguments to use as the key in the cache
            (including list_name). Defaults to all named parameters.
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
