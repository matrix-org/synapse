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
import enum
import functools
import inspect
import logging
from typing import (
    Any,
    Callable,
    Generic,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    TypeVar,
    Union,
    cast,
)
from weakref import WeakValueDictionary

from twisted.internet import defer

from synapse.logging.context import make_deferred_yieldable, preserve_fn
from synapse.util import unwrapFirstError
from synapse.util.caches.deferred_cache import DeferredCache
from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)

CacheKey = Union[Tuple, Any]

F = TypeVar("F", bound=Callable[..., Any])


class _CachedFunction(Generic[F]):
    invalidate = None  # type: Any
    invalidate_all = None  # type: Any
    invalidate_many = None  # type: Any
    prefill = None  # type: Any
    cache = None  # type: Any
    num_args = None  # type: Any

    __name__ = None  # type: str

    # Note: This function signature is actually fiddled with by the synapse mypy
    # plugin to a) make it a bound method, and b) remove any `cache_context` arg.
    __call__ = None  # type: F


class _CacheDescriptorBase:
    def __init__(self, orig: Callable[..., Any], num_args, cache_context=False):
        self.orig = orig

        arg_spec = inspect.getfullargspec(orig)
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

        self.cache_key_builder = get_cache_key_builder(
            self.arg_names, self.arg_defaults
        )


class _LruCachedFunction(Generic[F]):
    cache = None  # type: LruCache[CacheKey, Any]
    __call__ = None  # type: F


def lru_cache(
    max_entries: int = 1000, cache_context: bool = False,
) -> Callable[[F], _LruCachedFunction[F]]:
    """A method decorator that applies a memoizing cache around the function.

    This is more-or-less a drop-in equivalent to functools.lru_cache, although note
    that the signature is slightly different.

    The main differences with functools.lru_cache are:
        (a) the size of the cache can be controlled via the cache_factor mechanism
        (b) the wrapped function can request a "cache_context" which provides a
            callback mechanism to indicate that the result is no longer valid
        (c) prometheus metrics are exposed automatically.

    The function should take zero or more arguments, which are used as the key for the
    cache. Single-argument functions use that argument as the cache key; otherwise the
    arguments are built into a tuple.

    Cached functions can be "chained" (i.e. a cached function can call other cached
    functions and get appropriately invalidated when they called caches are
    invalidated) by adding a special "cache_context" argument to the function
    and passing that as a kwarg to all caches called. For example:

        @lru_cache(cache_context=True)
        def foo(self, key, cache_context):
            r1 = self.bar1(key, on_invalidate=cache_context.invalidate)
            r2 = self.bar2(key, on_invalidate=cache_context.invalidate)
            return r1 + r2

    The wrapped function also has a 'cache' property which offers direct access to the
    underlying LruCache.
    """

    def func(orig: F) -> _LruCachedFunction[F]:
        desc = LruCacheDescriptor(
            orig, max_entries=max_entries, cache_context=cache_context,
        )
        return cast(_LruCachedFunction[F], desc)

    return func


class LruCacheDescriptor(_CacheDescriptorBase):
    """Helper for @lru_cache"""

    class _Sentinel(enum.Enum):
        sentinel = object()

    def __init__(
        self, orig, max_entries: int = 1000, cache_context: bool = False,
    ):
        super().__init__(orig, num_args=None, cache_context=cache_context)
        self.max_entries = max_entries

    def __get__(self, obj, owner):
        cache = LruCache(
            cache_name=self.orig.__name__, max_size=self.max_entries,
        )  # type: LruCache[CacheKey, Any]

        get_cache_key = self.cache_key_builder
        sentinel = LruCacheDescriptor._Sentinel.sentinel

        @functools.wraps(self.orig)
        def _wrapped(*args, **kwargs):
            invalidate_callback = kwargs.pop("on_invalidate", None)
            callbacks = (invalidate_callback,) if invalidate_callback else ()

            cache_key = get_cache_key(args, kwargs)

            ret = cache.get(cache_key, default=sentinel, callbacks=callbacks)
            if ret != sentinel:
                return ret

            # Add our own `cache_context` to argument list if the wrapped function
            # has asked for one
            if self.add_cache_context:
                kwargs["cache_context"] = _CacheContext.get_instance(cache, cache_key)

            ret2 = self.orig(obj, *args, **kwargs)
            cache.set(cache_key, ret2, callbacks=callbacks)

            return ret2

        wrapped = cast(_CachedFunction, _wrapped)
        wrapped.cache = cache
        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class DeferredCacheDescriptor(_CacheDescriptorBase):
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

        @cached(cache_context=True)
        def foo(self, key, cache_context):
            r1 = yield self.bar1(key, on_invalidate=cache_context.invalidate)
            r2 = yield self.bar2(key, on_invalidate=cache_context.invalidate)
            return r1 + r2

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
        cache_context=False,
        iterable=False,
    ):
        super().__init__(orig, num_args=num_args, cache_context=cache_context)

        self.max_entries = max_entries
        self.tree = tree
        self.iterable = iterable

    def __get__(self, obj, owner):
        cache = DeferredCache(
            name=self.orig.__name__,
            max_entries=self.max_entries,
            keylen=self.num_args,
            tree=self.tree,
            iterable=self.iterable,
        )  # type: DeferredCache[CacheKey, Any]

        get_cache_key = self.cache_key_builder

        @functools.wraps(self.orig)
        def _wrapped(*args, **kwargs):
            # If we're passed a cache_context then we'll want to call its invalidate()
            # whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            cache_key = get_cache_key(args, kwargs)

            try:
                ret = cache.get(cache_key, callback=invalidate_callback)
            except KeyError:
                # Add our own `cache_context` to argument list if the wrapped function
                # has asked for one
                if self.add_cache_context:
                    kwargs["cache_context"] = _CacheContext.get_instance(
                        cache, cache_key
                    )

                ret = defer.maybeDeferred(preserve_fn(self.orig), obj, *args, **kwargs)
                ret = cache.set(cache_key, ret, callback=invalidate_callback)

            return make_deferred_yieldable(ret)

        wrapped = cast(_CachedFunction, _wrapped)

        if self.num_args == 1:
            wrapped.invalidate = lambda key: cache.invalidate(key[0])
            wrapped.prefill = lambda key, val: cache.prefill(key[0], val)
        else:
            wrapped.invalidate = cache.invalidate
            wrapped.invalidate_many = cache.invalidate_many
            wrapped.prefill = cache.prefill

        wrapped.invalidate_all = cache.invalidate_all
        wrapped.cache = cache
        wrapped.num_args = self.num_args

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class DeferredCacheListDescriptor(_CacheDescriptorBase):
    """Wraps an existing cache to support bulk fetching of keys.

    Given a list of keys it looks in the cache to find any hits, then passes
    the list of missing keys to the wrapped function.

    Once wrapped, the function returns a Deferred which resolves to the list
    of results.
    """

    def __init__(self, orig, cached_method_name, list_name, num_args=None):
        """
        Args:
            orig (function)
            cached_method_name (str): The name of the cached method.
            list_name (str): Name of the argument which is the bulk lookup list
            num_args (int): number of positional arguments (excluding ``self``,
                but including list_name) to use as cache keys. Defaults to all
                named args of the function.
        """
        super().__init__(orig, num_args=num_args)

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
        cache = cached_method.cache  # type: DeferredCache[CacheKey, Any]
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
                    if not res.called:
                        res.addCallback(update_results_dict, arg)
                        cached_defers.append(res)
                    else:
                        results[arg] = res.result
                except KeyError:
                    missing.add(arg)

            if missing:
                # we need a deferred for each entry in the list,
                # which we put in the cache. Each deferred resolves with the
                # relevant result for that key.
                deferreds_map = {}
                for arg in missing:
                    deferred = defer.Deferred()
                    deferreds_map[arg] = deferred
                    key = arg_to_cache_key(arg)
                    cache.set(key, deferred, callback=invalidate_callback)

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
                        preserve_fn(self.orig), **args_to_call
                    ).addCallbacks(complete_all, errback)
                )

            if cached_defers:
                d = defer.gatherResults(cached_defers, consumeErrors=True).addCallbacks(
                    lambda _: results, unwrapFirstError
                )
                return make_deferred_yieldable(d)
            else:
                return defer.succeed(results)

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class _CacheContext:
    """Holds cache information from the cached function higher in the calling order.

    Can be used to invalidate the higher level cache entry if something changes
    on a lower level.
    """

    Cache = Union[DeferredCache, LruCache]

    _cache_context_objects = (
        WeakValueDictionary()
    )  # type: WeakValueDictionary[Tuple[_CacheContext.Cache, CacheKey], _CacheContext]

    def __init__(self, cache: "_CacheContext.Cache", cache_key: CacheKey) -> None:
        self._cache = cache
        self._cache_key = cache_key

    def invalidate(self):  # type: () -> None
        """Invalidates the cache entry referred to by the context."""
        self._cache.invalidate(self._cache_key)

    @classmethod
    def get_instance(
        cls, cache: "_CacheContext.Cache", cache_key: CacheKey
    ) -> "_CacheContext":
        """Returns an instance constructed with the given arguments.

        A new instance is only created if none already exists.
        """

        # We make sure there are no identical _CacheContext instances. This is
        # important in particular to dedupe when we add callbacks to lru cache
        # nodes, otherwise the number of callbacks would grow.
        return cls._cache_context_objects.setdefault(
            (cache, cache_key), cls(cache, cache_key)
        )


def cached(
    max_entries: int = 1000,
    num_args: Optional[int] = None,
    tree: bool = False,
    cache_context: bool = False,
    iterable: bool = False,
) -> Callable[[F], _CachedFunction[F]]:
    func = lambda orig: DeferredCacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        tree=tree,
        cache_context=cache_context,
        iterable=iterable,
    )

    return cast(Callable[[F], _CachedFunction[F]], func)


def cachedList(
    cached_method_name: str, list_name: str, num_args: Optional[int] = None
) -> Callable[[F], _CachedFunction[F]]:
    """Creates a descriptor that wraps a function in a `CacheListDescriptor`.

    Used to do batch lookups for an already created cache. A single argument
    is specified as a list that is iterated through to lookup keys in the
    original cache. A new list consisting of the keys that weren't in the cache
    get passed to the original function, the result of which is stored in the
    cache.

    Args:
        cached_method_name: The name of the single-item lookup method.
            This is only used to find the cache to use.
        list_name: The name of the argument that is the list to use to
            do batch lookups in the cache.
        num_args: Number of arguments to use as the key in the cache
            (including list_name). Defaults to all named parameters.

    Example:

        class Example:
            @cached(num_args=2)
            def do_something(self, first_arg):
                ...

            @cachedList(do_something.cache, list_name="second_args", num_args=2)
            def batch_do_something(self, first_arg, second_args):
                ...
    """
    func = lambda orig: DeferredCacheListDescriptor(
        orig,
        cached_method_name=cached_method_name,
        list_name=list_name,
        num_args=num_args,
    )

    return cast(Callable[[F], _CachedFunction[F]], func)


def get_cache_key_builder(
    param_names: Sequence[str], param_defaults: Mapping[str, Any]
) -> Callable[[Sequence[Any], Mapping[str, Any]], CacheKey]:
    """Construct a function which will build cache keys suitable for a cached function

    Args:
        param_names: list of formal parameter names for the cached function
        param_defaults: a mapping from parameter name to default value for that param

    Returns:
        A function which will take an (args, kwargs) pair and return a cache key
    """

    # By default our cache key is a tuple, but if there is only one item
    # then don't bother wrapping in a tuple.  This is to save memory.

    if len(param_names) == 1:
        nm = param_names[0]

        def get_cache_key(args: Sequence[Any], kwargs: Mapping[str, Any]) -> CacheKey:
            if nm in kwargs:
                return kwargs[nm]
            elif len(args):
                return args[0]
            else:
                return param_defaults[nm]

    else:

        def get_cache_key(args: Sequence[Any], kwargs: Mapping[str, Any]) -> CacheKey:
            return tuple(_get_cache_key_gen(param_names, param_defaults, args, kwargs))

    return get_cache_key


def _get_cache_key_gen(
    param_names: Iterable[str],
    param_defaults: Mapping[str, Any],
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
) -> Iterable[Any]:
    """Given some args/kwargs return a generator that resolves into
    the cache_key.

    This is essentially the same operation as `inspect.getcallargs`, but optimised so
    that we don't need to inspect the target function for each call.
    """

    # We loop through each arg name, looking up if its in the `kwargs`,
    # otherwise using the next argument in `args`. If there are no more
    # args then we try looking the arg name up in the defaults.
    pos = 0
    for nm in param_names:
        if nm in kwargs:
            yield kwargs[nm]
        elif pos < len(args):
            yield args[pos]
            pos += 1
        else:
            yield param_defaults[nm]
