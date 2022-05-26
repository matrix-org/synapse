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
    Awaitable,
    Callable,
    Collection,
    Dict,
    Generic,
    Hashable,
    Iterable,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Type,
    TypeVar,
    Union,
    cast,
)
from weakref import WeakValueDictionary

from twisted.internet import defer
from twisted.python.failure import Failure

from synapse.logging.context import make_deferred_yieldable, preserve_fn
from synapse.util import unwrapFirstError
from synapse.util.async_helpers import delay_cancellation
from synapse.util.caches.deferred_cache import DeferredCache
from synapse.util.caches.lrucache import LruCache

logger = logging.getLogger(__name__)

CacheKey = Union[Tuple, Any]

F = TypeVar("F", bound=Callable[..., Any])


class _CachedFunction(Generic[F]):
    invalidate: Any = None
    invalidate_all: Any = None
    prefill: Any = None
    cache: Any = None
    num_args: Any = None

    __name__: str

    # Note: This function signature is actually fiddled with by the synapse mypy
    # plugin to a) make it a bound method, and b) remove any `cache_context` arg.
    __call__: F


class _CacheDescriptorBase:
    def __init__(
        self,
        orig: Callable[..., Any],
        num_args: Optional[int],
        uncached_args: Optional[Collection[str]] = None,
        cache_context: bool = False,
    ):
        self.orig = orig

        arg_spec = inspect.getfullargspec(orig)
        all_args = arg_spec.args

        # There's no reason that keyword-only arguments couldn't be supported,
        # but right now they're buggy so do not allow them.
        if arg_spec.kwonlyargs:
            raise ValueError(
                "_CacheDescriptorBase does not support keyword-only arguments."
            )

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

        if num_args is not None and uncached_args is not None:
            raise ValueError("Cannot provide both num_args and uncached_args")

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

        # If there are args to not cache on, filter them out (and fix the size of num_args).
        if uncached_args is not None:
            include_arg_in_cache_key = [n not in uncached_args for n in self.arg_names]
        else:
            include_arg_in_cache_key = [True] * len(self.arg_names)

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

        self.cache_key_builder = _get_cache_key_builder(
            self.arg_names, include_arg_in_cache_key, self.arg_defaults
        )


class _LruCachedFunction(Generic[F]):
    cache: LruCache[CacheKey, Any]
    __call__: F


def lru_cache(
    *, max_entries: int = 1000, cache_context: bool = False
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
            orig,
            max_entries=max_entries,
            cache_context=cache_context,
        )
        return cast(_LruCachedFunction[F], desc)

    return func


class LruCacheDescriptor(_CacheDescriptorBase):
    """Helper for @lru_cache"""

    class _Sentinel(enum.Enum):
        sentinel = object()

    def __init__(
        self,
        orig: Callable[..., Any],
        max_entries: int = 1000,
        cache_context: bool = False,
    ):
        super().__init__(
            orig, num_args=None, uncached_args=None, cache_context=cache_context
        )
        self.max_entries = max_entries

    def __get__(self, obj: Optional[Any], owner: Optional[Type]) -> Callable[..., Any]:
        cache: LruCache[CacheKey, Any] = LruCache(
            cache_name=self.orig.__name__,
            max_size=self.max_entries,
        )

        get_cache_key = self.cache_key_builder
        sentinel = LruCacheDescriptor._Sentinel.sentinel

        @functools.wraps(self.orig)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
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
    """A method decorator that applies a memoizing cache around the function.

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
        orig:
        max_entries:
        num_args: number of positional arguments (excluding ``self`` and
            ``cache_context``) to use as cache keys. Defaults to all named
            args of the function.
        uncached_args: a list of argument names to not use as the cache key.
            (``self`` and ``cache_context`` are always ignored.) Cannot be used
            with num_args.
        tree:
        cache_context:
        iterable:
        prune_unread_entries: If True, cache entries that haven't been read recently
            will be evicted from the cache in the background. Set to False to opt-out
            of this behaviour.
    """

    def __init__(
        self,
        orig: Callable[..., Any],
        max_entries: int = 1000,
        num_args: Optional[int] = None,
        uncached_args: Optional[Collection[str]] = None,
        tree: bool = False,
        cache_context: bool = False,
        iterable: bool = False,
        prune_unread_entries: bool = True,
    ):
        super().__init__(
            orig,
            num_args=num_args,
            uncached_args=uncached_args,
            cache_context=cache_context,
        )

        if tree and self.num_args < 2:
            raise RuntimeError(
                "tree=True is nonsensical for cached functions with a single parameter"
            )

        self.max_entries = max_entries
        self.tree = tree
        self.iterable = iterable
        self.prune_unread_entries = prune_unread_entries

    def __get__(self, obj: Optional[Any], owner: Optional[Type]) -> Callable[..., Any]:
        cache: DeferredCache[CacheKey, Any] = DeferredCache(
            name=self.orig.__name__,
            max_entries=self.max_entries,
            tree=self.tree,
            iterable=self.iterable,
            prune_unread_entries=self.prune_unread_entries,
        )

        get_cache_key = self.cache_key_builder

        @functools.wraps(self.orig)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
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

                # We started a new call to `self.orig`, so we must always wait for it to
                # complete. Otherwise we might mark our current logging context as
                # finished while `self.orig` is still using it in the background.
                ret = delay_cancellation(ret)

            return make_deferred_yieldable(ret)

        wrapped = cast(_CachedFunction, _wrapped)

        if self.num_args == 1:
            assert not self.tree
            wrapped.invalidate = lambda key: cache.invalidate(key[0])
            wrapped.prefill = lambda key, val: cache.prefill(key[0], val)
        else:
            wrapped.invalidate = cache.invalidate
            wrapped.prefill = cache.prefill

        wrapped.invalidate_all = cache.invalidate_all
        wrapped.cache = cache
        wrapped.num_args = self.num_args

        obj.__dict__[self.orig.__name__] = wrapped

        return wrapped


class DeferredCacheListDescriptor(_CacheDescriptorBase):
    """Wraps an existing cache to support bulk fetching of keys.

    Given an iterable of keys it looks in the cache to find any hits, then passes
    the set of missing keys to the wrapped function.

    Once wrapped, the function returns a Deferred which resolves to a Dict mapping from
    input key to output value.
    """

    def __init__(
        self,
        orig: Callable[..., Awaitable[Dict]],
        cached_method_name: str,
        list_name: str,
        num_args: Optional[int] = None,
    ):
        """
        Args:
            orig
            cached_method_name: The name of the cached method.
            list_name: Name of the argument which is the bulk lookup list
            num_args: number of positional arguments (excluding ``self``,
                but including list_name) to use as cache keys. Defaults to all
                named args of the function.
        """
        super().__init__(orig, num_args=num_args, uncached_args=None)

        self.list_name = list_name

        self.list_pos = self.arg_names.index(self.list_name)
        self.cached_method_name = cached_method_name

        self.sentinel = object()

        if self.list_name not in self.arg_names:
            raise Exception(
                "Couldn't see arguments %r for %r."
                % (self.list_name, cached_method_name)
            )

    def __get__(
        self, obj: Optional[Any], objtype: Optional[Type] = None
    ) -> Callable[..., "defer.Deferred[Dict[Hashable, Any]]"]:
        cached_method = getattr(obj, self.cached_method_name)
        cache: DeferredCache[CacheKey, Any] = cached_method.cache
        num_args = cached_method.num_args

        @functools.wraps(self.orig)
        def wrapped(*args: Any, **kwargs: Any) -> "defer.Deferred[Dict]":
            # If we're passed a cache_context then we'll want to call its
            # invalidate() whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            keyargs = [arg_dict[arg_nm] for arg_nm in self.arg_names]
            list_args = arg_dict[self.list_name]

            results = {}

            def update_results_dict(res: Any, arg: Hashable) -> None:
                results[arg] = res

            # list of deferreds to wait for
            cached_defers = []

            missing = set()

            # If the cache takes a single arg then that is used as the key,
            # otherwise a tuple is used.
            if num_args == 1:

                def arg_to_cache_key(arg: Hashable) -> Hashable:
                    return arg

            else:
                keylist = list(keyargs)

                def arg_to_cache_key(arg: Hashable) -> Hashable:
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
                    deferred: "defer.Deferred[Any]" = defer.Deferred()
                    deferreds_map[arg] = deferred
                    key = arg_to_cache_key(arg)
                    cached_defers.append(
                        cache.set(key, deferred, callback=invalidate_callback)
                    )

                def complete_all(res: Dict[Hashable, Any]) -> None:
                    # the wrapped function has completed. It returns a dict.
                    # We can now update our own result map, and then resolve the
                    # observable deferreds in the cache.
                    for e, d1 in deferreds_map.items():
                        val = res.get(e, None)
                        # make sure we update the results map before running the
                        # deferreds, because as soon as we run the last deferred, the
                        # gatherResults() below will complete and return the result
                        # dict to our caller.
                        results[e] = val
                        d1.callback(val)

                def errback_all(f: Failure) -> None:
                    # the wrapped function has failed. Propagate the failure into
                    # the cache, which will invalidate the entry, and cause the
                    # relevant cached_deferreds to fail, which will propagate the
                    # failure to our caller.
                    for d1 in deferreds_map.values():
                        d1.errback(f)

                args_to_call = dict(arg_dict)
                args_to_call[self.list_name] = missing

                # dispatch the call, and attach the two handlers
                defer.maybeDeferred(
                    preserve_fn(self.orig), **args_to_call
                ).addCallbacks(complete_all, errback_all)

            if cached_defers:
                d = defer.gatherResults(cached_defers, consumeErrors=True).addCallbacks(
                    lambda _: results, unwrapFirstError
                )
                if missing:
                    # We started a new call to `self.orig`, so we must always wait for it to
                    # complete. Otherwise we might mark our current logging context as
                    # finished while `self.orig` is still using it in the background.
                    d = delay_cancellation(d)
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

    _cache_context_objects: """WeakValueDictionary[
        Tuple["_CacheContext.Cache", CacheKey], "_CacheContext"
    ]""" = WeakValueDictionary()

    def __init__(self, cache: "_CacheContext.Cache", cache_key: CacheKey) -> None:
        self._cache = cache
        self._cache_key = cache_key

    def invalidate(self) -> None:
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
    *,
    max_entries: int = 1000,
    num_args: Optional[int] = None,
    uncached_args: Optional[Collection[str]] = None,
    tree: bool = False,
    cache_context: bool = False,
    iterable: bool = False,
    prune_unread_entries: bool = True,
) -> Callable[[F], _CachedFunction[F]]:
    func = lambda orig: DeferredCacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        uncached_args=uncached_args,
        tree=tree,
        cache_context=cache_context,
        iterable=iterable,
        prune_unread_entries=prune_unread_entries,
    )

    return cast(Callable[[F], _CachedFunction[F]], func)


def cachedList(
    *, cached_method_name: str, list_name: str, num_args: Optional[int] = None
) -> Callable[[F], _CachedFunction[F]]:
    """Creates a descriptor that wraps a function in a `DeferredCacheListDescriptor`.

    Used to do batch lookups for an already created cache. One of the arguments
    is specified as a list that is iterated through to lookup keys in the
    original cache. A new tuple consisting of the (deduplicated) keys that weren't in
    the cache gets passed to the original function, which is expected to results
    in a map of key to value for each passed value. THe new results are stored in the
    original cache. Note that any missing values are cached as None.

    Args:
        cached_method_name: The name of the single-item lookup method.
            This is only used to find the cache to use.
        list_name: The name of the argument that is the iterable to use to
            do batch lookups in the cache.
        num_args: Number of arguments to use as the key in the cache
            (including list_name). Defaults to all named parameters.

    Example:

        class Example:
            @cached()
            def do_something(self, first_arg, second_arg):
                ...

            @cachedList(cached_method_name="do_something", list_name="second_args")
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


def _get_cache_key_builder(
    param_names: Sequence[str],
    include_params: Sequence[bool],
    param_defaults: Mapping[str, Any],
) -> Callable[[Sequence[Any], Mapping[str, Any]], CacheKey]:
    """Construct a function which will build cache keys suitable for a cached function

    Args:
        param_names: list of formal parameter names for the cached function
        include_params: list of bools of whether to include the parameter name in the cache key
        param_defaults: a mapping from parameter name to default value for that param

    Returns:
        A function which will take an (args, kwargs) pair and return a cache key
    """

    # By default our cache key is a tuple, but if there is only one item
    # then don't bother wrapping in a tuple.  This is to save memory.

    if len(param_names) == 1:
        nm = param_names[0]
        assert include_params[0] is True

        def get_cache_key(args: Sequence[Any], kwargs: Mapping[str, Any]) -> CacheKey:
            if nm in kwargs:
                return kwargs[nm]
            elif len(args):
                return args[0]
            else:
                return param_defaults[nm]

    else:

        def get_cache_key(args: Sequence[Any], kwargs: Mapping[str, Any]) -> CacheKey:
            return tuple(
                _get_cache_key_gen(
                    param_names, include_params, param_defaults, args, kwargs
                )
            )

    return get_cache_key


def _get_cache_key_gen(
    param_names: Iterable[str],
    include_params: Iterable[bool],
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
    for nm, inc in zip(param_names, include_params):
        if nm in kwargs:
            if inc:
                yield kwargs[nm]
        elif pos < len(args):
            if inc:
                yield args[pos]
            pos += 1
        else:
            if inc:
                yield param_defaults[nm]
