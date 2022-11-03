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
from typing import (
    Any,
    Awaitable,
    Callable,
    Collection,
    Dict,
    Generic,
    Hashable,
    Iterable,
    List,
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


class CachedFunction(Generic[F]):
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
        name: Optional[str] = None,
    ):
        self.orig = orig
        self.name = name or orig.__name__

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
        name: Optional[str] = None,
    ):
        super().__init__(
            orig,
            num_args=num_args,
            uncached_args=uncached_args,
            cache_context=cache_context,
            name=name,
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
            name=self.name,
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

        wrapped = cast(CachedFunction, _wrapped)

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

        obj.__dict__[self.name] = wrapped

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
        name: Optional[str] = None,
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
        super().__init__(orig, num_args=num_args, uncached_args=None, name=name)

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

        if num_args != self.num_args:
            raise TypeError(
                "Number of args (%s) does not match underlying cache_method_name=%s (%s)."
                % (self.num_args, self.cached_method_name, num_args)
            )

        @functools.wraps(self.orig)
        def wrapped(*args: Any, **kwargs: Any) -> "defer.Deferred[Dict]":
            # If we're passed a cache_context then we'll want to call its
            # invalidate() whenever we are invalidated
            invalidate_callback = kwargs.pop("on_invalidate", None)

            arg_dict = inspect.getcallargs(self.orig, obj, *args, **kwargs)
            keyargs = [arg_dict[arg_nm] for arg_nm in self.arg_names]
            list_args = arg_dict[self.list_name]

            # If the cache takes a single arg then that is used as the key,
            # otherwise a tuple is used.
            if num_args == 1:

                def arg_to_cache_key(arg: Hashable) -> Hashable:
                    return arg

                def cache_key_to_arg(key: tuple) -> Hashable:
                    return key

            else:
                keylist = list(keyargs)

                def arg_to_cache_key(arg: Hashable) -> Hashable:
                    keylist[self.list_pos] = arg
                    return tuple(keylist)

                def cache_key_to_arg(key: tuple) -> Hashable:
                    return key[self.list_pos]

            cache_keys = [arg_to_cache_key(arg) for arg in list_args]
            immediate_results, pending_deferred, missing = cache.get_bulk(
                cache_keys, callback=invalidate_callback
            )

            results = {cache_key_to_arg(key): v for key, v in immediate_results.items()}

            cached_defers: List["defer.Deferred[Any]"] = []
            if pending_deferred:

                def update_results(r: Dict) -> None:
                    for k, v in r.items():
                        results[cache_key_to_arg(k)] = v

                pending_deferred.addCallback(update_results)
                cached_defers.append(pending_deferred)

            if missing:
                cache_entry = cache.start_bulk_input(missing, invalidate_callback)

                def complete_all(res: Dict[Hashable, Any]) -> None:
                    missing_results = {}
                    for key in missing:
                        arg = cache_key_to_arg(key)
                        val = res.get(arg, None)

                        results[arg] = val
                        missing_results[key] = val

                    cache_entry.complete_bulk(cache, missing_results)

                def errback_all(f: Failure) -> None:
                    cache_entry.error_bulk(cache, missing, f)

                args_to_call = dict(arg_dict)
                args_to_call[self.list_name] = {
                    cache_key_to_arg(key) for key in missing
                }

                # dispatch the call, and attach the two handlers
                missing_d = defer.maybeDeferred(
                    preserve_fn(self.orig), **args_to_call
                ).addCallbacks(complete_all, errback_all)
                cached_defers.append(missing_d)

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

        obj.__dict__[self.name] = wrapped

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
    name: Optional[str] = None,
) -> Callable[[F], CachedFunction[F]]:
    func = lambda orig: DeferredCacheDescriptor(
        orig,
        max_entries=max_entries,
        num_args=num_args,
        uncached_args=uncached_args,
        tree=tree,
        cache_context=cache_context,
        iterable=iterable,
        prune_unread_entries=prune_unread_entries,
        name=name,
    )

    return cast(Callable[[F], CachedFunction[F]], func)


def cachedList(
    *,
    cached_method_name: str,
    list_name: str,
    num_args: Optional[int] = None,
    name: Optional[str] = None,
) -> Callable[[F], CachedFunction[F]]:
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
        name=name,
    )

    return cast(Callable[[F], CachedFunction[F]], func)


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
