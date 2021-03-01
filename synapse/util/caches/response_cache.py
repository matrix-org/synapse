# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Any, Callable, Dict, Generic, Optional, Set, TypeVar

from twisted.internet import defer
from twisted.python.failure import Failure

from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches import register_cache

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)

T = TypeVar("T")


class ResponseCache(Generic[T]):
    """
    This caches a deferred response. Until the deferred completes it will be
    returned from the cache. This means that if the client retries the request
    while the response is still being computed, that original response will be
    used rather than trying to compute a new response.
    """

    def __init__(self, hs: "HomeServer", name: str, timeout_ms: float = 0):
        # Requests that haven't finished yet.
        self.pending_result_cache = {}  # type: Dict[T, ObservableDeferred]
        self.pending_conditionals = {}  # type: Dict[T, Set[Callable[[Any], bool]]]

        self.clock = hs.get_clock()
        self.timeout_sec = timeout_ms / 1000.0

        self._name = name
        self._metrics = register_cache("response_cache", name, self, resizable=False)

    def size(self) -> int:
        return len(self.pending_result_cache)

    def __len__(self) -> int:
        return self.size()

    def get(self, key: T) -> Optional[defer.Deferred]:
        """Look up the given key.

        Can return either a new Deferred (which also doesn't follow the synapse
        logcontext rules), or, if the request has completed, the actual
        result. You will probably want to make_deferred_yieldable the result.

        If there is no entry for the key, returns None. It is worth noting that
        this means there is no way to distinguish a completed result of None
        from an absent cache entry.

        Args:
            key: key to get/set in the cache

        Returns:
            None if there is no entry for this key; otherwise a deferred which
            resolves to the result.
        """
        result = self.pending_result_cache.get(key)
        if result is not None:
            self._metrics.inc_hits()
            return result.observe()
        else:
            self._metrics.inc_misses()
            return None

    @staticmethod
    def _safe_call(func: Callable[[Any], bool], ret_val: Any, key: T) -> bool:
        """
        Wraps a conditional checking function with a try-catch, returns False
        if the conditional function threw an exception during evaluation.
        """
        try:
            return func(ret_val)
        except Exception as e:
            logger.warning(
                "conditional %r threw exception on %s, ignoring and invalidating cache...",
                func,
                key,
                exc_info=e,
            )
            return False

    def _remove_cache(self, key: T):
        self.pending_result_cache.pop(key, None)

    def _errback_remove_cache(self, f: Failure, key: T):
        self._remove_cache(key)
        return f

    def _test_cache(self, r: Any, key: T):
        should_cache = all(
            self._safe_call(func, r, key=key)
            for func in self.pending_conditionals.pop(key, [])
        )

        if self.timeout_sec and should_cache:
            self.clock.call_later(self.timeout_sec, self._remove_cache, key)
        else:
            self._remove_cache(key)
        return r

    def set(self, key: T, deferred: defer.Deferred) -> defer.Deferred:
        """Set the entry for the given key to the given deferred.

        *deferred* should run its callbacks in the sentinel logcontext (ie,
        you should wrap normal synapse deferreds with
        synapse.logging.context.run_in_background).

        Can return either a new Deferred (which also doesn't follow the synapse
        logcontext rules), or, if *deferred* was already complete, the actual
        result. You will probably want to make_deferred_yieldable the result.

        Args:
            key: key to get/set in the cache
            deferred: The deferred which resolves to the result.

        Returns:
            A new deferred which resolves to the actual result.
        """
        result = ObservableDeferred(deferred, consumeErrors=True)
        self.pending_result_cache[key] = result

        result.addCallback(self._test_cache, key)
        result.addErrback(self._errback_remove_cache, key)
        return result.observe()

    def add_conditional(self, key: T, conditional: Callable[[Any], bool]):
        self.pending_conditionals.setdefault(key, set()).add(conditional)

    def wrap_conditional(
        self,
        key: T,
        should_cache: Callable[[Any], bool],
        callback: "Callable[..., Any]",
        *args: Any,
        **kwargs: Any
    ) -> defer.Deferred:
        """The same as wrap(), but adds a conditional to the final execution.

        When the final execution completes, *all* conditionals need to return
        True for it to properly cache (apart from it also not having thrown an
        uncaught exception), else the cache will instantly expire.

        (Note that no conditional must throw an uncaught exception too for it to
        cache)
        """

        # See if there's already a result on this key that hasn't yet completed. Due to the single-threaded nature of
        # python, adding a key immediately in the same execution thread will not cause a race condition.
        result = self.get(key)
        if not result or isinstance(result, defer.Deferred) and not result.called:
            self.add_conditional(key, should_cache)

        return self.wrap(key, callback, *args, **kwargs)

    def wrap(
        self, key: T, callback: "Callable[..., Any]", *args: Any, **kwargs: Any
    ) -> defer.Deferred:
        """Wrap together a *get* and *set* call, taking care of logcontexts.

        Does not cache if the wrapped function throws an uncaught exception.

        First looks up the key in the cache, and if it is present makes it
        follow the synapse logcontext rules and returns it.

        Otherwise, makes a call to *callback(*args, **kwargs)*, which should
        follow the synapse logcontext rules, and adds the result to the cache.

        Example usage:

            async def handle_request(request):
                # etc
                return result

            result = await response_cache.wrap(
                key,
                handle_request,
                request,
            )

        Args:
            key: key to get/set in the cache

            callback: function to call if the key is not found in
                the cache

            *args: positional parameters to pass to the callback, if it is used

            **kwargs: named parameters to pass to the callback, if it is used

        Returns:
            Deferred which resolves to the result
        """
        result = self.get(key)
        if not result:
            logger.debug(
                "[%s]: no cached result for [%s], calculating new one", self._name, key
            )
            d = run_in_background(callback, *args, **kwargs)
            result = self.set(key, d)
        elif not isinstance(result, defer.Deferred) or result.called:
            logger.info("[%s]: using completed cached result for [%s]", self._name, key)
        else:
            logger.info(
                "[%s]: using incomplete cached result for [%s]", self._name, key
            )
        return make_deferred_yieldable(result)
