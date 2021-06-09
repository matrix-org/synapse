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
from typing import Any, Awaitable, Callable, Dict, Generic, Optional, TypeVar

import attr

from twisted.internet import defer

from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.util import Clock
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches import register_cache

logger = logging.getLogger(__name__)

# the type of the key in the cache
KV = TypeVar("KV")

# the type of the result from the operation
RV = TypeVar("RV")


@attr.s(auto_attribs=True)
class ResponseCacheContext(Generic[KV]):
    """Information about a missed ResponseCache hit

    This object can be passed into the callback for additional feedback
    """

    cache_key: KV
    """The cache key that caused the cache miss

    This should be considered read-only.

    TODO: in attrs 20.1, make it frozen with an on_setattr.
    """

    should_cache: bool = True
    """Whether the result should be cached once the request completes.

    This can be modified by the callback if it decides its result should not be cached.
    """


class ResponseCache(Generic[KV]):
    """
    This caches a deferred response. Until the deferred completes it will be
    returned from the cache. This means that if the client retries the request
    while the response is still being computed, that original response will be
    used rather than trying to compute a new response.
    """

    def __init__(self, clock: Clock, name: str, timeout_ms: float = 0):
        # This is poorly-named: it includes both complete and incomplete results.
        # We keep complete results rather than switching to absolute values because
        # that makes it easier to cache Failure results.
        self.pending_result_cache = {}  # type: Dict[KV, ObservableDeferred]

        self.clock = clock
        self.timeout_sec = timeout_ms / 1000.0

        self._name = name
        self._metrics = register_cache("response_cache", name, self, resizable=False)

    def size(self) -> int:
        return len(self.pending_result_cache)

    def __len__(self) -> int:
        return self.size()

    def get(self, key: KV) -> Optional[defer.Deferred]:
        """Look up the given key.

        Returns a new Deferred (which also doesn't follow the synapse
        logcontext rules). You will probably want to make_deferred_yieldable the result.

        If there is no entry for the key, returns None.

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

    def _set(
        self, context: ResponseCacheContext[KV], deferred: defer.Deferred
    ) -> defer.Deferred:
        """Set the entry for the given key to the given deferred.

        *deferred* should run its callbacks in the sentinel logcontext (ie,
        you should wrap normal synapse deferreds with
        synapse.logging.context.run_in_background).

        Returns a new Deferred (which also doesn't follow the synapse logcontext rules).
        You will probably want to make_deferred_yieldable the result.

        Args:
            context: Information about the cache miss
            deferred: The deferred which resolves to the result.

        Returns:
            A new deferred which resolves to the actual result.
        """
        result = ObservableDeferred(deferred, consumeErrors=True)
        key = context.cache_key
        self.pending_result_cache[key] = result

        def on_complete(r):
            # if this cache has a non-zero timeout, and the callback has not cleared
            # the should_cache bit, we leave it in the cache for now and schedule
            # its removal later.
            if self.timeout_sec and context.should_cache:
                self.clock.call_later(
                    self.timeout_sec, self.pending_result_cache.pop, key, None
                )
            else:
                # otherwise, remove the result immediately.
                self.pending_result_cache.pop(key, None)
            return r

        # make sure we do this *after* adding the entry to pending_result_cache,
        # in case the result is already complete (in which case flipping the order would
        # leave us with a stuck entry in the cache).
        result.addBoth(on_complete)
        return result.observe()

    async def wrap(
        self,
        key: KV,
        callback: Callable[..., Awaitable[RV]],
        *args: Any,
        cache_context: bool = False,
        **kwargs: Any,
    ) -> RV:
        """Wrap together a *get* and *set* call, taking care of logcontexts

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

            cache_context: if set, the callback will be given a `cache_context` kw arg,
                which will be a ResponseCacheContext object.

            **kwargs: named parameters to pass to the callback, if it is used

        Returns:
            The result of the callback (from the cache, or otherwise)
        """
        result = self.get(key)
        if not result:
            logger.debug(
                "[%s]: no cached result for [%s], calculating new one", self._name, key
            )
            context = ResponseCacheContext(cache_key=key)
            if cache_context:
                kwargs["cache_context"] = context
            d = run_in_background(callback, *args, **kwargs)
            result = self._set(context, d)
        elif not isinstance(result, defer.Deferred) or result.called:
            logger.info("[%s]: using completed cached result for [%s]", self._name, key)
        else:
            logger.info(
                "[%s]: using incomplete cached result for [%s]", self._name, key
            )
        return await make_deferred_yieldable(result)
