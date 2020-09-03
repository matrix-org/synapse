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

from twisted.internet import defer

from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches import register_cache

logger = logging.getLogger(__name__)


class ResponseCache:
    """
    This caches a deferred response. Until the deferred completes it will be
    returned from the cache. This means that if the client retries the request
    while the response is still being computed, that original response will be
    used rather than trying to compute a new response.
    """

    def __init__(self, hs, name, timeout_ms=0):
        self.pending_result_cache = {}  # Requests that haven't finished yet.

        self.clock = hs.get_clock()
        self.timeout_sec = timeout_ms / 1000.0

        self._name = name
        self._metrics = register_cache("response_cache", name, self, resizable=False)

    def size(self):
        return len(self.pending_result_cache)

    def __len__(self):
        return self.size()

    def get(self, key):
        """Look up the given key.

        Can return either a new Deferred (which also doesn't follow the synapse
        logcontext rules), or, if the request has completed, the actual
        result. You will probably want to make_deferred_yieldable the result.

        If there is no entry for the key, returns None. It is worth noting that
        this means there is no way to distinguish a completed result of None
        from an absent cache entry.

        Args:
            key (hashable):

        Returns:
            twisted.internet.defer.Deferred|None|E: None if there is no entry
            for this key; otherwise either a deferred result or the result
            itself.
        """
        result = self.pending_result_cache.get(key)
        if result is not None:
            self._metrics.inc_hits()
            return result.observe()
        else:
            self._metrics.inc_misses()
            return None

    def set(self, key, deferred):
        """Set the entry for the given key to the given deferred.

        *deferred* should run its callbacks in the sentinel logcontext (ie,
        you should wrap normal synapse deferreds with
        synapse.logging.context.run_in_background).

        Can return either a new Deferred (which also doesn't follow the synapse
        logcontext rules), or, if *deferred* was already complete, the actual
        result. You will probably want to make_deferred_yieldable the result.

        Args:
            key (hashable):
            deferred (twisted.internet.defer.Deferred[T):

        Returns:
            twisted.internet.defer.Deferred[T]|T: a new deferred, or the actual
                result.
        """
        result = ObservableDeferred(deferred, consumeErrors=True)
        self.pending_result_cache[key] = result

        def remove(r):
            if self.timeout_sec:
                self.clock.call_later(
                    self.timeout_sec, self.pending_result_cache.pop, key, None
                )
            else:
                self.pending_result_cache.pop(key, None)
            return r

        result.addBoth(remove)
        return result.observe()

    def wrap(self, key, callback, *args, **kwargs):
        """Wrap together a *get* and *set* call, taking care of logcontexts

        First looks up the key in the cache, and if it is present makes it
        follow the synapse logcontext rules and returns it.

        Otherwise, makes a call to *callback(*args, **kwargs)*, which should
        follow the synapse logcontext rules, and adds the result to the cache.

        Example usage:

            @defer.inlineCallbacks
            def handle_request(request):
                # etc
                return result

            result = yield response_cache.wrap(
                key,
                handle_request,
                request,
            )

        Args:
            key (hashable): key to get/set in the cache

            callback (callable): function to call if the key is not found in
                the cache

            *args: positional parameters to pass to the callback, if it is used

            **kwargs: named parameters to pass to the callback, if it is used

        Returns:
            twisted.internet.defer.Deferred: yieldable result
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
