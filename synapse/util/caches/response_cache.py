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

from synapse.util.async import ObservableDeferred


class ResponseCache(object):
    """
    This caches a deferred response. Until the deferred completes it will be
    returned from the cache. This means that if the client retries the request
    while the response is still being computed, that original response will be
    used rather than trying to compute a new response.
    """

    def __init__(self, hs, timeout_ms=0):
        self.pending_result_cache = {}  # Requests that haven't finished yet.

        self.clock = hs.get_clock()
        self.timeout_sec = timeout_ms / 1000.

    def get(self, key):
        result = self.pending_result_cache.get(key)
        if result is not None:
            return result.observe()
        else:
            return None

    def set(self, key, deferred):
        result = ObservableDeferred(deferred, consumeErrors=True)
        self.pending_result_cache[key] = result

        def remove(r):
            if self.timeout_sec:
                self.clock.call_later(
                    self.timeout_sec,
                    self.pending_result_cache.pop, key, None,
                )
            else:
                self.pending_result_cache.pop(key, None)
            return r

        result.addBoth(remove)
        return result.observe()
