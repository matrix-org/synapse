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

from synapse.util.async import ObservableDeferred


class SnapshotCache(object):
    """Cache for snapshots like the response of /initialSync.
    The response of initialSync only has to be a recent snapshot of the
    server state. It shouldn't matter to clients if it is a few minutes out
    of date.

    This caches a deferred response. Until the deferred completes it will be
    returned from the cache. This means that if the client retries the request
    while the response is still being computed, that original response will be
    used rather than trying to compute a new response.

    Once the deferred completes it will removed from the cache after 5 minutes.
    We delay removing it from the cache because a client retrying its request
    could race with us finishing computing the response.

    Rather than tracking precisely how long something has been in the cache we
    keep two generations of completed responses. Every 5 minutes discard the
    old generation, move the new generation to the old generation, and set the
    new generation to be empty. This means that a result will be in the cache
    somewhere between 5 and 10 minutes.
    """

    DURATION_MS = 5 * 60 * 1000  # Cache results for 5 minutes.

    def __init__(self):
        self.pending_result_cache = {}  # Request that haven't finished yet.
        self.prev_result_cache = {}  # The older requests that have finished.
        self.next_result_cache = {}  # The newer requests that have finished.
        self.time_last_rotated_ms = 0

    def rotate(self, time_now_ms):
        # Rotate once if the cache duration has passed since the last rotation.
        if time_now_ms - self.time_last_rotated_ms >= self.DURATION_MS:
            self.prev_result_cache = self.next_result_cache
            self.next_result_cache = {}
            self.time_last_rotated_ms += self.DURATION_MS

        # Rotate again if the cache duration has passed twice since the last
        # rotation.
        if time_now_ms - self.time_last_rotated_ms >= self.DURATION_MS:
            self.prev_result_cache = self.next_result_cache
            self.next_result_cache = {}
            self.time_last_rotated_ms = time_now_ms

    def get(self, time_now_ms, key):
        self.rotate(time_now_ms)
        # This cache is intended to deduplicate requests, so we expect it to be
        # missed most of the time. So we just lookup the key in all of the
        # dictionaries rather than trying to short circuit the lookup if the
        # key is found.
        result = self.prev_result_cache.get(key)
        result = self.next_result_cache.get(key, result)
        result = self.pending_result_cache.get(key, result)
        if result is not None:
            return result.observe()
        else:
            return None

    def set(self, time_now_ms, key, deferred):
        self.rotate(time_now_ms)

        result = ObservableDeferred(deferred)

        self.pending_result_cache[key] = result

        def shuffle_along(r):
            # When the deferred completes we shuffle it along to the first
            # generation of the result cache. So that it will eventually
            # expire from the rotation of that cache.
            self.next_result_cache[key] = result
            self.pending_result_cache.pop(key, None)
            return r

        result.addBoth(shuffle_along)

        return result.observe()
