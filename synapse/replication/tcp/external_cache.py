# -*- coding: utf-8 -*-
# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Any, Optional

from prometheus_client import Counter

from synapse.logging.context import make_deferred_yieldable
from synapse.util import json_decoder, json_encoder

if TYPE_CHECKING:
    from synapse.server import HomeServer

set_counter = Counter(
    "synapse_external_cache_set",
    "Number of times we set a cache",
    labelnames=["cache_name"],
)

get_counter = Counter(
    "synapse_external_cache_get",
    "Number of times we get a cache",
    labelnames=["cache_name", "hit"],
)


logger = logging.getLogger(__name__)


class ExternalCache:
    """A cache backed by an external Redis. Does nothing if no Redis is
    configured.
    """

    def __init__(self, hs: "HomeServer"):
        self._redis_connection = hs.get_outbound_redis_connection()

    def _get_redis_key(self, cache_name: str, key: str) -> str:
        return "cache_v1:%s:%s" % (cache_name, key)

    def is_enabled(self) -> bool:
        """Whether the external cache is used or not.

        It's safe to use the cache when this returns false, the methods will
        just no-op, but the function is useful to avoid doing unnecessary work.
        """
        return self._redis_connection is not None

    async def set(self, cache_name: str, key: str, value: Any, expiry_ms: int) -> None:
        """Add the key/value to the named cache, with the expiry time given.
        """

        if self._redis_connection is None:
            return

        set_counter.labels(cache_name).inc()

        # txredisapi requires the value to be string, bytes or numbers, so we
        # encode stuff in JSON.
        encoded_value = json_encoder.encode(value)

        logger.debug("Caching %s %s: %r", cache_name, key, encoded_value)

        return await make_deferred_yieldable(
            self._redis_connection.set(
                self._get_redis_key(cache_name, key), encoded_value, pexpire=expiry_ms,
            )
        )

    async def get(self, cache_name: str, key: str) -> Optional[Any]:
        """Look up a key/value in the named cache.
        """

        if self._redis_connection is None:
            return None

        result = await make_deferred_yieldable(
            self._redis_connection.get(self._get_redis_key(cache_name, key))
        )

        logger.debug("Got cache result %s %s: %r", cache_name, key, result)

        get_counter.labels(cache_name, result is not None).inc()

        if not result:
            return None

        # For some reason the integers get magically converted back to integers
        if isinstance(result, int):
            return result

        return json_decoder.decode(result)
