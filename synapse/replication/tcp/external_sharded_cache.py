# Copyright 2022 Beeper
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

import binascii
import logging
import pickle
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

import jump
from prometheus_client import Counter, Histogram
from txredisapi import RedisError

from twisted.internet import defer

from synapse.logging import opentracing
from synapse.logging.context import make_deferred_yieldable
from synapse.replication.tcp.redis import lazyConnection
from synapse.util import unwrapFirstError

if TYPE_CHECKING:
    from synapse.server import HomeServer

set_counter = Counter(
    "synapse_external_sharded_cache_set",
    "Number of times we set a cache",
    labelnames=["cache_name"],
)

get_counter = Counter(
    "synapse_external_sharded_cache_get",
    "Number of times we get a cache",
    labelnames=["cache_name", "hit"],
)

response_timer = Histogram(
    "synapse_external_sharded_cache_response_time_seconds",
    "Time taken to get a response from Redis for a cache get/set request",
    labelnames=["method"],
    buckets=(
        0.001,
        0.002,
        0.005,
        0.01,
        0.02,
        0.05,
    ),
)


logger = logging.getLogger(__name__)


class ExternalShardedCache:
    """A cache backed by an external Redis. Does nothing if no Redis is
    configured.
    """

    def __init__(self, hs: "HomeServer"):
        self._redis_shards = []

        if hs.config.redis.redis_enabled and hs.config.redis.cache_shard_hosts:
            for shard in hs.config.redis.cache_shard_hosts:
                logger.info(
                    "Connecting to redis (host=%r port=%r) for external cache",
                    shard["host"],
                    shard["port"],
                )
                self._redis_shards.append(
                    lazyConnection(
                        hs=hs,
                        host=shard["host"],
                        port=shard["port"],
                        reconnect=True,
                        replyTimeout=5,
                    ),
                )

    def _get_redis_key(self, cache_name: str, key: str) -> str:
        return "sharded_cache_v1:%s:%s" % (cache_name, key)

    def _get_redis_shard_id(self, redis_key: str) -> int:
        key = binascii.crc32(redis_key.encode()) & 0xFFFFFFFF
        idx = jump.hash(key, len(self._redis_shards))
        return idx

    def is_enabled(self) -> bool:
        """Whether the external cache is used or not.

        It's safe to use the cache when this returns false, the methods will
        just no-op, but the function is useful to avoid doing unnecessary work.
        """
        return bool(self._redis_shards)

    async def mset(
        self,
        cache_name: str,
        values: Dict[str, Any],
    ) -> None:
        """Add the key/value combinations to the named cache, with the expiry time given."""

        if not self.is_enabled():
            return

        set_counter.labels(cache_name).inc(len(values))

        logger.debug("Caching %s: %r", cache_name, values)

        shard_id_to_encoded_values: Dict[int, Dict[str, Any]] = defaultdict(dict)

        for key, value in values.items():
            redis_key = self._get_redis_key(cache_name, key)
            shard_id = self._get_redis_shard_id(redis_key)
            shard_id_to_encoded_values[shard_id][redis_key] = pickle.dumps(value)

        with opentracing.start_active_span(
            "ExternalShardedCache.set",
            tags={opentracing.SynapseTags.CACHE_NAME: cache_name},
        ):
            with response_timer.labels("set").time():
                deferreds = [
                    self._redis_shards[shard_id].mset(values)
                    for shard_id, values in shard_id_to_encoded_values.items()
                ]
                try:
                    await make_deferred_yieldable(
                        defer.gatherResults(deferreds, consumeErrors=True)
                    ).addErrback(unwrapFirstError)
                except RedisError as e:
                    logger.error("Failed to set on one or more Redis shards: %r", e)

    async def set(self, cache_name: str, key: str, value: Any) -> None:
        await self.mset(cache_name, {key: value})

    async def _mget_shard(
        self, shard_id: int, key_mapping: Dict[str, str]
    ) -> Dict[str, Any]:
        shard = self._redis_shards[shard_id]
        try:
            results = await shard.mget(list(key_mapping.values()))
        except RedisError as e:
            logger.error("Failed to get from Redis %r: %r", shard, e)
            return {}
        original_keys = list(key_mapping.keys())
        mapped_results: Dict[str, Any] = {}
        for i, result in enumerate(results):
            if not result:
                continue
            try:
                result = pickle.loads(result)
            except Exception as e:
                logger.error("Failed to decode cache result: %r", e)
            else:
                mapped_results[original_keys[i]] = result
        return mapped_results

    async def mget(self, cache_name: str, keys: List[str]) -> Dict[str, Any]:
        """Look up a key/value combinations in the named cache."""

        if not self.is_enabled():
            return {}

        shard_id_to_key_mapping: Dict[int, Dict[str, str]] = defaultdict(dict)

        for key in keys:
            redis_key = self._get_redis_key(cache_name, key)
            shard_id = self._get_redis_shard_id(redis_key)
            shard_id_to_key_mapping[shard_id][key] = redis_key

        with opentracing.start_active_span(
            "ExternalShardedCache.get",
            tags={opentracing.SynapseTags.CACHE_NAME: cache_name},
        ):
            with response_timer.labels("get").time():
                deferreds = [
                    defer.ensureDeferred(self._mget_shard(shard_id, keys))
                    for shard_id, keys in shard_id_to_key_mapping.items()
                ]
                results: Union[
                    list, list[Dict[str, Any]]
                ] = await make_deferred_yieldable(
                    defer.gatherResults(deferreds, consumeErrors=True)
                ).addErrback(
                    unwrapFirstError
                )

        combined_results: Dict[str, Any] = {}
        for result in results:
            combined_results.update(result)

        logger.debug("Got cache result %s %s: %r", cache_name, keys, combined_results)

        get_counter.labels(cache_name, True).inc(len(combined_results))
        get_counter.labels(cache_name, False).inc(len(keys) - len(combined_results))

        return combined_results

    async def get(
        self, cache_name: str, key: str, default: Optional[Any] = None
    ) -> Any:
        return (await self.mget(cache_name, [key])).get(key, default)

    async def contains(self, cache_name: str, key: str) -> bool:
        redis_key = self._get_redis_key(cache_name, key)
        shard_id = self._get_redis_shard_id(redis_key)
        return await self._redis_shards[shard_id].exists(redis_key)

    async def delete(self, cache_name: str, key: str) -> None:
        redis_key = self._get_redis_key(cache_name, key)
        shard_id = self._get_redis_shard_id(redis_key)
        await self._redis_shards[shard_id].delete(redis_key)
