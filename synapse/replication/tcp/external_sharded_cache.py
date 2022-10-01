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
from typing import TYPE_CHECKING, Any, Callable, Coroutine, Dict, List, Optional, Union

import jump
from prometheus_client import Counter, Histogram
from txredisapi import ConnectionError, ConnectionHandler, RedisError

from twisted.internet import defer

from synapse.logging import opentracing
from synapse.logging.context import make_deferred_yieldable, run_in_background
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


_REDIS_CONNECTION_ATTEMPTS = 5
_REDIS_TIMEOUT = 5

# Object to return when we fail to talk to Redis, rather than an exception because
# we shouldn't fail if we can't use the cache.
_SENTINEL = object()


class ExternalShardedCache:
    """
    A sharded cache backed by an external Redis instances. Does nothing if no
    Redis shards are configured. Methods do not raise exceptions and sends
    warning logs in case Redis shards are unavailable.
    """

    def __init__(self, hs: "HomeServer"):
        self._redis_shards: List[ConnectionHandler] = []
        self._reactor = hs.get_reactor()

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
                    ),
                )

    async def _redis_with_retry(
        self,
        shard: ConnectionHandler,
        method: Callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        # Have to access the private factory method here because the txredisapi.ConnectionHandler
        # provides no way to access the underlying pool.
        if not shard._factory.pool:
            logger.warning("Redis shard is not connected: %r", shard)
            return _SENTINEL

        attempt = 0
        try:
            while True:
                try:
                    return await method(*args, **kwargs).addTimeout(
                        _REDIS_TIMEOUT, self._reactor
                    )
                except ConnectionError:
                    if attempt >= _REDIS_CONNECTION_ATTEMPTS:
                        raise
                    attempt += 1
        except (ConnectionError, RedisError, defer.TimeoutError) as e:
            logger.warning("Failed to talk to Redis %r: %r", shard, e)
        return _SENTINEL

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

    def _mset_shard(
        self,
        shard_id: int,
        values: Dict[str, Any],
    ) -> Coroutine:
        shard = self._redis_shards[shard_id]
        return self._redis_with_retry(shard, shard.mset, values)

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
                    defer.ensureDeferred(self._mset_shard(shard_id, values))
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
        results = await self._redis_with_retry(
            shard,
            shard.mget,
            list(key_mapping.values()),
        )
        if results is _SENTINEL:
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
        shard = self._redis_shards[shard_id]
        return (await self._redis_with_retry(shard, shard.exists, redis_key)) is True

    async def delete(self, cache_name: str, key: str) -> None:
        redis_key = self._get_redis_key(cache_name, key)
        shard_id = self._get_redis_shard_id(redis_key)
        shard = self._redis_shards[shard_id]
        result = await self._redis_with_retry(shard, shard.delete, redis_key)

        if result is _SENTINEL:
            logger.error(
                "Failed to delete Redis key %s on shard %r, backgrounding...",
                key,
                shard,
            )

            async def background_delete() -> None:
                await shard.delete(redis_key)
                logger.warning(
                    "Successfully background deleted Redis key %s on shard %r",
                    key,
                    shard,
                )

            run_in_background(background_delete)
