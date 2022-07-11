from typing import Any, Generic, Optional, Union, TYPE_CHECKING
from functools import wraps

from synapse.util.caches.lrucache import KT, VT, AsyncLruCache, T

if TYPE_CHECKING:
    from synapse.replication.tcp.external_sharded_cache import ExternalShardedCache


def redisCachedList(redis_shard_cache, cache_name, list_name):
    def decorator(f):
        @wraps(f)
        async def _wrapped(**kwargs):
            keys = kwargs[list_name]
            values = await redis_shard_cache.mget(cache_name, keys)

            missing_keys = set(keys) - set(values.keys())
            kwargs[list_name] = missing_keys
            missing_values = await f(**kwargs)
            await redis_shard_cache.mset(cache_name, missing_values)

            values.update(missing_values)
            return values
        return _wrapped
    return decorator


def _redis_key(key: KT) -> str:
    if isinstance(key, tuple):
        return key[0]
    return f"{key}"


class RedisLruCache(AsyncLruCache, Generic[KT, VT]):
    def __init__(
        self,
        redis_shard_cache: "ExternalShardedCache",
        cache_name: str,
        max_size: int,
    ):
        super().__init__(cache_name=cache_name, max_size=max_size)
        self.cache_name = cache_name
        self.redis_shard_cache = redis_shard_cache

    async def get(
        self, key: KT, default: Optional[T] = None, update_metrics: bool = True
    ) -> Union[None, VT, T]:
        local_value = await super().get(
            key, default=default, update_metrics=update_metrics
        )
        if local_value is not default:
            return local_value

        redis_value = await self.redis_shard_cache.get(self.cache_name, _redis_key(key))
        if redis_value:
            await super().set(key, redis_value)
            return redis_value

        return default

    async def set(self, key: KT, value: Any) -> None:
        await self.redis_shard_cache.set(self.cache_name, _redis_key(key), value)
        await super().set(key, value)

    async def invalidate(self, key: KT) -> None:
        await self.redis_shard_cache.delete(self.cache_name, _redis_key(key))
        await super().invalidate(key)

    async def contains(self, key: KT) -> bool:
        if await super().contains(key):
            return True

        if await self.redis_shard_cache.contains(self.cache_name, _redis_key(key)):
            return True

        return False
