import logging
from functools import wraps
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Union,
    cast,
)

from synapse.util.caches.lrucache import KT, VT, AsyncLruCache, T

if TYPE_CHECKING:
    from synapse.replication.tcp.external_sharded_cache import ExternalShardedCache
    from synapse.util.caches.descriptors import CachedFunction

logger = logging.getLogger(__name__)

sentinel = object()


def _redis_key(key: KT) -> str:
    if isinstance(key, tuple):
        if len(key) == 1:
            return key[0]
        return "".join(map(str, key))
    return f"{key}"


def redisCachedList(
    redis_shard_cache: "ExternalShardedCache",
    cache_name: str,
    list_name: str,
) -> Callable:
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def _wrapped(**kwargs: Any) -> Dict[str, Any]:
            keys: List[str] = kwargs[list_name]
            values = await redis_shard_cache.mget(cache_name, keys)

            missing_keys = list(set(keys) - set(values.keys()))
            kwargs[list_name] = missing_keys
            missing_values = await f(**kwargs)
            await redis_shard_cache.mset(cache_name, missing_values)

            values.update(missing_values)
            return values

        return _wrapped

    return decorator


def redisCached(
    redis_shard_cache: "ExternalShardedCache",
    get_cache_key: Callable,
    cache_name: str,
) -> Callable:
    def decorator(f: Callable) -> "CachedFunction":
        @wraps(f)
        async def _wrapped(self: Any, *args: Any, **kwargs: Any) -> Any:
            cache_key = _redis_key(get_cache_key(args, kwargs))
            value = await redis_shard_cache.get(
                cache_name,
                cache_key,
                default=sentinel,
            )

            if value is sentinel:
                value = await f(self, *args, **kwargs)
                await redis_shard_cache.set(cache_name, cache_key, value)
            return value

        async def _invalidate(key: KT) -> None:
            return await redis_shard_cache.delete(
                cache_name,
                _redis_key(key),
            )

        wrapped = cast("CachedFunction", _wrapped)
        wrapped.invalidate = _invalidate
        return wrapped

    return decorator


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

        return await self.get_external(key, default, update_metrics=update_metrics)

    async def get_external(
        self,
        key: KT,
        default: Optional[T] = None,
        update_metrics: bool = True,
    ) -> Union[None, VT, T]:
        value = await self.redis_shard_cache.get(self.cache_name, _redis_key(key))
        if value is not default:
            self.set_local(key, value)
            return value
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
