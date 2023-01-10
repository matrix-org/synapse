from typing import TYPE_CHECKING, List

from txredisapi import RedisFactory, Sentinel  # type: ignore[attr-defined]

from synapse.config.redis import RedisConfig
from synapse.replication.tcp.redis.connection import (
    IRedisConnection,
    RedisConnection,
    SentinelRedisConnection,
)
from synapse.replication.tcp.redis.replication import (
    RedisReplicationFactory,
    RedisSentinelReplicationFactory,
)

if TYPE_CHECKING:
    from synapse.server import HomeServer


def get_redis_connection(hs: "HomeServer", config: RedisConfig) -> "IRedisConnection":
    if config.redis_sentinel_enabled:
        return SentinelRedisConnection(
            hs=hs,
            sentinels=config.redis_sentinels,
            service_name=config.redis_dbid,
            password=config.redis_password,
            reconnect=True,
        )
    else:
        return RedisConnection(
            hs=hs,
            host=config.redis_host,
            port=config.redis_port,
            password=config.redis_password,
            dbid=config.redis_dbid,
            reconnect=True,
        )


def get_replication_factory(
    hs: "HomeServer",
    connection: IRedisConnection,
    channel_names: List[str],
) -> RedisFactory:
    factory: RedisFactory
    if isinstance(connection, SentinelRedisConnection):
        factory = RedisSentinelReplicationFactory(
            hs,
            connection.sentinel,
            connection.service_name,
            True,
            connection,
            channel_names,
        )
        Sentinel._connect_factory_and_return_handler(factory, 1)
    else:
        factory = RedisReplicationFactory(
            hs,
            connection,
            channel_names=channel_names,
        )

        reactor = hs.get_reactor()
        reactor.connectTCP(
            hs.config.redis.redis_host,
            hs.config.redis.redis_port,
            factory,
            timeout=30,
            bindAddress=None,
        )
    return factory
