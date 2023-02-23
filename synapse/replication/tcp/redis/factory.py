# Copyright 2023 The Matrix.org Foundation C.I.C
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
