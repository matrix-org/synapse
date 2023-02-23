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

import logging
from typing import TYPE_CHECKING, Any, Generic, Optional, Type, TypeVar, cast

import attr
from txredisapi import (  # type: ignore[attr-defined]
    ConnectionHandler,
    RedisFactory,
    Sentinel,
)
from zope.interface import Interface, implementer

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.interfaces import IAddress, IConnector
from twisted.python.failure import Failure

from synapse.logging.context import make_deferred_yieldable
from synapse.metrics.background_process_metrics import wrap_as_background_process

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class IRedisConnection(Interface):
    def set(
        key: str,
        value: str,
        expire: Any = None,
        pexpire: Any = None,
        only_if_not_exists: bool = False,
        only_if_exists: bool = False,
    ) -> Any:
        """Store value on the designated key"""

    def get(key: str) -> Any:
        """Retrieve the value"""

    def publish(channel: Any, message: Any) -> Any:
        """Publish"""


T = TypeVar("T")
V = TypeVar("V")


@attr.s
class ConstantProperty(Generic[T, V]):
    """A descriptor that returns the given constant, ignoring attempts to set
    it.
    """

    constant: V = attr.ib()

    def __get__(self, obj: Optional[T], objtype: Optional[Type[T]] = None) -> V:
        return self.constant

    def __set__(self, obj: Optional[T], value: V) -> None:
        pass


def format_address(address: IAddress) -> str:
    if isinstance(address, (IPv4Address, IPv6Address)):
        return "%s:%i" % (address.host, address.port)
    return str(address)


class SynapseRedisFactory(RedisFactory):
    """A subclass of RedisFactory that periodically sends pings to ensure that
    we detect dead connections.
    """

    # We want to *always* retry connecting, txredisapi will stop if there is a
    # failure during certain operations, e.g. during AUTH.
    continueTrying = cast(bool, ConstantProperty(True))

    def __init__(
        self,
        hs: "HomeServer",
        uuid: str,
        dbid: Optional[int],
        poolsize: int,
        isLazy: bool = False,
        handler: Type = ConnectionHandler,
        charset: str = "utf-8",
        password: Optional[str] = None,
        replyTimeout: int = 30,
        convertNumbers: Optional[int] = True,
    ):
        super().__init__(
            uuid=uuid,
            dbid=dbid,
            poolsize=poolsize,
            isLazy=isLazy,
            handler=handler,
            charset=charset,
            password=password,
            replyTimeout=replyTimeout,
            convertNumbers=convertNumbers,
        )

        hs.get_clock().looping_call(self._send_ping, 30 * 1000)

    @wrap_as_background_process("redis_ping")
    async def _send_ping(self) -> None:
        for connection in self.pool:
            try:
                await make_deferred_yieldable(connection.ping())
            except Exception:
                logger.warning("Failed to send ping to a redis connection")

    # ReconnectingClientFactory has some logging (if you enable `self.noisy`), but
    # it's rubbish. We add our own here.

    def startedConnecting(self, connector: IConnector) -> None:
        logger.info(
            "Connecting to redis server %s", format_address(connector.getDestination())
        )
        super().startedConnecting(connector)

    def clientConnectionFailed(self, connector: IConnector, reason: Failure) -> None:
        logger.info(
            "Connection to redis server %s failed: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure) -> None:
        logger.info(
            "Connection to redis server %s lost: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionLost(connector, reason)


@implementer(IRedisConnection)
class RedisConnection:
    def __init__(
        self,
        hs: "HomeServer",
        host: str = "localhost",
        port: int = 6379,
        dbid: Optional[int] = None,
        reconnect: bool = True,
        password: Optional[str] = None,
        replyTimeout: int = 30,
    ):
        """Creates a connection to Redis that is lazily set up and reconnects if the
        connections is lost.
        """
        uuid = "%s:%d" % (host, port)
        factory = SynapseRedisFactory(
            hs,
            uuid=uuid,
            dbid=dbid,
            poolsize=1,
            isLazy=True,
            handler=ConnectionHandler,
            password=password,
            replyTimeout=replyTimeout,
        )
        factory.continueTrying = reconnect

        reactor = hs.get_reactor()
        reactor.connectTCP(
            host,
            port,
            factory,
            timeout=30,
            bindAddress=None,
        )

        self.handler = factory.handler

    def get(self, key: str) -> Any:
        return self.handler.get(key)

    def set(
        self,
        key: str,
        value: str,
        expire: Any = None,
        pexpire: Any = None,
        only_if_not_exists: bool = False,
        only_if_exists: bool = False,
    ) -> Any:
        return self.handler.set(
            key, value, expire, pexpire, only_if_not_exists, only_if_exists
        )

    def publish(self, channel: Any, message: Any) -> Any:
        return self.handler.publish(channel, message)


@implementer(IRedisConnection)
class SentinelRedisConnection:
    def __init__(
        self,
        hs: "HomeServer",
        sentinels: list,
        service_name: str,
        dbid: Optional[int] = None,
        reconnect: bool = True,
        password: Optional[str] = None,
        replyTimeout: int = 30,
    ):
        self.service_name = service_name
        self.password = password
        self.sentinel = Sentinel(sentinels)
        self.dbid = dbid
        self.replyTimeout = replyTimeout

    def _get_master(self) -> ConnectionHandler:
        return self.sentinel.master_for(
            self.service_name,
            dbid=self.dbid,
            poolsize=1,
            isLazy=True,
            replyTimeout=self.replyTimeout,
            password=self.password,
        )

    def _get_slave(self) -> ConnectionHandler:
        return self.sentinel.master_for(
            self.service_name,
            dbid=self.dbid,
            poolsize=1,
            isLazy=True,
            replyTimeout=self.replyTimeout,
            password=self.password,
        )

    def get(self, key: str) -> Any:
        return self._get_slave().get(key)

    def set(
        self,
        key: str,
        value: str,
        expire: Any = None,
        pexpire: Any = None,
        only_if_not_exists: bool = False,
        only_if_exists: bool = False,
    ) -> Any:
        return self._get_master().set(
            key, value, expire, pexpire, only_if_not_exists, only_if_exists
        )

    def publish(self, channel: Any, message: Any) -> Any:
        return self._get_master().publish(channel, message)
