# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from inspect import isawaitable
from typing import TYPE_CHECKING, Generic, Optional, Type, TypeVar, cast

import attr
import txredisapi
from zope.interface import implementer

from twisted.internet.address import IPv4Address, IPv6Address
from twisted.internet.interfaces import IAddress, IConnector
from twisted.python.failure import Failure

from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.metrics.background_process_metrics import (
    BackgroundProcessLoggingContext,
    run_as_background_process,
    wrap_as_background_process,
)
from synapse.replication.tcp.commands import (
    Command,
    ReplicateCommand,
    parse_command_from_line,
)
from synapse.replication.tcp.protocol import (
    IReplicationConnection,
    tcp_inbound_commands_counter,
    tcp_outbound_commands_counter,
)

if TYPE_CHECKING:
    from synapse.replication.tcp.handler import ReplicationCommandHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

T = TypeVar("T")
V = TypeVar("V")


@attr.s
class ConstantProperty(Generic[T, V]):
    """A descriptor that returns the given constant, ignoring attempts to set
    it.
    """

    constant = attr.ib()  # type: V

    def __get__(self, obj: Optional[T], objtype: Optional[Type[T]] = None) -> V:
        return self.constant

    def __set__(self, obj: Optional[T], value: V):
        pass


@implementer(IReplicationConnection)
class RedisSubscriber(txredisapi.SubscriberProtocol):
    """Connection to redis subscribed to replication stream.

    This class fulfils two functions:

    (a) it implements the twisted Protocol API, where it handles the SUBSCRIBEd redis
    connection, parsing *incoming* messages into replication commands, and passing them
    to `ReplicationCommandHandler`

    (b) it implements the IReplicationConnection API, where it sends *outgoing* commands
    onto outbound_redis_connection.

    Due to the vagaries of `txredisapi` we don't want to have a custom
    constructor, so instead we expect the defined attributes below to be set
    immediately after initialisation.

    Attributes:
        synapse_handler: The command handler to handle incoming commands.
        synapse_stream_name: The *redis* stream name to subscribe to and publish
            from (not anything to do with Synapse replication streams).
        synapse_outbound_redis_connection: The connection to redis to use to send
            commands.
    """

    synapse_handler = None  # type: ReplicationCommandHandler
    synapse_stream_name = None  # type: str
    synapse_outbound_redis_connection = None  # type: txredisapi.RedisProtocol

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # a logcontext which we use for processing incoming commands. We declare it as a
        # background process so that the CPU stats get reported to prometheus.
        self._logging_context = BackgroundProcessLoggingContext(
            "replication_command_handler"
        )

    def connectionMade(self):
        logger.info("Connected to redis")
        super().connectionMade()
        run_as_background_process("subscribe-replication", self._send_subscribe)

    async def _send_subscribe(self):
        # it's important to make sure that we only send the REPLICATE command once we
        # have successfully subscribed to the stream - otherwise we might miss the
        # POSITION response sent back by the other end.
        logger.info("Sending redis SUBSCRIBE for %s", self.synapse_stream_name)
        await make_deferred_yieldable(self.subscribe(self.synapse_stream_name))
        logger.info(
            "Successfully subscribed to redis stream, sending REPLICATE command"
        )
        self.synapse_handler.new_connection(self)
        await self._async_send_command(ReplicateCommand())
        logger.info("REPLICATE successfully sent")

        # We send out our positions when there is a new connection in case the
        # other side missed updates. We do this for Redis connections as the
        # otherside won't know we've connected and so won't issue a REPLICATE.
        self.synapse_handler.send_positions_to_connection(self)

    def messageReceived(self, pattern: str, channel: str, message: str):
        """Received a message from redis."""
        with PreserveLoggingContext(self._logging_context):
            self._parse_and_dispatch_message(message)

    def _parse_and_dispatch_message(self, message: str):
        if message.strip() == "":
            # Ignore blank lines
            return

        try:
            cmd = parse_command_from_line(message)
        except Exception:
            logger.exception(
                "Failed to parse replication line: %r",
                message,
            )
            return

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_inbound_commands_counter.labels(cmd.NAME, "redis").inc()

        self.handle_command(cmd)

    def handle_command(self, cmd: Command) -> None:
        """Handle a command we have received over the replication stream.

        Delegates to `self.handler.on_<COMMAND>` (which can optionally return an
        Awaitable).

        Args:
            cmd: received command
        """

        cmd_func = getattr(self.synapse_handler, "on_%s" % (cmd.NAME,), None)
        if not cmd_func:
            logger.warning("Unhandled command: %r", cmd)
            return

        res = cmd_func(self, cmd)

        # the handler might be a coroutine: fire it off as a background process
        # if so.

        if isawaitable(res):
            run_as_background_process(
                "replication-" + cmd.get_logcontext_id(), lambda: res
            )

    def connectionLost(self, reason):
        logger.info("Lost connection to redis")
        super().connectionLost(reason)
        self.synapse_handler.lost_connection(self)

        # mark the logging context as finished
        self._logging_context.__exit__(None, None, None)

    def send_command(self, cmd: Command):
        """Send a command if connection has been established.

        Args:
            cmd (Command)
        """
        run_as_background_process(
            "send-cmd", self._async_send_command, cmd, bg_start_span=False
        )

    async def _async_send_command(self, cmd: Command):
        """Encode a replication command and send it over our outbound connection"""
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_outbound_commands_counter.labels(cmd.NAME, "redis").inc()

        await make_deferred_yieldable(
            self.synapse_outbound_redis_connection.publish(
                self.synapse_stream_name, encoded_string
            )
        )


class SynapseRedisFactory(txredisapi.RedisFactory):
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
        handler: Type = txredisapi.ConnectionHandler,
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
    async def _send_ping(self):
        for connection in self.pool:
            try:
                await make_deferred_yieldable(connection.ping())
            except Exception:
                logger.warning("Failed to send ping to a redis connection")

    # ReconnectingClientFactory has some logging (if you enable `self.noisy`), but
    # it's rubbish. We add our own here.

    def startedConnecting(self, connector: IConnector):
        logger.info(
            "Connecting to redis server %s", format_address(connector.getDestination())
        )
        super().startedConnecting(connector)

    def clientConnectionFailed(self, connector: IConnector, reason: Failure):
        logger.info(
            "Connection to redis server %s failed: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure):
        logger.info(
            "Connection to redis server %s lost: %s",
            format_address(connector.getDestination()),
            reason.value,
        )
        super().clientConnectionLost(connector, reason)


def format_address(address: IAddress) -> str:
    if isinstance(address, (IPv4Address, IPv6Address)):
        return "%s:%i" % (address.host, address.port)
    return str(address)


class RedisDirectTcpReplicationClientFactory(SynapseRedisFactory):
    """This is a reconnecting factory that connects to redis and immediately
    subscribes to a stream.

    Args:
        hs
        outbound_redis_connection: A connection to redis that will be used to
            send outbound commands (this is separate to the redis connection
            used to subscribe).
    """

    maxDelay = 5
    protocol = RedisSubscriber

    def __init__(
        self, hs: "HomeServer", outbound_redis_connection: txredisapi.RedisProtocol
    ):

        super().__init__(
            hs,
            uuid="subscriber",
            dbid=None,
            poolsize=1,
            replyTimeout=30,
            password=hs.config.redis.redis_password,
        )

        self.synapse_handler = hs.get_tcp_replication()
        self.synapse_stream_name = hs.hostname

        self.synapse_outbound_redis_connection = outbound_redis_connection

    def buildProtocol(self, addr):
        p = super().buildProtocol(addr)
        p = cast(RedisSubscriber, p)

        # We do this here rather than add to the constructor of `RedisSubcriber`
        # as to do so would involve overriding `buildProtocol` entirely, however
        # the base method does some other things than just instantiating the
        # protocol.
        p.synapse_handler = self.synapse_handler
        p.synapse_outbound_redis_connection = self.synapse_outbound_redis_connection
        p.synapse_stream_name = self.synapse_stream_name

        return p


def lazyConnection(
    hs: "HomeServer",
    host: str = "localhost",
    port: int = 6379,
    dbid: Optional[int] = None,
    reconnect: bool = True,
    password: Optional[str] = None,
    replyTimeout: int = 30,
) -> txredisapi.RedisProtocol:
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
        handler=txredisapi.ConnectionHandler,
        password=password,
        replyTimeout=replyTimeout,
    )
    factory.continueTrying = reconnect

    reactor = hs.get_reactor()
    reactor.connectTCP(host.encode(), port, factory, timeout=30, bindAddress=None)

    return factory.handler
