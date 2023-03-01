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
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, List, cast

from txredisapi import (  # type: ignore[attr-defined]
    Sentinel,
    SentinelConnectionFactory,
    SentinelRedisProtocol,
    SubscriberProtocol,
)
from zope.interface import implementer

from twisted.internet.interfaces import IAddress
from twisted.python.failure import Failure

from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.metrics.background_process_metrics import (
    BackgroundProcessLoggingContext,
    run_as_background_process,
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
from synapse.replication.tcp.redis.connection import (
    IRedisConnection,
    SentinelRedisConnection,
    SynapseRedisFactory,
)

if TYPE_CHECKING:
    from synapse.replication.tcp.handler import ReplicationCommandHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@implementer(IReplicationConnection)
class RedisSubscriberHelper(SubscriberProtocol):
    """
    Attributes:
     synapse_handler: The command handler to handle incoming commands.
     synapse_stream_prefix: The *redis* stream name to subscribe to and publish
         from (not anything to do with Synapse replication streams).
     synapse_outbound_redis_connection: The connection to redis to use to send
         commands.

    """

    synapse_handler: "ReplicationCommandHandler"
    synapse_stream_prefix: str
    synapse_channel_names: List[str]
    synapse_outbound_redis_connection: IRedisConnection

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self.setLoggingContext()

    def setLoggingContext(self) -> None:
        # a logcontext which we use for processing incoming commands. We declare it as a
        # background process so that the CPU stats get reported to prometheus.
        with PreserveLoggingContext():
            # thanks to `PreserveLoggingContext()`, the new logcontext is guaranteed to
            # capture the sentinel context as its containing context and won't prevent
            # GC of / unintentionally reactivate what would be the current context.
            self._logging_context = BackgroundProcessLoggingContext(
                "replication_command_handler"
            )

    async def _send_subscribe(self) -> None:
        # it's important to make sure that we only send the REPLICATE command once we
        # have successfully subscribed to the stream - otherwise we might miss the
        # POSITION response sent back by the other end.
        fully_qualified_stream_names = [
            f"{self.synapse_stream_prefix}/{stream_suffix}"
            for stream_suffix in self.synapse_channel_names
        ] + [self.synapse_stream_prefix]
        logger.info("Sending redis SUBSCRIBE for %r", fully_qualified_stream_names)
        await make_deferred_yieldable(self.sub(fully_qualified_stream_names))

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

    def sub(self, stream_names: List[str]) -> Any:
        ...

    def _parse_and_dispatch_message(self, message: str) -> None:
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

    def send_command(self, cmd: Command) -> None:
        """Send a command if connection has been established.

        Args:
            cmd: The command to send
        """
        run_as_background_process(
            "send-cmd",
            lambda cmd: RedisSubscriberHelper._async_send_command(self, cmd),
            cmd,
            bg_start_span=False,
        )

    async def _async_send_command(self, cmd: Command) -> None:
        """Encode a replication command and send it over our outbound connection"""
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_outbound_commands_counter.labels(cmd.NAME, "redis").inc()

        channel_name = cmd.redis_channel_name(self.synapse_stream_prefix)

        await make_deferred_yieldable(
            self.synapse_outbound_redis_connection.publish(channel_name, encoded_string)
        )


class RedisSubscriber(RedisSubscriberHelper):
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
    """

    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    def connectionMade(self) -> None:
        logger.info("Connected to redis")
        super().connectionMade()
        run_as_background_process(
            "subscribe-replication", lambda: RedisSubscriberHelper._send_subscribe(self)
        )

    def messageReceived(self, pattern: str, channel: str, message: str) -> None:
        """Received a message from redis."""
        with PreserveLoggingContext(self._logging_context):
            RedisSubscriberHelper._parse_and_dispatch_message(self, message)

    def connectionLost(self, reason: Failure) -> None:  # type: ignore[override]
        logger.info("Lost connection to redis")
        super().connectionLost(reason)
        self.synapse_handler.lost_connection(self)

        # mark the logging context as finished by triggering `__exit__()`
        with PreserveLoggingContext():
            with self._logging_context:
                pass
            # the sentinel context is now active, which may not be correct.
            # PreserveLoggingContext() will restore the correct logging context.

    def sub(self, stream_names: List[str]) -> Any:
        return self.subscribe(stream_names)


class SentinelRedisSubscriber(
    RedisSubscriberHelper,
    SentinelRedisProtocol,
):
    def __init__(self, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

    def connectionMade(self) -> None:
        logger.info("Connected to redis")
        super().connectionMade()
        run_as_background_process(
            "subscribe-replication", lambda: RedisSubscriberHelper._send_subscribe(self)
        )

    def messageReceived(self, pattern: str, channel: str, message: str) -> None:
        """Received a message from redis."""
        with PreserveLoggingContext(self._logging_context):
            RedisSubscriberHelper._parse_and_dispatch_message(self, message)

    def connectionLost(self, reason: Failure) -> None:  # type: ignore[override]
        logger.info("Lost connection to redis")
        super().connectionLost(reason)
        self.synapse_handler.lost_connection(self)

        # mark the logging context as finished by triggering `__exit__()`
        with PreserveLoggingContext():
            with self._logging_context:
                pass
            # the sentinel context is now active, which may not be correct.
            # PreserveLoggingContext() will restore the correct logging context.

    def sub(self, stream_names: List[str]) -> Any:
        return self.subscribe(stream_names)


class RedisReplicationFactory(SynapseRedisFactory):
    """This is a reconnecting factory that connects to redis and immediately
    subscribes to some streams.

    Args:
        hs
        outbound_redis_connection: A connection to redis that will be used to
            send outbound commands (this is separate to the redis connection
            used to subscribe).
        channel_names: A list of channel names to append to the base channel name
            to additionally subscribe to.
            e.g. if ['ABC', 'DEF'] is specified then we'll listen to:
            example.com; example.com/ABC; and example.com/DEF.
    """

    maxDelay = 5
    protocol = RedisSubscriber

    def __init__(
        self,
        hs: "HomeServer",
        outbound_redis_connection: IRedisConnection,
        channel_names: List[str],
    ):
        super().__init__(
            hs,
            uuid="subscriber",
            dbid=None,
            poolsize=1,
            replyTimeout=30,
            password=hs.config.redis.redis_password,
        )

        self.synapse_handler = hs.get_replication_command_handler()
        self.synapse_stream_prefix = hs.hostname
        self.synapse_channel_names = channel_names

        self.synapse_outbound_redis_connection = outbound_redis_connection

    def buildProtocol(self, addr: IAddress) -> RedisSubscriber:
        p = super().buildProtocol(addr)
        p = cast(RedisSubscriber, p)

        # We do this here rather than add to the constructor of `RedisSubcriber`
        # as to do so would involve overriding `buildProtocol` entirely, however
        # the base method does some other things than just instantiating the
        # protocol.
        p.synapse_handler = self.synapse_handler
        p.synapse_outbound_redis_connection = self.synapse_outbound_redis_connection
        p.synapse_stream_prefix = self.synapse_stream_prefix
        p.synapse_channel_names = self.synapse_channel_names

        return p


class RedisSentinelReplicationFactory(SentinelConnectionFactory):
    maxDelay = 5
    protocol = SentinelRedisSubscriber

    def __init__(
        self,
        hs: "HomeServer",
        sentinel_manager: "Sentinel",
        service_name: str,
        is_master: bool,
        outbound_redis_connection: SentinelRedisConnection,
        channel_names: List[str],
        **connection_kwargs: Any,
    ):
        super().__init__(
            sentinel_manager,
            service_name,
            is_master,
            uuid="subscriber",
            dbid=None,
            poolsize=1,
            **connection_kwargs,
        )

        self.synapse_handler = hs.get_replication_command_handler()
        self.synapse_stream_prefix = hs.hostname
        self.synapse_channel_names = channel_names

        self.synapse_outbound_redis_connection = outbound_redis_connection

    def buildProtocol(self, addr: IAddress) -> SentinelRedisSubscriber:
        p = super().buildProtocol(addr)
        p = cast(SentinelRedisSubscriber, p)

        p.password = self.synapse_outbound_redis_connection.password
        # We do this here rather than add to the constructor of `RedisSubcriber`
        # as to do so would involve overriding `buildProtocol` entirely, however
        # the base method does some other things than just instantiating the
        # protocol.
        p.synapse_handler = self.synapse_handler
        p.synapse_outbound_redis_connection = self.synapse_outbound_redis_connection
        p.synapse_stream_prefix = self.synapse_stream_prefix
        p.synapse_channel_names = self.synapse_channel_names

        return p
