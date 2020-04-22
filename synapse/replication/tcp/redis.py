# -*- coding: utf-8 -*-
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
from typing import TYPE_CHECKING

import txredisapi

from synapse.logging.context import PreserveLoggingContext
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.tcp.commands import (
    Command,
    ReplicateCommand,
    parse_command_from_line,
)
from synapse.replication.tcp.protocol import (
    AbstractConnection,
    tcp_inbound_commands,
    tcp_outbound_commands,
)

if TYPE_CHECKING:
    from synapse.replication.tcp.handler import ReplicationCommandHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RedisSubscriber(txredisapi.SubscriberProtocol, AbstractConnection):
    """Connection to redis subscribed to replication stream.

    Parses incoming messages from redis into replication commands, and passes
    them to `ReplicationCommandHandler`

    Due to the vagaries of `txredisapi` we don't want to have a custom
    constructor, so instead we expect the defined attributes below to be set
    immediately after initialisation.

    Attributes:
        handler: The command handler to handle incoming commands.
        stream_name: The *redis* stream name to subscribe to (not anything to
            do with Synapse replication streams).
        outbound_redis_connection: The connection to redis to use to send
            commands.
    """

    handler = None  # type: ReplicationCommandHandler
    stream_name = None  # type: str
    outbound_redis_connection = None  # type: txredisapi.RedisProtocol

    def connectionMade(self):
        logger.info("Connected to redis instance")
        self.subscribe(self.stream_name)
        self.send_command(ReplicateCommand())

        self.handler.new_connection(self)

    def messageReceived(self, pattern: str, channel: str, message: str):
        """Received a message from redis.
        """

        if message.strip() == "":
            # Ignore blank lines
            return

        try:
            cmd = parse_command_from_line(message)
        except Exception:
            logger.exception(
                "[%s] failed to parse line: %r", message,
            )
            return

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_inbound_commands.labels(cmd.NAME, "redis").inc()

        # Now lets try and call on_<CMD_NAME> function
        run_as_background_process(
            "replication-" + cmd.get_logcontext_id(), self.handle_command, cmd
        )

    async def handle_command(self, cmd: Command):
        """Handle a command we have received over the replication stream.

        By default delegates to on_<COMMAND>, which should return an awaitable.

        Args:
            cmd: received command
        """
        handled = False

        # First call any command handlers on this instance. These are for redis
        # specific handling.
        cmd_func = getattr(self, "on_%s" % (cmd.NAME,), None)
        if cmd_func:
            await cmd_func(cmd)
            handled = True

        # Then call out to the handler.
        cmd_func = getattr(self.handler, "on_%s" % (cmd.NAME,), None)
        if cmd_func:
            await cmd_func(cmd)
            handled = True

        if not handled:
            logger.warning("Unhandled command: %r", cmd)

    def connectionLost(self, reason):
        logger.info("Lost connection to redis instance")
        self.handler.lost_connection(self)

    def send_command(self, cmd: Command):
        """Send a command if connection has been established.

        Args:
            cmd (Command)
        """
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        # We use "redis" as the name here as we don't have 1:1 connections to
        # remote instances.
        tcp_outbound_commands.labels(cmd.NAME, "redis").inc()

        async def _send():
            with PreserveLoggingContext():
                # Note that we use the other connection as we can't send
                # commands using the subscription connection.
                await self.outbound_redis_connection.publish(
                    self.stream_name, encoded_string
                )

        run_as_background_process("send-cmd", _send)


class RedisDirectTcpReplicationClientFactory(txredisapi.SubscriberFactory):
    """This is a reconnecting factory that connects to redis and immediately
    subscribes to a stream.

    Args:
        hs
        outbound_redis_connection: A connection to redis that will be used to
            send outbound commands (this is seperate to the redis connection
            used to subscribe).
    """

    maxDelay = 5
    continueTrying = True
    protocol = RedisSubscriber

    def __init__(
        self, hs: "HomeServer", outbound_redis_connection: txredisapi.RedisProtocol
    ):

        super().__init__()

        # This sets the password on the RedisFactory base class (as
        # SubscriberFactory constructor doesn't pass it through).
        self.password = hs.config.redis.redis_password

        self.handler = hs.get_tcp_replication()
        self.stream_name = hs.hostname

        self.outbound_redis_connection = outbound_redis_connection

    def buildProtocol(self, addr):
        p = super().buildProtocol(addr)  # type: RedisSubscriber

        # We do this here rather than add to the constructor of `RedisSubcriber`
        # as to do so would involve overriding `buildProtocol` entirely, however
        # the base method does some other things than just instantiating the
        # protocol.
        p.handler = self.handler
        p.outbound_redis_connection = self.outbound_redis_connection
        p.stream_name = self.stream_name

        return p
