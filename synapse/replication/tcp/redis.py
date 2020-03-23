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

import txredisapi

from synapse.logging.context import PreserveLoggingContext
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.replication.tcp.commands import (
    COMMAND_MAP,
    Command,
    RdataCommand,
    ReplicateCommand,
)
from synapse.util.stringutils import random_string

logger = logging.getLogger(__name__)


class RedisSubscriber(txredisapi.SubscriberProtocol):
    """Connection to redis subscribed to replication stream.
    """

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

        line = message
        cmd_name, rest_of_line = line.split(" ", 1)

        cmd_cls = COMMAND_MAP[cmd_name]
        try:
            cmd = cmd_cls.from_line(rest_of_line)
        except Exception as e:
            logger.exception(
                "[%s] failed to parse line %r: %r", self.id(), cmd_name, rest_of_line
            )
            self.send_error(
                "failed to parse line for  %r: %r (%r):" % (cmd_name, e, rest_of_line)
            )
            return

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

    def send_command(self, cmd):
        """Send a command if connection has been established.

        Args:
            cmd (Command)
        """
        string = "%s %s" % (cmd.NAME, cmd.to_line())
        if "\n" in string:
            raise Exception("Unexpected newline in command: %r", string)

        encoded_string = string.encode("utf-8")

        async def _send():
            with PreserveLoggingContext():
                await self.redis_connection.publish(self.stream_name, encoded_string)

        run_as_background_process("send-cmd", _send)

    def stream_update(self, stream_name, token, data):
        """Called when a new update is available to stream to clients.

        We need to check if the client is interested in the stream or not
        """
        self.send_command(RdataCommand(stream_name, token, data))


class RedisFactory(txredisapi.SubscriberFactory):
    """This is a reconnecting factory that connects to redis and immediately
    subscribes to a stream.
    """

    maxDelay = 5
    continueTrying = True
    protocol = RedisSubscriber

    def __init__(self, hs):
        super(RedisFactory, self).__init__()

        self.password = hs.config.redis.redis_password

        self.handler = hs.get_tcp_replication()
        self.stream_name = hs.hostname

        self.redis_connection = txredisapi.lazyConnection(
            host=hs.config.redis_host,
            port=hs.config.redis_port,
            dbid=hs.config.redis_dbid,
            password=hs.config.redis.redis_password,
            reconnect=True,
        )

        self.conn_id = random_string(5)

    def buildProtocol(self, addr):
        p = super(RedisFactory, self).buildProtocol(addr)
        p.handler = self.handler
        p.redis_connection = self.redis_connection
        p.conn_id = self.conn_id
        p.stream_name = self.stream_name
        return p
