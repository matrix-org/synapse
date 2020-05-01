# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
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
"""A replication client for use by synapse workers.
"""

import logging
from typing import TYPE_CHECKING

from twisted.internet.protocol import ReconnectingClientFactory

from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.replication.tcp.handler import ReplicationCommandHandler

logger = logging.getLogger(__name__)


class DirectTcpReplicationClientFactory(ReconnectingClientFactory):
    """Factory for building connections to the master. Will reconnect if the
    connection is lost.

    Accepts a handler that is passed to `ClientReplicationStreamProtocol`.
    """

    initialDelay = 0.1
    maxDelay = 1  # Try at least once every N seconds

    def __init__(
        self,
        hs: "HomeServer",
        client_name: str,
        command_handler: "ReplicationCommandHandler",
    ):
        self.client_name = client_name
        self.command_handler = command_handler
        self.server_name = hs.config.server_name
        self.hs = hs
        self._clock = hs.get_clock()  # As self.clock is defined in super class

        hs.get_reactor().addSystemEventTrigger("before", "shutdown", self.stopTrying)

    def startedConnecting(self, connector):
        logger.info("Connecting to replication: %r", connector.getDestination())

    def buildProtocol(self, addr):
        logger.info("Connected to replication: %r", addr)
        return ClientReplicationStreamProtocol(
            self.hs,
            self.client_name,
            self.server_name,
            self._clock,
            self.command_handler,
        )

    def clientConnectionLost(self, connector, reason):
        logger.error("Lost replication conn: %r", reason)
        ReconnectingClientFactory.clientConnectionLost(self, connector, reason)

    def clientConnectionFailed(self, connector, reason):
        logger.error("Failed to connect to replication: %r", reason)
        ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)


class ReplicationDataHandler:
    """Handles incoming stream updates from replication.

    This instance notifies the slave data store about updates. Can be subclassed
    to handle updates in additional ways.
    """

    def __init__(self, store: BaseSlavedStore):
        self.store = store

    async def on_rdata(
        self, stream_name: str, instance_name: str, token: int, rows: list
    ):
        """Called to handle a batch of replication data with a given stream token.

        By default this just pokes the slave store. Can be overridden in subclasses to
        handle more.

        Args:
            stream_name: name of the replication stream for this batch of rows
            instance_name: the instance that wrote the rows.
            token: stream token for this batch of rows
            rows: a list of Stream.ROW_TYPE objects as returned by Stream.parse_row.
        """
        self.store.process_replication_rows(stream_name, token, rows)

    async def on_position(self, stream_name: str, token: int):
        self.store.process_replication_rows(stream_name, token, [])

    def on_remote_server_up(self, server: str):
        """Called when get a new REMOTE_SERVER_UP command."""
