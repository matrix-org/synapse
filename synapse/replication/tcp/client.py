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
from typing import Dict

from twisted.internet.protocol import ReconnectingClientFactory

from synapse.replication.slave.storage._base import BaseSlavedStore
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol

MYPY = False
if MYPY:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationClientFactory(ReconnectingClientFactory):
    """Factory for building connections to the master. Will reconnect if the
    connection is lost.

    Accepts a handler that will be called when new data is available or data
    is required.
    """

    initialDelay = 0.1
    maxDelay = 1  # Try at least once every N seconds

    def __init__(self, hs: "HomeServer", client_name, command_handler):
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
    """A replication data handler that calls slave data stores.
    """

    def __init__(self, store: BaseSlavedStore):
        self.store = store

    async def on_rdata(self, stream_name: str, token: int, rows: list):
        """Called to handle a batch of replication data with a given stream token.

        By default this just pokes the slave store. Can be overridden in subclasses to
        handle more.

        Args:
            stream_name (str): name of the replication stream for this batch of rows
            token (int): stream token for this batch of rows
            rows (list): a list of Stream.ROW_TYPE objects as returned by
                Stream.parse_row.
        """
        self.store.process_replication_rows(stream_name, token, rows)

    def get_streams_to_replicate(self) -> Dict[str, int]:
        """Called when a new connection has been established and we need to
        subscribe to streams.

        Returns:
            map from stream name to the most recent update we have for
            that stream (ie, the point we want to start replicating from)
        """
        args = self.store.stream_positions()
        user_account_data = args.pop("user_account_data", None)
        room_account_data = args.pop("room_account_data", None)
        if user_account_data:
            args["account_data"] = user_account_data
        elif room_account_data:
            args["account_data"] = room_account_data
        return args

    async def on_position(self, stream_name: str, token: int):
        self.store.process_replication_rows(stream_name, token, [])
