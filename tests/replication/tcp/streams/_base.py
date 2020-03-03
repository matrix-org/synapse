# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from mock import Mock

from synapse.replication.tcp.commands import ReplicateCommand
from synapse.replication.tcp.protocol import ClientReplicationStreamProtocol
from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory

from tests import unittest
from tests.server import FakeTransport


class BaseStreamTestCase(unittest.HomeserverTestCase):
    """Base class for tests of the replication streams"""

    def prepare(self, reactor, clock, hs):
        # build a replication server
        server_factory = ReplicationStreamProtocolFactory(self.hs)
        self.streamer = server_factory.streamer
        self.server = server_factory.buildProtocol(None)

        self.test_handler = Mock(wraps=TestReplicationClientHandler())
        self.client = ClientReplicationStreamProtocol(
            hs, "client", "test", clock, self.test_handler,
        )

        self._client_transport = None
        self._server_transport = None

    def reconnect(self):
        if self._client_transport:
            self.client.close()

        if self._server_transport:
            self.server.close()

        self._client_transport = FakeTransport(self.server, self.reactor)
        self.client.makeConnection(self._client_transport)

        self._server_transport = FakeTransport(self.client, self.reactor)
        self.server.makeConnection(self._server_transport)

    def disconnect(self):
        if self._client_transport:
            self._client_transport = None
            self.client.close()

        if self._server_transport:
            self._server_transport = None
            self.server.close()

    def replicate(self):
        """Tell the master side of replication that something has happened, and then
        wait for the replication to occur.
        """
        self.streamer.on_notifier_poke()
        self.pump(0.1)

    def replicate_stream(self, stream, token="NOW"):
        """Make the client end a REPLICATE command to set up a subscription to a stream"""
        self.client.send_command(ReplicateCommand(stream, token))


class TestReplicationClientHandler(object):
    """Drop-in for ReplicationClientHandler which just collects RDATA rows"""

    def __init__(self):
        self.streams = set()
        self._received_rdata_rows = []

    def get_streams_to_replicate(self):
        positions = {s: 0 for s in self.streams}
        for stream, token, _ in self._received_rdata_rows:
            if stream in self.streams:
                positions[stream] = max(token, positions.get(stream, 0))
        return positions

    def get_currently_syncing_users(self):
        return []

    def update_connection(self, connection):
        pass

    def finished_connecting(self):
        pass

    async def on_position(self, stream_name, token):
        """Called when we get new position data."""

    async def on_rdata(self, stream_name, token, rows):
        for r in rows:
            self._received_rdata_rows.append((stream_name, token, r))
