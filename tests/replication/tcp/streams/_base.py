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
        server = server_factory.buildProtocol(None)

        # build a replication client, with a dummy handler
        self.test_handler = TestReplicationClientHandler()
        self.client = ClientReplicationStreamProtocol(
            "client", "test", clock, self.test_handler
        )

        # wire them together
        self.client.makeConnection(FakeTransport(server, reactor))
        server.makeConnection(FakeTransport(self.client, reactor))

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
        self.received_rdata_rows = []

    def get_streams_to_replicate(self):
        return {}

    def get_currently_syncing_users(self):
        return []

    def update_connection(self, connection):
        pass

    def finished_connecting(self):
        pass

    def on_rdata(self, stream_name, token, rows):
        for r in rows:
            self.received_rdata_rows.append((stream_name, token, r))
