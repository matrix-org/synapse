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

from typing import Tuple

from twisted.internet.interfaces import IProtocol
from twisted.test.proto_helpers import StringTransport

from synapse.replication.tcp.resource import ReplicationStreamProtocolFactory

from tests.unittest import HomeserverTestCase


class RemoteServerUpTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.factory = ReplicationStreamProtocolFactory(hs)

    def _make_client(self) -> Tuple[IProtocol, StringTransport]:
        """Create a new direct TCP replication connection"""

        proto = self.factory.buildProtocol(("127.0.0.1", 0))
        transport = StringTransport()
        proto.makeConnection(transport)

        # We can safely ignore the commands received during connection.
        self.pump()
        transport.clear()

        return proto, transport

    def test_relay(self):
        """Test that Synapse will relay REMOTE_SERVER_UP commands to all
        other connections, but not the one that sent it.
        """

        proto1, transport1 = self._make_client()

        # We shouldn't receive an echo.
        proto1.dataReceived(b"REMOTE_SERVER_UP example.com\n")
        self.pump()
        self.assertEqual(transport1.value(), b"")

        # But we should see an echo if we connect another client
        proto2, transport2 = self._make_client()
        proto1.dataReceived(b"REMOTE_SERVER_UP example.com\n")

        self.pump()
        self.assertEqual(transport1.value(), b"")
        self.assertEqual(transport2.value(), b"REMOTE_SERVER_UP example.com\n")
