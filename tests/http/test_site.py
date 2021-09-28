# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from twisted.internet.address import IPv6Address
from twisted.test.proto_helpers import StringTransport

from synapse.app.homeserver import SynapseHomeServer

from tests.unittest import HomeserverTestCase


class SynapseRequestTestCase(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(homeserver_to_use=SynapseHomeServer)

    def test_large_request(self):
        """overlarge HTTP requests should be rejected"""
        self.hs.start_listening()

        # find the HTTP server which is configured to listen on port 0
        (port, factory, _backlog, interface) = self.reactor.tcpServers[0]
        self.assertEqual(interface, "::")
        self.assertEqual(port, 0)

        # as a control case, first send a regular request.

        # complete the connection and wire it up to a fake transport
        client_address = IPv6Address("TCP", "::1", "2345")
        protocol = factory.buildProtocol(client_address)
        transport = StringTransport()
        protocol.makeConnection(transport)

        protocol.dataReceived(
            b"POST / HTTP/1.1\r\n"
            b"Connection: close\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"0\r\n"
            b"\r\n"
        )

        while not transport.disconnecting:
            self.reactor.advance(1)

        # we should get a 404
        self.assertRegex(transport.value().decode(), r"^HTTP/1\.1 404 ")

        # now send an oversized request
        protocol = factory.buildProtocol(client_address)
        transport = StringTransport()
        protocol.makeConnection(transport)

        protocol.dataReceived(
            b"POST / HTTP/1.1\r\n"
            b"Connection: close\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
        )

        # we deliberately send all the data in one big chunk, to ensure that
        # twisted isn't buffering the data in the chunked transfer decoder.
        # we start with the chunk size, in hex. (We won't actually send this much)
        protocol.dataReceived(b"10000000\r\n")
        sent = 0
        while not transport.disconnected:
            self.assertLess(sent, 0x10000000, "connection did not drop")
            protocol.dataReceived(b"\0" * 1024)
            sent += 1024

        # default max upload size is 50M, so it should drop on the next buffer after
        # that.
        self.assertEqual(sent, 50 * 1024 * 1024 + 1024)
