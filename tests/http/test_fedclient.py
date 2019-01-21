# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from twisted.internet.defer import TimeoutError
from twisted.internet.error import ConnectingCancelledError, DNSLookupError
from twisted.test.proto_helpers import StringTransport
from twisted.web.client import ResponseNeverReceived
from twisted.web.http import HTTPChannel

from synapse.api.errors import RequestSendFailed
from synapse.http.matrixfederationclient import (
    MatrixFederationHttpClient,
    MatrixFederationRequest,
)

from tests.server import FakeTransport
from tests.unittest import HomeserverTestCase


class FederationClientTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(reactor=reactor, clock=clock)
        hs.tls_client_options_factory = None
        return hs

    def prepare(self, reactor, clock, homeserver):

        self.cl = MatrixFederationHttpClient(self.hs)
        self.reactor.lookups["testserv"] = "1.2.3.4"

    def test_dns_error(self):
        """
        If the DNS lookup returns an error, it will bubble up.
        """
        d = self.cl.get_json("testserv2:8008", "foo/bar", timeout=10000)
        self.pump()

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, DNSLookupError)

    def test_client_never_connect(self):
        """
        If the HTTP request is not connected and is timed out, it'll give a
        ConnectingCancelledError or TimeoutError.
        """
        d = self.cl.get_json("testserv:8008", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        # Deferred is still without a result
        self.assertNoResult(d)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(
            f.value.inner_exception,
            (ConnectingCancelledError, TimeoutError),
        )

    def test_client_connect_no_response(self):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a ResponseNeverReceived.
        """
        d = self.cl.get_json("testserv:8008", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        conn = Mock()
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred is still without a result
        self.assertNoResult(d)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, ResponseNeverReceived)

    def test_client_gets_headers(self):
        """
        Once the client gets the headers, _request returns successfully.
        """
        request = MatrixFederationRequest(
            method="GET",
            destination="testserv:8008",
            path="foo/bar",
        )
        d = self.cl._send_request(request, timeout=10000)

        self.pump()

        conn = Mock()
        clients = self.reactor.tcpClients
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred does not have a result
        self.assertNoResult(d)

        # Send it the HTTP response
        client.dataReceived(b"HTTP/1.1 200 OK\r\nServer: Fake\r\n\r\n")

        # We should get a successful response
        r = self.successResultOf(d)
        self.assertEqual(r.code, 200)

    def test_client_headers_no_body(self):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a ResponseNeverReceived.
        """
        d = self.cl.post_json("testserv:8008", "foo/bar", timeout=10000)

        self.pump()

        conn = Mock()
        clients = self.reactor.tcpClients
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred does not have a result
        self.assertNoResult(d)

        # Send it the HTTP response
        client.dataReceived(
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
             b"Server: Fake\r\n\r\n")
        )

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, TimeoutError)

    def test_client_sends_body(self):
        self.cl.post_json(
            "testserv:8008", "foo/bar", timeout=10000,
            data={"a": "b"}
        )

        self.pump()

        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        client = clients[0][2].buildProtocol(None)
        server = HTTPChannel()

        client.makeConnection(FakeTransport(server, self.reactor))
        server.makeConnection(FakeTransport(client, self.reactor))

        self.pump(0.1)

        self.assertEqual(len(server.requests), 1)
        request = server.requests[0]
        content = request.content.read()
        self.assertEqual(content, b'{"a":"b"}')

    def test_closes_connection(self):
        """Check that the client closes unused HTTP connections"""
        d = self.cl.get_json("testserv:8008", "foo/bar")

        self.pump()

        # there should have been a call to connectTCP
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (_host, _port, factory, _timeout, _bindAddress) = clients[0]

        # complete the connection and wire it up to a fake transport
        client = factory.buildProtocol(None)
        conn = StringTransport()
        client.makeConnection(conn)

        # that should have made it send the request to the connection
        self.assertRegex(conn.value(), b"^GET /foo/bar")

        # Send the HTTP response
        client.dataReceived(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

        # We should get a successful response
        r = self.successResultOf(d)
        self.assertEqual(r, {})

        self.assertFalse(conn.disconnecting)

        # wait for a while
        self.pump(120)

        self.assertTrue(conn.disconnecting)
