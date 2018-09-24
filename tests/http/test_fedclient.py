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
from twisted.web.client import ResponseNeverReceived

from synapse.http.matrixfederationclient import MatrixFederationHttpClient

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
        If the DNS raising returns an error, it will bubble up.
        """
        d = self.cl._request("testserv2:8008", "GET", "foo/bar", timeout=10000)
        self.pump()

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, DNSLookupError)

    def test_client_never_connect(self):
        """
        If the HTTP request is not connected and is timed out, it'll give a
        ConnectingCancelledError or TimeoutError.
        """
        d = self.cl._request("testserv:8008", "GET", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertFalse(d.called)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        # Deferred is still without a result
        self.assertFalse(d.called)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, (ConnectingCancelledError, TimeoutError))

    def test_client_connect_no_response(self):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a ResponseNeverReceived.
        """
        d = self.cl._request("testserv:8008", "GET", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertFalse(d.called)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        conn = Mock()
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred is still without a result
        self.assertFalse(d.called)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, ResponseNeverReceived)

    def test_client_gets_headers(self):
        """
        Once the client gets the headers, _request returns successfully.
        """
        d = self.cl._request("testserv:8008", "GET", "foo/bar", timeout=10000)

        self.pump()

        conn = Mock()
        clients = self.reactor.tcpClients
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred does not have a result
        self.assertFalse(d.called)

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
        self.assertFalse(d.called)

        # Send it the HTTP response
        client.dataReceived(
            (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
             b"Server: Fake\r\n\r\n")
        )

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, TimeoutError)
