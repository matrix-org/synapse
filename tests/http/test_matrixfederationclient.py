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

from unittest.mock import Mock

from netaddr import IPSet
from parameterized import parameterized

from twisted.internet import defer
from twisted.internet.defer import TimeoutError
from twisted.internet.error import ConnectingCancelledError, DNSLookupError
from twisted.test.proto_helpers import StringTransport
from twisted.web.client import ResponseNeverReceived
from twisted.web.http import HTTPChannel

from synapse.api.errors import RequestSendFailed
from synapse.http.matrixfederationclient import (
    JsonParser,
    MatrixFederationHttpClient,
    MatrixFederationRequest,
)
from synapse.logging.context import SENTINEL_CONTEXT, LoggingContext, current_context

from tests.server import FakeTransport
from tests.unittest import HomeserverTestCase


def check_logcontext(context):
    current = current_context()
    if current is not context:
        raise AssertionError("Expected logcontext %s but was %s" % (context, current))


class FederationClientTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(reactor=reactor, clock=clock)
        return hs

    def prepare(self, reactor, clock, homeserver):
        self.cl = MatrixFederationHttpClient(self.hs, None)
        self.reactor.lookups["testserv"] = "1.2.3.4"

    def test_client_get(self):
        """
        happy-path test of a GET request
        """

        @defer.inlineCallbacks
        def do_request():
            with LoggingContext("one") as context:
                fetch_d = defer.ensureDeferred(
                    self.cl.get_json("testserv:8008", "foo/bar")
                )

                # Nothing happened yet
                self.assertNoResult(fetch_d)

                # should have reset logcontext to the sentinel
                check_logcontext(SENTINEL_CONTEXT)

                try:
                    fetch_res = yield fetch_d
                    return fetch_res
                finally:
                    check_logcontext(context)

        test_d = do_request()

        self.pump()

        # Nothing happened yet
        self.assertNoResult(test_d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8008)

        # complete the connection and wire it up to a fake transport
        protocol = factory.buildProtocol(None)
        transport = StringTransport()
        protocol.makeConnection(transport)

        # that should have made it send the request to the transport
        self.assertRegex(transport.value(), b"^GET /foo/bar")
        self.assertRegex(transport.value(), b"Host: testserv:8008")

        # Deferred is still without a result
        self.assertNoResult(test_d)

        # Send it the HTTP response
        res_json = b'{ "a": 1 }'
        protocol.dataReceived(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Fake\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: %i\r\n"
            b"\r\n"
            b"%s" % (len(res_json), res_json)
        )

        self.pump()

        res = self.successResultOf(test_d)

        # check the response is as expected
        self.assertEqual(res, {"a": 1})

    def test_dns_error(self):
        """
        If the DNS lookup returns an error, it will bubble up.
        """
        d = defer.ensureDeferred(
            self.cl.get_json("testserv2:8008", "foo/bar", timeout=10000)
        )
        self.pump()

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, DNSLookupError)

    def test_client_connection_refused(self):
        d = defer.ensureDeferred(
            self.cl.get_json("testserv:8008", "foo/bar", timeout=10000)
        )

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8008)
        e = Exception("go away")
        factory.clientConnectionFailed(None, e)
        self.pump(0.5)

        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIs(f.value.inner_exception, e)

    def test_client_never_connect(self):
        """
        If the HTTP request is not connected and is timed out, it'll give a
        ConnectingCancelledError or TimeoutError.
        """
        d = defer.ensureDeferred(
            self.cl.get_json("testserv:8008", "foo/bar", timeout=10000)
        )

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], "1.2.3.4")
        self.assertEqual(clients[0][1], 8008)

        # Deferred is still without a result
        self.assertNoResult(d)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(
            f.value.inner_exception, (ConnectingCancelledError, TimeoutError)
        )

    def test_client_connect_no_response(self):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a ResponseNeverReceived.
        """
        d = defer.ensureDeferred(
            self.cl.get_json("testserv:8008", "foo/bar", timeout=10000)
        )

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], "1.2.3.4")
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

    def test_client_ip_range_blacklist(self):
        """Ensure that Synapse does not try to connect to blacklisted IPs"""

        # Set up the ip_range blacklist
        self.hs.config.server.federation_ip_range_blacklist = IPSet(
            ["127.0.0.0/8", "fe80::/64"]
        )
        self.reactor.lookups["internal"] = "127.0.0.1"
        self.reactor.lookups["internalv6"] = "fe80:0:0:0:0:8a2e:370:7337"
        self.reactor.lookups["fine"] = "10.20.30.40"
        cl = MatrixFederationHttpClient(self.hs, None)

        # Try making a GET request to a blacklisted IPv4 address
        # ------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(cl.get_json("internal:8008", "foo/bar", timeout=10000))

        # Nothing happened yet
        self.assertNoResult(d)

        self.pump(1)

        # Check that it was unable to resolve the address
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 0)

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, DNSLookupError)

        # Try making a POST request to a blacklisted IPv6 address
        # -------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(
            cl.post_json("internalv6:8008", "foo/bar", timeout=10000)
        )

        # Nothing has happened yet
        self.assertNoResult(d)

        # Move the reactor forwards
        self.pump(1)

        # Check that it was unable to resolve the address
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 0)

        # Check that it was due to a blacklisted DNS lookup
        f = self.failureResultOf(d, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, DNSLookupError)

        # Try making a GET request to a non-blacklisted IPv4 address
        # ----------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(cl.post_json("fine:8008", "foo/bar", timeout=10000))

        # Nothing has happened yet
        self.assertNoResult(d)

        # Move the reactor forwards
        self.pump(1)

        # Check that it was able to resolve the address
        clients = self.reactor.tcpClients
        self.assertNotEqual(len(clients), 0)

        # Connection will still fail as this IP address does not resolve to anything
        f = self.failureResultOf(d, RequestSendFailed)
        self.assertIsInstance(f.value.inner_exception, ConnectingCancelledError)

    def test_client_gets_headers(self):
        """
        Once the client gets the headers, _request returns successfully.
        """
        request = MatrixFederationRequest(
            method="GET", destination="testserv:8008", path="foo/bar"
        )
        d = defer.ensureDeferred(self.cl._send_request(request, timeout=10000))

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

    @parameterized.expand(["get_json", "post_json", "delete_json", "put_json"])
    def test_timeout_reading_body(self, method_name: str):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a RequestSendFailed with can_retry.
        """
        method = getattr(self.cl, method_name)
        d = defer.ensureDeferred(method("testserv:8008", "foo/bar", timeout=10000))

        self.pump()

        conn = Mock()
        clients = self.reactor.tcpClients
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred does not have a result
        self.assertNoResult(d)

        # Send it the HTTP response
        client.dataReceived(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            b"Server: Fake\r\n\r\n"
        )

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestSendFailed)
        self.assertTrue(f.value.can_retry)
        self.assertIsInstance(f.value.inner_exception, defer.TimeoutError)

    def test_client_requires_trailing_slashes(self):
        """
        If a connection is made to a client but the client rejects it due to
        requiring a trailing slash. We need to retry the request with a
        trailing slash. Workaround for Synapse <= v0.99.3, explained in #3622.
        """
        d = defer.ensureDeferred(
            self.cl.get_json("testserv:8008", "foo/bar", try_trailing_slash_on_400=True)
        )

        # Send the request
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

        # Clear the original request data before sending a response
        conn.clear()

        # Send the HTTP response
        client.dataReceived(
            b"HTTP/1.1 400 Bad Request\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 59\r\n"
            b"\r\n"
            b'{"errcode":"M_UNRECOGNIZED","error":"Unrecognized request"}'
        )

        # We should get another request with a trailing slash
        self.assertRegex(conn.value(), b"^GET /foo/bar/")

        # Send a happy response this time
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

    def test_client_does_not_retry_on_400_plus(self):
        """
        Another test for trailing slashes but now test that we don't retry on
        trailing slashes on a non-400/M_UNRECOGNIZED response.

        See test_client_requires_trailing_slashes() for context.
        """
        d = defer.ensureDeferred(
            self.cl.get_json("testserv:8008", "foo/bar", try_trailing_slash_on_400=True)
        )

        # Send the request
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

        # Clear the original request data before sending a response
        conn.clear()

        # Send the HTTP response
        client.dataReceived(
            b"HTTP/1.1 404 Not Found\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 2\r\n"
            b"\r\n"
            b"{}"
        )

        # We should not get another request
        self.assertEqual(conn.value(), b"")

        # We should get a 404 failure response
        self.failureResultOf(d)

    def test_client_sends_body(self):
        defer.ensureDeferred(
            self.cl.post_json(
                "testserv:8008", "foo/bar", timeout=10000, data={"a": "b"}
            )
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
        d = defer.ensureDeferred(self.cl.get_json("testserv:8008", "foo/bar"))

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
        self.reactor.advance(120)

        self.assertTrue(conn.disconnecting)

    @parameterized.expand([(b"",), (b"foo",), (b'{"a": Infinity}',)])
    def test_json_error(self, return_value):
        """
        Test what happens if invalid JSON is returned from the remote endpoint.
        """

        test_d = defer.ensureDeferred(self.cl.get_json("testserv:8008", "foo/bar"))

        self.pump()

        # Nothing happened yet
        self.assertNoResult(test_d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8008)

        # complete the connection and wire it up to a fake transport
        protocol = factory.buildProtocol(None)
        transport = StringTransport()
        protocol.makeConnection(transport)

        # that should have made it send the request to the transport
        self.assertRegex(transport.value(), b"^GET /foo/bar")
        self.assertRegex(transport.value(), b"Host: testserv:8008")

        # Deferred is still without a result
        self.assertNoResult(test_d)

        # Send it the HTTP response
        protocol.dataReceived(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Fake\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: %i\r\n"
            b"\r\n"
            b"%s" % (len(return_value), return_value)
        )

        self.pump()

        f = self.failureResultOf(test_d)
        self.assertIsInstance(f.value, RequestSendFailed)

    def test_too_big(self):
        """
        Test what happens if a huge response is returned from the remote endpoint.
        """

        test_d = defer.ensureDeferred(self.cl.get_json("testserv:8008", "foo/bar"))

        self.pump()

        # Nothing happened yet
        self.assertNoResult(test_d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8008)

        # complete the connection and wire it up to a fake transport
        protocol = factory.buildProtocol(None)
        transport = StringTransport()
        protocol.makeConnection(transport)

        # that should have made it send the request to the transport
        self.assertRegex(transport.value(), b"^GET /foo/bar")
        self.assertRegex(transport.value(), b"Host: testserv:8008")

        # Deferred is still without a result
        self.assertNoResult(test_d)

        # Send it a huge HTTP response
        protocol.dataReceived(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Fake\r\n"
            b"Content-Type: application/json\r\n"
            b"\r\n"
        )

        self.pump()

        # should still be waiting
        self.assertNoResult(test_d)

        sent = 0
        chunk_size = 1024 * 512
        while not test_d.called:
            protocol.dataReceived(b"a" * chunk_size)
            sent += chunk_size
            self.assertLessEqual(sent, JsonParser.MAX_RESPONSE_SIZE)

        self.assertEqual(sent, JsonParser.MAX_RESPONSE_SIZE)

        f = self.failureResultOf(test_d)
        self.assertIsInstance(f.value, RequestSendFailed)

        self.assertTrue(transport.disconnecting)

    def test_build_auth_headers_rejects_falsey_destinations(self) -> None:
        with self.assertRaises(ValueError):
            self.cl.build_auth_headers(None, b"GET", b"https://example.com")
        with self.assertRaises(ValueError):
            self.cl.build_auth_headers(b"", b"GET", b"https://example.com")
        with self.assertRaises(ValueError):
            self.cl.build_auth_headers(
                None, b"GET", b"https://example.com", destination_is=b""
            )
        with self.assertRaises(ValueError):
            self.cl.build_auth_headers(
                b"", b"GET", b"https://example.com", destination_is=b""
            )
