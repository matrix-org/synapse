#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from io import BytesIO
from unittest.mock import Mock

from netaddr import IPSet

from twisted.internet.error import DNSLookupError
from twisted.python.failure import Failure
from twisted.test.proto_helpers import AccumulatingProtocol
from twisted.web.client import Agent, ResponseDone
from twisted.web.iweb import UNKNOWN_LENGTH

from synapse.api.errors import SynapseError
from synapse.http.client import (
    BlacklistingAgentWrapper,
    BlacklistingReactorWrapper,
    BodyExceededMaxSize,
    read_body_with_max_size,
)

from tests.server import FakeTransport, get_clock
from tests.unittest import TestCase


class ReadBodyWithMaxSizeTests(TestCase):
    def _build_response(self, length=UNKNOWN_LENGTH):
        """Start reading the body, returns the response, result and proto"""
        response = Mock(length=length)
        result = BytesIO()
        deferred = read_body_with_max_size(response, result, 6)

        # Fish the protocol out of the response.
        protocol = response.deliverBody.call_args[0][0]
        protocol.transport = Mock()

        return result, deferred, protocol

    def _assert_error(self, deferred, protocol):
        """Ensure that the expected error is received."""
        self.assertIsInstance(deferred.result, Failure)
        self.assertIsInstance(deferred.result.value, BodyExceededMaxSize)
        protocol.transport.abortConnection.assert_called_once()

    def _cleanup_error(self, deferred):
        """Ensure that the error in the Deferred is handled gracefully."""
        called = [False]

        def errback(f):
            called[0] = True

        deferred.addErrback(errback)
        self.assertTrue(called[0])

    def test_no_error(self):
        """A response that is NOT too large."""
        result, deferred, protocol = self._build_response()

        # Start sending data.
        protocol.dataReceived(b"12345")
        # Close the connection.
        protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(result.getvalue(), b"12345")
        self.assertEqual(deferred.result, 5)

    def test_too_large(self):
        """A response which is too large raises an exception."""
        result, deferred, protocol = self._build_response()

        # Start sending data.
        protocol.dataReceived(b"1234567890")

        self.assertEqual(result.getvalue(), b"1234567890")
        self._assert_error(deferred, protocol)
        self._cleanup_error(deferred)

    def test_multiple_packets(self):
        """Data should be accumulated through mutliple packets."""
        result, deferred, protocol = self._build_response()

        # Start sending data.
        protocol.dataReceived(b"12")
        protocol.dataReceived(b"34")
        # Close the connection.
        protocol.connectionLost(Failure(ResponseDone()))

        self.assertEqual(result.getvalue(), b"1234")
        self.assertEqual(deferred.result, 4)

    def test_additional_data(self):
        """A connection can receive data after being closed."""
        result, deferred, protocol = self._build_response()

        # Start sending data.
        protocol.dataReceived(b"1234567890")
        self._assert_error(deferred, protocol)

        # More data might have come in.
        protocol.dataReceived(b"1234567890")

        self.assertEqual(result.getvalue(), b"1234567890")
        self._assert_error(deferred, protocol)
        self._cleanup_error(deferred)

    def test_content_length(self):
        """The body shouldn't be read (at all) if the Content-Length header is too large."""
        result, deferred, protocol = self._build_response(length=10)

        # Deferred shouldn't be called yet.
        self.assertFalse(deferred.called)

        # Start sending data.
        protocol.dataReceived(b"12345")
        self._assert_error(deferred, protocol)
        self._cleanup_error(deferred)

        # The data is never consumed.
        self.assertEqual(result.getvalue(), b"")


class BlacklistingAgentTest(TestCase):
    def setUp(self):
        self.reactor, self.clock = get_clock()

        self.safe_domain, self.safe_ip = b"safe.test", b"1.2.3.4"
        self.unsafe_domain, self.unsafe_ip = b"danger.test", b"5.6.7.8"
        self.allowed_domain, self.allowed_ip = b"allowed.test", b"5.1.1.1"

        # Configure the reactor's DNS resolver.
        for (domain, ip) in (
            (self.safe_domain, self.safe_ip),
            (self.unsafe_domain, self.unsafe_ip),
            (self.allowed_domain, self.allowed_ip),
        ):
            self.reactor.lookups[domain.decode()] = ip.decode()
            self.reactor.lookups[ip.decode()] = ip.decode()

        self.ip_whitelist = IPSet([self.allowed_ip.decode()])
        self.ip_blacklist = IPSet(["5.0.0.0/8"])

    def test_reactor(self):
        """Apply the blacklisting reactor and ensure it properly blocks connections to particular domains and IPs."""
        agent = Agent(
            BlacklistingReactorWrapper(
                self.reactor,
                ip_whitelist=self.ip_whitelist,
                ip_blacklist=self.ip_blacklist,
            ),
        )

        # The unsafe domains and IPs should be rejected.
        for domain in (self.unsafe_domain, self.unsafe_ip):
            self.failureResultOf(
                agent.request(b"GET", b"http://" + domain), DNSLookupError
            )

        # The safe domains IPs should be accepted.
        for domain in (
            self.safe_domain,
            self.allowed_domain,
            self.safe_ip,
            self.allowed_ip,
        ):
            d = agent.request(b"GET", b"http://" + domain)

            # Grab the latest TCP connection.
            (
                host,
                port,
                client_factory,
                _timeout,
                _bindAddress,
            ) = self.reactor.tcpClients[-1]

            # Make the connection and pump data through it.
            client = client_factory.buildProtocol(None)
            server = AccumulatingProtocol()
            server.makeConnection(FakeTransport(client, self.reactor))
            client.makeConnection(FakeTransport(server, self.reactor))
            client.dataReceived(
                b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n"
            )

            response = self.successResultOf(d)
            self.assertEqual(response.code, 200)

    def test_agent(self):
        """Apply the blacklisting agent and ensure it properly blocks connections to particular IPs."""
        agent = BlacklistingAgentWrapper(
            Agent(self.reactor),
            ip_whitelist=self.ip_whitelist,
            ip_blacklist=self.ip_blacklist,
        )

        # The unsafe IPs should be rejected.
        self.failureResultOf(
            agent.request(b"GET", b"http://" + self.unsafe_ip), SynapseError
        )

        # The safe and unsafe domains and safe IPs should be accepted.
        for domain in (
            self.safe_domain,
            self.unsafe_domain,
            self.allowed_domain,
            self.safe_ip,
            self.allowed_ip,
        ):
            d = agent.request(b"GET", b"http://" + domain)

            # Grab the latest TCP connection.
            (
                host,
                port,
                client_factory,
                _timeout,
                _bindAddress,
            ) = self.reactor.tcpClients[-1]

            # Make the connection and pump data through it.
            client = client_factory.buildProtocol(None)
            server = AccumulatingProtocol()
            server.makeConnection(FakeTransport(client, self.reactor))
            client.makeConnection(FakeTransport(server, self.reactor))
            client.dataReceived(
                b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n"
            )

            response = self.successResultOf(d)
            self.assertEqual(response.code, 200)
