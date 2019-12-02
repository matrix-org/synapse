# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import logging

import treq

from twisted.internet import interfaces  # noqa: F401
from twisted.internet.protocol import Factory
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.web.http import HTTPChannel

from synapse.http.proxyagent import ProxyAgent

from tests.http import TestServerTLSConnectionFactory, get_test_https_policy
from tests.server import FakeTransport, ThreadedMemoryReactorClock
from tests.unittest import TestCase

logger = logging.getLogger(__name__)

HTTPFactory = Factory.forProtocol(HTTPChannel)


class MatrixFederationAgentTests(TestCase):
    def setUp(self):
        self.reactor = ThreadedMemoryReactorClock()

    def _make_connection(
        self, client_factory, server_factory, ssl=False, expected_sni=None
    ):
        """Builds a test server, and completes the outgoing client connection

        Args:
            client_factory (interfaces.IProtocolFactory): the the factory that the
                application is trying to use to make the outbound connection. We will
                invoke it to build the client Protocol

            server_factory (interfaces.IProtocolFactory): a factory to build the
                server-side protocol

            ssl (bool): If true, we will expect an ssl connection and wrap
                server_factory with a TLSMemoryBIOFactory

            expected_sni (bytes|None): the expected SNI value

        Returns:
            IProtocol: the server Protocol returned by server_factory
        """
        if ssl:
            server_factory = _wrap_server_factory_for_tls(server_factory)

        server_protocol = server_factory.buildProtocol(None)

        # now, tell the client protocol factory to build the client protocol,
        # and wire the output of said protocol up to the server via
        # a FakeTransport.
        #
        # Normally this would be done by the TCP socket code in Twisted, but we are
        # stubbing that out here.
        client_protocol = client_factory.buildProtocol(None)
        client_protocol.makeConnection(
            FakeTransport(server_protocol, self.reactor, client_protocol)
        )

        # tell the server protocol to send its stuff back to the client, too
        server_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, server_protocol)
        )

        if ssl:
            http_protocol = server_protocol.wrappedProtocol
            tls_connection = server_protocol._tlsConnection
        else:
            http_protocol = server_protocol
            tls_connection = None

        # give the reactor a pump to get the TLS juices flowing (if needed)
        self.reactor.advance(0)

        if expected_sni is not None:
            server_name = tls_connection.get_servername()
            self.assertEqual(
                server_name,
                expected_sni,
                "Expected SNI %s but got %s" % (expected_sni, server_name),
            )

        return http_protocol

    def test_http_request(self):
        agent = ProxyAgent(self.reactor)

        self.reactor.lookups["test.com"] = "1.2.3.4"
        d = agent.request(b"GET", b"http://test.com")

        # there should be a pending TCP connection
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 80)

        # make a test server, and wire up the client
        http_server = self._make_connection(
            client_factory, _get_test_protocol_factory()
        )

        # the FakeTransport is async, so we need to pump the reactor
        self.reactor.advance(0)

        # now there should be a pending request
        self.assertEqual(len(http_server.requests), 1)

        request = http_server.requests[0]
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.path, b"/")
        self.assertEqual(request.requestHeaders.getRawHeaders(b"host"), [b"test.com"])
        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")

    def test_https_request(self):
        agent = ProxyAgent(self.reactor, contextFactory=get_test_https_policy())

        self.reactor.lookups["test.com"] = "1.2.3.4"
        d = agent.request(b"GET", b"https://test.com/abc")

        # there should be a pending TCP connection
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 443)

        # make a test server, and wire up the client
        http_server = self._make_connection(
            client_factory,
            _get_test_protocol_factory(),
            ssl=True,
            expected_sni=b"test.com",
        )

        # the FakeTransport is async, so we need to pump the reactor
        self.reactor.advance(0)

        # now there should be a pending request
        self.assertEqual(len(http_server.requests), 1)

        request = http_server.requests[0]
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.path, b"/abc")
        self.assertEqual(request.requestHeaders.getRawHeaders(b"host"), [b"test.com"])
        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")

    def test_http_request_via_proxy(self):
        agent = ProxyAgent(self.reactor, http_proxy=b"proxy.com:8888")

        self.reactor.lookups["proxy.com"] = "1.2.3.5"
        d = agent.request(b"GET", b"http://test.com")

        # there should be a pending TCP connection
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.5")
        self.assertEqual(port, 8888)

        # make a test server, and wire up the client
        http_server = self._make_connection(
            client_factory, _get_test_protocol_factory()
        )

        # the FakeTransport is async, so we need to pump the reactor
        self.reactor.advance(0)

        # now there should be a pending request
        self.assertEqual(len(http_server.requests), 1)

        request = http_server.requests[0]
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.path, b"http://test.com")
        self.assertEqual(request.requestHeaders.getRawHeaders(b"host"), [b"test.com"])
        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")

    def test_https_request_via_proxy(self):
        agent = ProxyAgent(
            self.reactor,
            contextFactory=get_test_https_policy(),
            https_proxy=b"proxy.com",
        )

        self.reactor.lookups["proxy.com"] = "1.2.3.5"
        d = agent.request(b"GET", b"https://test.com/abc")

        # there should be a pending TCP connection
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.5")
        self.assertEqual(port, 1080)

        # make a test HTTP server, and wire up the client
        proxy_server = self._make_connection(
            client_factory, _get_test_protocol_factory()
        )

        # fish the transports back out so that we can do the old switcheroo
        s2c_transport = proxy_server.transport
        client_protocol = s2c_transport.other
        c2s_transport = client_protocol.transport

        # the FakeTransport is async, so we need to pump the reactor
        self.reactor.advance(0)

        # now there should be a pending CONNECT request
        self.assertEqual(len(proxy_server.requests), 1)

        request = proxy_server.requests[0]
        self.assertEqual(request.method, b"CONNECT")
        self.assertEqual(request.path, b"test.com:443")

        # tell the proxy server not to close the connection
        proxy_server.persistent = True

        # this just stops the http Request trying to do a chunked response
        # request.setHeader(b"Content-Length", b"0")
        request.finish()

        # now we can replace the proxy channel with a new, SSL-wrapped HTTP channel
        ssl_factory = _wrap_server_factory_for_tls(_get_test_protocol_factory())
        ssl_protocol = ssl_factory.buildProtocol(None)
        http_server = ssl_protocol.wrappedProtocol

        ssl_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, ssl_protocol)
        )
        c2s_transport.other = ssl_protocol

        self.reactor.advance(0)

        server_name = ssl_protocol._tlsConnection.get_servername()
        expected_sni = b"test.com"
        self.assertEqual(
            server_name,
            expected_sni,
            "Expected SNI %s but got %s" % (expected_sni, server_name),
        )

        # now there should be a pending request
        self.assertEqual(len(http_server.requests), 1)

        request = http_server.requests[0]
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.path, b"/abc")
        self.assertEqual(request.requestHeaders.getRawHeaders(b"host"), [b"test.com"])
        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")


def _wrap_server_factory_for_tls(factory, sanlist=None):
    """Wrap an existing Protocol Factory with a test TLSMemoryBIOFactory

    The resultant factory will create a TLS server which presents a certificate
    signed by our test CA, valid for the domains in `sanlist`

    Args:
        factory (interfaces.IProtocolFactory): protocol factory to wrap
        sanlist (iterable[bytes]): list of domains the cert should be valid for

    Returns:
        interfaces.IProtocolFactory
    """
    if sanlist is None:
        sanlist = [b"DNS:test.com"]

    connection_creator = TestServerTLSConnectionFactory(sanlist=sanlist)
    return TLSMemoryBIOFactory(
        connection_creator, isClient=False, wrappedFactory=factory
    )


def _get_test_protocol_factory():
    """Get a protocol Factory which will build an HTTPChannel

    Returns:
        interfaces.IProtocolFactory
    """
    server_factory = Factory.forProtocol(HTTPChannel)

    # Request.finish expects the factory to have a 'log' method.
    server_factory.log = _log_request

    return server_factory


def _log_request(request):
    """Implements Factory.log, which is expected by Request.finish"""
    logger.info("Completed request %s", request)
