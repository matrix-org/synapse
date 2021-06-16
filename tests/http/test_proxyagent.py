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
import base64
import logging
import os
from typing import Optional
from unittest.mock import patch

import treq
from netaddr import IPSet

from twisted.internet import interfaces  # noqa: F401
from twisted.internet.protocol import Factory
from twisted.protocols.tls import TLSMemoryBIOFactory
from twisted.web.http import HTTPChannel

from synapse.http.client import BlacklistingReactorWrapper
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

    def _test_request_direct_connection(self, agent, scheme, hostname, path):
        """Runs a test case for a direct connection not going through a proxy.

        Args:
            agent (ProxyAgent): the proxy agent being tested

            scheme (bytes): expected to be either "http" or "https"

            hostname (bytes): the hostname to connect to in the test

            path (bytes): the path to connect to in the test
        """
        is_https = scheme == b"https"

        self.reactor.lookups[hostname.decode()] = "1.2.3.4"
        d = agent.request(b"GET", scheme + b"://" + hostname + b"/" + path)

        # there should be a pending TCP connection
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, client_factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 443 if is_https else 80)

        # make a test server, and wire up the client
        http_server = self._make_connection(
            client_factory,
            _get_test_protocol_factory(),
            ssl=is_https,
            expected_sni=hostname if is_https else None,
        )

        # the FakeTransport is async, so we need to pump the reactor
        self.reactor.advance(0)

        # now there should be a pending request
        self.assertEqual(len(http_server.requests), 1)

        request = http_server.requests[0]
        self.assertEqual(request.method, b"GET")
        self.assertEqual(request.path, b"/" + path)
        self.assertEqual(request.requestHeaders.getRawHeaders(b"host"), [hostname])
        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")

    def test_http_request(self):
        agent = ProxyAgent(self.reactor)
        self._test_request_direct_connection(agent, b"http", b"test.com", b"")

    def test_https_request(self):
        agent = ProxyAgent(self.reactor, contextFactory=get_test_https_policy())
        self._test_request_direct_connection(agent, b"https", b"test.com", b"abc")

    def test_http_request_use_proxy_empty_environment(self):
        agent = ProxyAgent(self.reactor, use_proxy=True)
        self._test_request_direct_connection(agent, b"http", b"test.com", b"")

    @patch.dict(os.environ, {"http_proxy": "proxy.com:8888", "NO_PROXY": "test.com"})
    def test_http_request_via_uppercase_no_proxy(self):
        agent = ProxyAgent(self.reactor, use_proxy=True)
        self._test_request_direct_connection(agent, b"http", b"test.com", b"")

    @patch.dict(
        os.environ, {"http_proxy": "proxy.com:8888", "no_proxy": "test.com,unused.com"}
    )
    def test_http_request_via_no_proxy(self):
        agent = ProxyAgent(self.reactor, use_proxy=True)
        self._test_request_direct_connection(agent, b"http", b"test.com", b"")

    @patch.dict(
        os.environ, {"https_proxy": "proxy.com", "no_proxy": "test.com,unused.com"}
    )
    def test_https_request_via_no_proxy(self):
        agent = ProxyAgent(
            self.reactor,
            contextFactory=get_test_https_policy(),
            use_proxy=True,
        )
        self._test_request_direct_connection(agent, b"https", b"test.com", b"abc")

    @patch.dict(os.environ, {"http_proxy": "proxy.com:8888", "no_proxy": "*"})
    def test_http_request_via_no_proxy_star(self):
        agent = ProxyAgent(self.reactor, use_proxy=True)
        self._test_request_direct_connection(agent, b"http", b"test.com", b"")

    @patch.dict(os.environ, {"https_proxy": "proxy.com", "no_proxy": "*"})
    def test_https_request_via_no_proxy_star(self):
        agent = ProxyAgent(
            self.reactor,
            contextFactory=get_test_https_policy(),
            use_proxy=True,
        )
        self._test_request_direct_connection(agent, b"https", b"test.com", b"abc")

    @patch.dict(os.environ, {"http_proxy": "proxy.com:8888", "no_proxy": "unused.com"})
    def test_http_request_via_proxy(self):
        agent = ProxyAgent(self.reactor, use_proxy=True)

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

    @patch.dict(os.environ, {"https_proxy": "proxy.com", "no_proxy": "unused.com"})
    def test_https_request_via_proxy(self):
        """Tests that TLS-encrypted requests can be made through a proxy"""
        self._do_https_request_via_proxy(auth_credentials=None)

    @patch.dict(
        os.environ,
        {"https_proxy": "bob:pinkponies@proxy.com", "no_proxy": "unused.com"},
    )
    def test_https_request_via_proxy_with_auth(self):
        """Tests that authenticated, TLS-encrypted requests can be made through a proxy"""
        self._do_https_request_via_proxy(auth_credentials="bob:pinkponies")

    def _do_https_request_via_proxy(
        self,
        auth_credentials: Optional[str] = None,
    ):
        agent = ProxyAgent(
            self.reactor,
            contextFactory=get_test_https_policy(),
            use_proxy=True,
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

        # Check whether auth credentials have been supplied to the proxy
        proxy_auth_header_values = request.requestHeaders.getRawHeaders(
            b"Proxy-Authorization"
        )

        if auth_credentials is not None:
            # Compute the correct header value for Proxy-Authorization
            encoded_credentials = base64.b64encode(b"bob:pinkponies")
            expected_header_value = b"Basic " + encoded_credentials

            # Validate the header's value
            self.assertIn(expected_header_value, proxy_auth_header_values)
        else:
            # Check that the Proxy-Authorization header has not been supplied to the proxy
            self.assertIsNone(proxy_auth_header_values)

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

        # Check that the destination server DID NOT receive proxy credentials
        proxy_auth_header_values = request.requestHeaders.getRawHeaders(
            b"Proxy-Authorization"
        )
        self.assertIsNone(proxy_auth_header_values)

        request.write(b"result")
        request.finish()

        self.reactor.advance(0)

        resp = self.successResultOf(d)
        body = self.successResultOf(treq.content(resp))
        self.assertEqual(body, b"result")

    @patch.dict(os.environ, {"http_proxy": "proxy.com:8888"})
    def test_http_request_via_proxy_with_blacklist(self):
        # The blacklist includes the configured proxy IP.
        agent = ProxyAgent(
            BlacklistingReactorWrapper(
                self.reactor, ip_whitelist=None, ip_blacklist=IPSet(["1.0.0.0/8"])
            ),
            self.reactor,
            use_proxy=True,
        )

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

    @patch.dict(os.environ, {"HTTPS_PROXY": "proxy.com"})
    def test_https_request_via_uppercase_proxy_with_blacklist(self):
        # The blacklist includes the configured proxy IP.
        agent = ProxyAgent(
            BlacklistingReactorWrapper(
                self.reactor, ip_whitelist=None, ip_blacklist=IPSet(["1.0.0.0/8"])
            ),
            self.reactor,
            contextFactory=get_test_https_policy(),
            use_proxy=True,
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
