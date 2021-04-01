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

from zope.interface import implementer

from twisted.internet import defer, protocol
from twisted.internet.error import ConnectError
from twisted.internet.interfaces import IReactorCore, IStreamClientEndpoint
from twisted.internet.protocol import ClientFactory, Protocol, connectionDone
from twisted.web import http
from twisted.web.http_headers import Headers

logger = logging.getLogger(__name__)


class ProxyConnectError(ConnectError):
    pass


@implementer(IStreamClientEndpoint)
class HTTPConnectProxyEndpoint:
    """An Endpoint implementation which will send a CONNECT request to an http proxy

    Wraps an existing HostnameEndpoint for the proxy.

    When we get the connect() request from the connection pool (via the TLS wrapper),
    we'll first connect to the proxy endpoint with a ProtocolFactory which will make the
    CONNECT request. Once that completes, we invoke the protocolFactory which was passed
    in.

    Args:
        reactor: the Twisted reactor to use for the connection
        proxy_endpoint: the endpoint to use to connect to the proxy
        host: hostname that we want to CONNECT to
        port: port that we want to connect to
        headers: Extra HTTP headers to include in the CONNECT request
    """

    def __init__(
        self,
        reactor: IReactorCore,
        proxy_endpoint: IStreamClientEndpoint,
        host: bytes,
        port: int,
        headers: Headers,
    ):
        self._reactor = reactor
        self._proxy_endpoint = proxy_endpoint
        self._host = host
        self._port = port
        self._headers = headers

    def __repr__(self):
        return "<HTTPConnectProxyEndpoint %s>" % (self._proxy_endpoint,)

    def connect(self, protocolFactory: ClientFactory):
        f = HTTPProxiedClientFactory(
            self._host, self._port, protocolFactory, self._headers
        )
        d = self._proxy_endpoint.connect(f)
        # once the tcp socket connects successfully, we need to wait for the
        # CONNECT to complete.
        d.addCallback(lambda conn: f.on_connection)
        return d


class HTTPProxiedClientFactory(protocol.ClientFactory):
    """ClientFactory wrapper that triggers an HTTP proxy CONNECT on connect.

    Once the CONNECT completes, invokes the original ClientFactory to build the
    HTTP Protocol object and run the rest of the connection.

    Args:
        dst_host: hostname that we want to CONNECT to
        dst_port: port that we want to connect to
        wrapped_factory: The original Factory
        headers: Extra HTTP headers to include in the CONNECT request
    """

    def __init__(
        self,
        dst_host: bytes,
        dst_port: int,
        wrapped_factory: ClientFactory,
        headers: Headers,
    ):
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.wrapped_factory = wrapped_factory
        self.headers = headers
        self.on_connection = defer.Deferred()

    def startedConnecting(self, connector):
        return self.wrapped_factory.startedConnecting(connector)

    def buildProtocol(self, addr):
        wrapped_protocol = self.wrapped_factory.buildProtocol(addr)

        return HTTPConnectProtocol(
            self.dst_host,
            self.dst_port,
            wrapped_protocol,
            self.on_connection,
            self.headers,
        )

    def clientConnectionFailed(self, connector, reason):
        logger.debug("Connection to proxy failed: %s", reason)
        if not self.on_connection.called:
            self.on_connection.errback(reason)
        return self.wrapped_factory.clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector, reason):
        logger.debug("Connection to proxy lost: %s", reason)
        if not self.on_connection.called:
            self.on_connection.errback(reason)
        return self.wrapped_factory.clientConnectionLost(connector, reason)


class HTTPConnectProtocol(protocol.Protocol):
    """Protocol that wraps an existing Protocol to do a CONNECT handshake at connect

    Args:
        host: The original HTTP(s) hostname or IPv4 or IPv6 address literal
            to put in the CONNECT request

        port: The original HTTP(s) port to put in the CONNECT request

        wrapped_protocol: the original protocol (probably HTTPChannel or
            TLSMemoryBIOProtocol, but could be anything really)

        connected_deferred: a Deferred which will be callbacked with
            wrapped_protocol when the CONNECT completes

        headers: Extra HTTP headers to include in the CONNECT request
    """

    def __init__(
        self,
        host: bytes,
        port: int,
        wrapped_protocol: Protocol,
        connected_deferred: defer.Deferred,
        headers: Headers,
    ):
        self.host = host
        self.port = port
        self.wrapped_protocol = wrapped_protocol
        self.connected_deferred = connected_deferred
        self.headers = headers

        self.http_setup_client = HTTPConnectSetupClient(
            self.host, self.port, self.headers
        )
        self.http_setup_client.on_connected.addCallback(self.proxyConnected)

    def connectionMade(self):
        self.http_setup_client.makeConnection(self.transport)

    def connectionLost(self, reason=connectionDone):
        if self.wrapped_protocol.connected:
            self.wrapped_protocol.connectionLost(reason)

        self.http_setup_client.connectionLost(reason)

        if not self.connected_deferred.called:
            self.connected_deferred.errback(reason)

    def proxyConnected(self, _):
        self.wrapped_protocol.makeConnection(self.transport)

        self.connected_deferred.callback(self.wrapped_protocol)

        # Get any pending data from the http buf and forward it to the original protocol
        buf = self.http_setup_client.clearLineBuffer()
        if buf:
            self.wrapped_protocol.dataReceived(buf)

    def dataReceived(self, data: bytes):
        # if we've set up the HTTP protocol, we can send the data there
        if self.wrapped_protocol.connected:
            return self.wrapped_protocol.dataReceived(data)

        # otherwise, we must still be setting up the connection: send the data to the
        # setup client
        return self.http_setup_client.dataReceived(data)


class HTTPConnectSetupClient(http.HTTPClient):
    """HTTPClient protocol to send a CONNECT message for proxies and read the response.

    Args:
        host: The hostname to send in the CONNECT message
        port: The port to send in the CONNECT message
        headers: Extra headers to send with the CONNECT message
    """

    def __init__(self, host: bytes, port: int, headers: Headers):
        self.host = host
        self.port = port
        self.headers = headers
        self.on_connected = defer.Deferred()

    def connectionMade(self):
        logger.debug("Connected to proxy, sending CONNECT")
        self.sendCommand(b"CONNECT", b"%s:%d" % (self.host, self.port))

        # Send any additional specified headers
        for name, values in self.headers.getAllRawHeaders():
            for value in values:
                self.sendHeader(name, value)

        self.endHeaders()

    def handleStatus(self, version: bytes, status: bytes, message: bytes):
        logger.debug("Got Status: %s %s %s", status, message, version)
        if status != b"200":
            raise ProxyConnectError("Unexpected status on CONNECT: %s" % status)

    def handleEndHeaders(self):
        logger.debug("End Headers")
        self.on_connected.callback(None)

    def handleResponse(self, body):
        pass
