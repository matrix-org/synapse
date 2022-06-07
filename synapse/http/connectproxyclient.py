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
from typing import Optional, Union

import attr
from zope.interface import implementer

from twisted.internet import defer, protocol
from twisted.internet.error import ConnectError
from twisted.internet.interfaces import (
    IAddress,
    IConnector,
    IProtocol,
    IReactorCore,
    IStreamClientEndpoint,
)
from twisted.internet.protocol import ClientFactory, Protocol, connectionDone
from twisted.python.failure import Failure
from twisted.web import http

logger = logging.getLogger(__name__)


class ProxyConnectError(ConnectError):
    pass


@attr.s(auto_attribs=True)
class ProxyCredentials:
    username_password: bytes

    def as_proxy_authorization_value(self) -> bytes:
        """
        Return the value for a Proxy-Authorization header (i.e. 'Basic abdef==').

        Returns:
            A transformation of the authentication string the encoded value for
            a Proxy-Authorization header.
        """
        # Encode as base64 and prepend the authorization type
        return b"Basic " + base64.encodebytes(self.username_password)


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
        proxy_creds: credentials to authenticate at proxy
    """

    def __init__(
        self,
        reactor: IReactorCore,
        proxy_endpoint: IStreamClientEndpoint,
        host: bytes,
        port: int,
        proxy_creds: Optional[ProxyCredentials],
    ):
        self._reactor = reactor
        self._proxy_endpoint = proxy_endpoint
        self._host = host
        self._port = port
        self._proxy_creds = proxy_creds

    def __repr__(self) -> str:
        return "<HTTPConnectProxyEndpoint %s>" % (self._proxy_endpoint,)

    # Mypy encounters a false positive here: it complains that ClientFactory
    # is incompatible with IProtocolFactory. But ClientFactory inherits from
    # Factory, which implements IProtocolFactory. So I think this is a bug
    # in mypy-zope.
    def connect(self, protocolFactory: ClientFactory) -> "defer.Deferred[IProtocol]":  # type: ignore[override]
        f = HTTPProxiedClientFactory(
            self._host, self._port, protocolFactory, self._proxy_creds
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
        proxy_creds: credentials to authenticate at proxy
    """

    def __init__(
        self,
        dst_host: bytes,
        dst_port: int,
        wrapped_factory: ClientFactory,
        proxy_creds: Optional[ProxyCredentials],
    ):
        self.dst_host = dst_host
        self.dst_port = dst_port
        self.wrapped_factory = wrapped_factory
        self.proxy_creds = proxy_creds
        self.on_connection: "defer.Deferred[None]" = defer.Deferred()

    def startedConnecting(self, connector: IConnector) -> None:
        return self.wrapped_factory.startedConnecting(connector)

    def buildProtocol(self, addr: IAddress) -> "HTTPConnectProtocol":
        wrapped_protocol = self.wrapped_factory.buildProtocol(addr)
        if wrapped_protocol is None:
            raise TypeError("buildProtocol produced None instead of a Protocol")

        return HTTPConnectProtocol(
            self.dst_host,
            self.dst_port,
            wrapped_protocol,
            self.on_connection,
            self.proxy_creds,
        )

    def clientConnectionFailed(self, connector: IConnector, reason: Failure) -> None:
        logger.debug("Connection to proxy failed: %s", reason)
        if not self.on_connection.called:
            self.on_connection.errback(reason)
        return self.wrapped_factory.clientConnectionFailed(connector, reason)

    def clientConnectionLost(self, connector: IConnector, reason: Failure) -> None:
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

        proxy_creds: credentials to authenticate at proxy
    """

    def __init__(
        self,
        host: bytes,
        port: int,
        wrapped_protocol: Protocol,
        connected_deferred: defer.Deferred,
        proxy_creds: Optional[ProxyCredentials],
    ):
        self.host = host
        self.port = port
        self.wrapped_protocol = wrapped_protocol
        self.connected_deferred = connected_deferred
        self.proxy_creds = proxy_creds

        self.http_setup_client = HTTPConnectSetupClient(
            self.host, self.port, self.proxy_creds
        )
        self.http_setup_client.on_connected.addCallback(self.proxyConnected)

    def connectionMade(self) -> None:
        self.http_setup_client.makeConnection(self.transport)

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        if self.wrapped_protocol.connected:
            self.wrapped_protocol.connectionLost(reason)

        self.http_setup_client.connectionLost(reason)

        if not self.connected_deferred.called:
            self.connected_deferred.errback(reason)

    def proxyConnected(self, _: Union[None, "defer.Deferred[None]"]) -> None:
        self.wrapped_protocol.makeConnection(self.transport)

        self.connected_deferred.callback(self.wrapped_protocol)

        # Get any pending data from the http buf and forward it to the original protocol
        buf = self.http_setup_client.clearLineBuffer()
        if buf:
            self.wrapped_protocol.dataReceived(buf)

    def dataReceived(self, data: bytes) -> None:
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
        proxy_creds: credentials to authenticate at proxy
    """

    def __init__(
        self,
        host: bytes,
        port: int,
        proxy_creds: Optional[ProxyCredentials],
    ):
        self.host = host
        self.port = port
        self.proxy_creds = proxy_creds
        self.on_connected: "defer.Deferred[None]" = defer.Deferred()

    def connectionMade(self) -> None:
        logger.debug("Connected to proxy, sending CONNECT")
        self.sendCommand(b"CONNECT", b"%s:%d" % (self.host, self.port))

        # Determine whether we need to set Proxy-Authorization headers
        if self.proxy_creds:
            # Set a Proxy-Authorization header
            self.sendHeader(
                b"Proxy-Authorization",
                self.proxy_creds.as_proxy_authorization_value(),
            )

        self.endHeaders()

    def handleStatus(self, version: bytes, status: bytes, message: bytes) -> None:
        logger.debug("Got Status: %s %s %s", status, message, version)
        if status != b"200":
            raise ProxyConnectError(f"Unexpected status on CONNECT: {status!s}")

    def handleEndHeaders(self) -> None:
        logger.debug("End Headers")
        self.on_connected.callback(None)

    def handleResponse(self, body: bytes) -> None:
        pass
