# Copyright 2019 New Vector Ltd
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
from typing import Any, Awaitable, Callable, Generator, List, Optional, cast
from unittest.mock import Mock, patch

import treq
from netaddr import IPSet
from service_identity import VerificationError
from zope.interface import implementer

from twisted.internet import defer
from twisted.internet._sslverify import ClientTLSOptions, OpenSSLCertificateOptions
from twisted.internet.defer import Deferred
from twisted.internet.endpoints import _WrappingProtocol
from twisted.internet.interfaces import (
    IOpenSSLClientConnectionCreator,
    IProtocolFactory,
)
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.web._newclient import ResponseNeverReceived
from twisted.web.client import Agent
from twisted.web.http import HTTPChannel, Request
from twisted.web.http_headers import Headers
from twisted.web.iweb import IPolicyForHTTPS, IResponse

from synapse.config.homeserver import HomeServerConfig
from synapse.crypto.context_factory import FederationPolicyForHTTPS
from synapse.http.federation.matrix_federation_agent import MatrixFederationAgent
from synapse.http.federation.srv_resolver import Server
from synapse.http.federation.well_known_resolver import (
    WELL_KNOWN_MAX_SIZE,
    WellKnownResolver,
    _cache_period_from_headers,
)
from synapse.logging.context import (
    SENTINEL_CONTEXT,
    LoggingContext,
    LoggingContextOrSentinel,
    current_context,
)
from synapse.types import ISynapseReactor
from synapse.util.caches.ttlcache import TTLCache

from tests import unittest
from tests.http import (
    TestServerTLSConnectionFactory,
    dummy_address,
    get_test_ca_cert_file,
)
from tests.server import FakeTransport, ThreadedMemoryReactorClock
from tests.utils import default_config

logger = logging.getLogger(__name__)


# Once Async Mocks or lambdas are supported this can go away.
def generate_resolve_service(
    result: List[Server],
) -> Callable[[Any], Awaitable[List[Server]]]:
    async def resolve_service(_: Any) -> List[Server]:
        return result

    return resolve_service


class MatrixFederationAgentTests(unittest.TestCase):

    def _make_connection(
        self,
        client_factory: IProtocolFactory,
        ssl: bool = True,
        expected_sni: Optional[bytes] = None,
        tls_sanlist: Optional[List[bytes]] = None,
    ) -> HTTPChannel:
        # build the test server
        server_factory = _get_test_protocol_factory()
        if ssl:
            server_factory = _wrap_server_factory_for_tls(server_factory, tls_sanlist)

        server_protocol = server_factory.buildProtocol(dummy_address)
        assert server_protocol is not None
        # now, tell the client protocol factory to build the client protocol (it will be a
        # _WrappingProtocol, around a TLSMemoryBIOProtocol, around an
        # HTTP11ClientProtocol) and wire the output of said protocol up to the server via
        # a FakeTransport.
        #
        # Normally this would be done by the TCP socket code in Twisted, but we are
        # stubbing that out here.
        # NB: we use a checked_cast here to workaround https://github.com/Shoobx/mypy-zope/issues/91)
        client_protocol = client_factory.buildProtocol(dummy_address)
        assert isinstance(client_protocol, _WrappingProtocol)
        client_protocol.makeConnection(
            FakeTransport(server_protocol, self.reactor, client_protocol)
        )

        # tell the server protocol to send its stuff back to the client, too
        server_protocol.makeConnection(
            FakeTransport(client_protocol, self.reactor, server_protocol)
        )

        if ssl:
            assert isinstance(server_protocol, TLSMemoryBIOProtocol)
            # fish the test server back out of the server-side TLS protocol.
            http_protocol = server_protocol.wrappedProtocol
            # grab a hold of the TLS connection, in case it gets torn down
            tls_connection = server_protocol._tlsConnection
        else:
            http_protocol = server_protocol
            tls_connection = None

        assert isinstance(http_protocol, HTTPChannel)
        # give the reactor a pump to get the TLS juices flowing (if needed)
        self.reactor.advance(0)

        # check the SNI
        if expected_sni is not None:
            server_name = tls_connection.get_servername()
            self.assertEqual(
                server_name,
                expected_sni,
                f"Expected SNI {expected_sni!s} but got {server_name!s}",
            )

        return http_protocol

def _wrap_server_factory_for_tls(
    factory: IProtocolFactory, sanlist: Optional[List[bytes]] = None
) -> TLSMemoryBIOFactory:
    """Wrap an existing Protocol Factory with a test TLSMemoryBIOFactory
    The resultant factory will create a TLS server which presents a certificate
    signed by our test CA, valid for the domains in `sanlist`
    Args:
        factory: protocol factory to wrap
        sanlist: list of domains the cert should be valid for
    Returns:
        interfaces.IProtocolFactory
    """
    if sanlist is None:
        sanlist = [
            b"DNS:testserv",
            b"DNS:target-server",
            b"DNS:xn--bcher-kva.com",
            b"IP:1.2.3.4",
            b"IP:::1",
        ]

    connection_creator = TestServerTLSConnectionFactory(sanlist=sanlist)
    return TLSMemoryBIOFactory(
        connection_creator, isClient=False, wrappedFactory=factory
    )


def _get_test_protocol_factory() -> IProtocolFactory:
    """Get a protocol Factory which will build an HTTPChannel
    Returns:
        interfaces.IProtocolFactory
    """
    server_factory = Factory.forProtocol(HTTPChannel)

    # Request.finish expects the factory to have a 'log' method.
    server_factory.log = _log_request

    return server_factory


def _log_request(request: str) -> None:
    """Implements Factory.log, which is expected by Request.finish"""
    logger.info(f"Completed request {request}")


