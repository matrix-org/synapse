import logging
from typing import List, Optional

from twisted.internet.endpoints import _WrappingProtocol
from twisted.internet.interfaces import (
    IProtocolFactory,
)
from twisted.protocols.tls import TLSMemoryBIOFactory, TLSMemoryBIOProtocol
from twisted.web.http import HTTPChannel

from tests import unittest
from tests.http import (
    dummy_address,
)
from tests.server import FakeTransport

logger = logging.getLogger(__name__)


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
    raise NotImplementedError()


def _get_test_protocol_factory() -> IProtocolFactory:
    raise NotImplementedError()


def _log_request(request: str) -> None:
    pass


