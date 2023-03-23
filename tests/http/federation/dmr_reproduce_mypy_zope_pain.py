from twisted.internet.endpoints import _WrappingProtocol
from twisted.internet.interfaces import (
    IProtocolFactory,
)

from tests import unittest
from tests.http import (
    dummy_address,
)



class MatrixFederationAgentTests(unittest.TestCase):

    def _make_connection(
        self,
        client_factory: IProtocolFactory,
    ) -> None:
        server_factory = _get_test_protocol_factory()
        server_protocol = server_factory.buildProtocol(dummy_address)
        assert server_protocol is not None

        client_protocol = client_factory.buildProtocol(dummy_address)
        assert isinstance(client_protocol, _WrappingProtocol)
        print("Hello")


def _get_test_protocol_factory() -> IProtocolFactory:
    raise NotImplementedError()



