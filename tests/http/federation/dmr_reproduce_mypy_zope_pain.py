from twisted.internet.endpoints import _WrappingProtocol
from twisted.internet.interfaces import (
    IProtocolFactory,
)

from tests.http import (
    dummy_address,
)

def _make_connection(
    client_factory: IProtocolFactory,
    server_factory: IProtocolFactory,
) -> None:
    server_protocol = server_factory.buildProtocol(dummy_address)
    assert server_protocol is not None

    client_protocol = client_factory.buildProtocol(dummy_address)
    assert isinstance(client_protocol, _WrappingProtocol)
    print("Hello")



