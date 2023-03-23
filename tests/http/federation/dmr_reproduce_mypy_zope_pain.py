from typing import Optional

from zope.interface import Interface, implementer


class IProtocol(Interface):
    pass


@implementer(IProtocol)
class Protocol:
    pass


class _WrappingProtocol(Protocol):
    pass


class IProtocolFactory(Interface):
    def buildProtocol() -> Optional[IProtocol]:
        pass


def _make_connection(
    client_factory: IProtocolFactory,
) -> None:
    client_protocol = client_factory.buildProtocol()
    assert isinstance(client_protocol, _WrappingProtocol)
    print("Hello")
