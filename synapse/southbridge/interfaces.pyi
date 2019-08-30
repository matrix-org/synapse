from typing import Any, List, Optional, Tuple

from zope.interface import Interface

from twisted.internet.interfaces import IProtocol
from twisted.python.failure import Failure
from twisted.web.iweb import (
    UNKNOWN_LENGTH,
    IBodyProducer,
    IPolicyForHTTPS,
    IRequest,
    IResponse,
)

class IAddress(Interface):
    port: int
    addresses: List[str]
    protocol: Any
    name: str

class IConnection(IProtocol):

    address: IAddress
    def relinquish() -> None: ...
    def set_client(client) -> None: ...
    def reset_client(unused_data: bytes = ...) -> None: ...
    def write(data: bytes) -> None: ...
    def can_be_bound() -> bool: ...
    def unbind() -> None: ...
    def bind() -> None: ...

class IConnectionPool(Interface):
    tls_factory: IPolicyForHTTPS
    timeout: int
    local_bind_address: Optional[Tuple[str, int]]
    async def request_connection(address: IAddress) -> IConnection: ...
    def connection_lost(connection: IConnection, reason: Failure) -> None: ...

class IClient(Interface):
    async def send_request(request: IRequest) -> IResponse: ...
    def data_received(data: bytes) -> None: ...
    def connection_lost(reason: Failure) -> None: ...
