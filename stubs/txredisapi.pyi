# Copyright 2020 The Matrix.org Foundation C.I.C.
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

"""Contains *incomplete* type hints for txredisapi.
"""
from typing import Any, List, Optional, Type, Union

from twisted.internet import protocol
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IAddress
from twisted.python.failure import Failure

class RedisProtocol(protocol.Protocol):
    def publish(self, channel: str, message: bytes) -> "Deferred[None]": ...
    def ping(self) -> "Deferred[None]": ...
    def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
        pexpire: Optional[int] = None,
        only_if_not_exists: bool = False,
        only_if_exists: bool = False,
    ) -> "Deferred[None]": ...
    def get(self, key: str) -> "Deferred[Any]": ...

class SubscriberProtocol(RedisProtocol):
    def __init__(self, *args: object, **kwargs: object): ...
    password: Optional[str]
    def subscribe(self, channels: Union[str, List[str]]) -> "Deferred[None]": ...
    def connectionMade(self) -> None: ...
    # type-ignore: twisted.internet.protocol.Protocol provides a default argument for
    # `reason`. txredisapi's LineReceiver Protocol doesn't. But that's fine: it's what's
    # actually specified in twisted.internet.interfaces.IProtocol.
    def connectionLost(self, reason: Failure) -> None: ...  # type: ignore[override]

def lazyConnection(
    host: str = ...,
    port: int = ...,
    dbid: Optional[int] = ...,
    reconnect: bool = ...,
    charset: str = ...,
    password: Optional[str] = ...,
    connectTimeout: Optional[int] = ...,
    replyTimeout: Optional[int] = ...,
    convertNumbers: bool = ...,
) -> RedisProtocol: ...

# ConnectionHandler doesn't actually inherit from RedisProtocol, but it proxies
# most methods to it via ConnectionHandler.__getattr__.
class ConnectionHandler(RedisProtocol):
    def disconnect(self) -> "Deferred[None]": ...
    def __repr__(self) -> str: ...

class UnixConnectionHandler(ConnectionHandler): ...

class RedisFactory(protocol.ReconnectingClientFactory):
    continueTrying: bool
    handler: ConnectionHandler
    pool: List[RedisProtocol]
    replyTimeout: Optional[int]
    def __init__(
        self,
        uuid: str,
        dbid: Optional[int],
        poolsize: int,
        isLazy: bool = False,
        handler: Type = ConnectionHandler,
        charset: str = "utf-8",
        password: Optional[str] = None,
        replyTimeout: Optional[int] = None,
        convertNumbers: Optional[int] = True,
    ): ...
    def buildProtocol(self, addr: IAddress) -> RedisProtocol: ...

class SubscriberFactory(RedisFactory):
    def __init__(self) -> None: ...
