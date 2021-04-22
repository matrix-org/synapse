# -*- coding: utf-8 -*-
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

class RedisProtocol:
    def publish(self, channel: str, message: bytes): ...
    async def ping(self) -> None: ...
    async def set(
        self,
        key: str,
        value: Any,
        expire: Optional[int] = None,
        pexpire: Optional[int] = None,
        only_if_not_exists: bool = False,
        only_if_exists: bool = False,
    ) -> None: ...
    async def get(self, key: str) -> Any: ...

class SubscriberProtocol(RedisProtocol):
    def __init__(self, *args, **kwargs): ...
    password: Optional[str]
    def subscribe(self, channels: Union[str, List[str]]): ...
    def connectionMade(self): ...
    def connectionLost(self, reason): ...

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

class ConnectionHandler: ...

class RedisFactory:
    continueTrying: bool
    handler: RedisProtocol
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
    def buildProtocol(self, addr) -> RedisProtocol: ...

class SubscriberFactory(RedisFactory):
    def __init__(self): ...
