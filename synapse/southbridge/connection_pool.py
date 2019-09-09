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

from collections import defaultdict
from typing import List, Mapping, Optional, Tuple

import attr
from zope.interface import implementer

from twisted.internet import endpoints
from twisted.internet.protocol import Factory
from twisted.python.failure import Failure

from synapse.crypto.context_factory import ClientTLSOptionsFactory
from synapse.logging.ids import readable_id

from .interfaces import IClient, IConnection, IConnectionPool, IRemoteAddress
from .objects import Protocols


@attr.s
@implementer(IConnection)
class Connection:

    pool = attr.ib(type=IConnectionPool)
    address = attr.ib(type=IRemoteAddress)
    chosen_address = attr.ib()
    _bound = attr.ib(default=False, repr=False)
    _client = attr.ib(default=None, repr=False, type=Optional[IClient])
    _connected = attr.ib(default=False, type=bool)
    _write_buffer = attr.ib(default=attr.Factory(list), repr=False, type=List[bytes])
    name = attr.ib(default=attr.Factory(readable_id))

    def relinquish(self) -> None:
        """
        Return this connection to the connection pool.
        """
        if not self.bound:
            raise Exception("Can't relinquish an unbound connection")

        if self._client:
            raise Exception("Connection hasn't had its client disconnected yet")

        self.unbind()

    def set_client(self, client) -> None:
        if not self.bound:
            raise Exception("Can't set a client on an unbound Connection")

        self._client = client

        if self._write_buffer:
            self._flush()

    def reset_client(self, unused_data: bytes = b"") -> None:
        """
        Reset the listening client. Done before relinquishing back to the
        connection pool.

        Puts unused data back into the write buffer. This unused data might be
        pushed from the client, writers must be able to ignore this.
        """
        self._client = None
        if unused_data:
            self._write_buffer.append(unused_data)

    def _flush(self):
        """
        Flush the write buffer to the callback.
        """
        for data in self._write_buffer:
            self._client.data_received(data)
        self._write_buffer.clear()

    def write(self, data: bytes) -> None:
        if self._connected:
            self.transport.write(data)
        else:
            # TODO: Do we yell or just eat it?
            pass

    @property
    def bound(self):
        return self._bound

    def can_be_bound(self) -> bool:
        return self._connected and not self._bound

    def unbind(self) -> None:
        """
        Unbind this connection. This can be done multiple times.
        """
        self._bound = False

    def bind(self) -> None:
        if self._bound:
            raise Exception("Can't bind twice")
        self._bound = True

    # IProtocol

    def makeConnection(self, transport):
        self._connected = True
        self.transport = transport
        self.connectionMade()

    def connectionMade(self) -> None:
        """
        We have a new connection.
        """
        self._connected = True

    def connectionLost(self, reason) -> None:
        """
        The connection has been lost.
        """
        self._connected = False
        self._bound = False
        if self._client:
            self._client.connection_lost(reason)

        self.pool.connection_lost(self, reason)

    def dataReceived(self, data: bytes) -> None:
        if self._client:
            self._client.data_received(data)
        else:
            self._write_buffer.append(data)


@attr.s
class ConnectionFactory(Factory):

    protocol = attr.ib()
    pool = attr.ib()
    address = attr.ib()
    chosen_address = attr.ib()
    bound = attr.ib()

    def buildProtocol(self, addr):
        p = self.protocol(
            pool=self.pool,
            address=self.address,
            chosen_address=self.chosen_address,
            bound=self.bound,
        )
        p.factory = self
        return p


@attr.s
class ConnectionPool:

    reactor = attr.ib(repr=False)
    tls_factory = attr.ib(type=ClientTLSOptionsFactory, repr=False)

    # TODO: Timeout configuration in config
    timeout = attr.ib(default=60, repr=False)
    # TODO: Local bind address in config
    local_bind_address = attr.ib(
        default=None, repr=False, type=Optional[Tuple[str, int]]
    )

    # Active connections.
    _connections = attr.ib(
        default=attr.Factory(lambda: defaultdict(list)),
        repr=False,
        type=Mapping[IRemoteAddress, List[IConnection]],
    )

    name = attr.ib(default=attr.Factory(readable_id))

    _endpoints = attr.ib(default=endpoints, repr=False)

    async def request_connection(self, address: IRemoteAddress) -> IConnection:
        """
        Request a connection from this connection pool.
        """
        # Do we have any open connections we can bind?
        bindable_connections = list(
            filter(lambda conn: conn.can_be_bound(), self._connections.get(address, []))
        )

        if bindable_connections:
            connection_to_use = bindable_connections[0]
            connection_to_use.bind()
            return connection_to_use

        # TODO: Select this smarter.
        host_to_connect_to = address.addresses[0]

        endpoint = self._endpoints.TCP4ClientEndpoint(
            reactor=self.reactor,
            host=host_to_connect_to,
            port=address.port,
            timeout=self.timeout,
            bindAddress=self.local_bind_address,
        )

        if address.protocol is Protocols.HTTPS:
            tls_connection_creator = self.tls_factory.creatorForNetloc(
                address.name.encode("ascii"), address.port
            )
            endpoint = self._endpoints.wrapClientTLS(tls_connection_creator, endpoint)

        connection_factory = ConnectionFactory(
            Connection,
            pool=self,
            address=address,
            chosen_address=(host_to_connect_to, address.port),
            bound=True,
        )

        try:
            connection = await endpoint.connect(connection_factory)
        except Exception:
            # TODO: Catch exceptions here.
            raise

        self._connections[address].append(connection)

        return connection

    def connection_lost(self, connection: IConnection, reason: Failure) -> None:
        """
        Called when a connection has had its underlying transport lost, and
        needs to be removed from the pool.
        """
        connection.unbind()
        current_connections = self._connections.get(connection.address, [])
        if connection in current_connections:
            current_connections.remove(connection)
