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

from typing import Callable, List, Tuple
from unittest import mock

from twisted.internet.defer import Deferred, ensureDeferred
from twisted.test.proto_helpers import StringTransport

from synapse.southbridge.connection_pool import Connection, ConnectionPool
from synapse.southbridge.objects import Protocols, RemoteAddress

from tests.unittest import HomeserverTestCase


def make_connector() -> Tuple[Callable, List[Tuple[Deferred, Tuple[str, int]]]]:

    connections = []

    def connector(reactor, host, port, timeout, bindAddress):

        connect = Deferred()

        def _conn(factory):
            connections.append((connect, (host, port), factory))
            return connect

        endpoint = mock.Mock(spec=["connect"], connect=_conn)
        return endpoint

    return connector, connections


class FakeConnector(object):
    pass


class ConnectionPoolTests(HomeserverTestCase):
    def test_basic(self):

        connector, connections = make_connector()
        endpoints = mock.Mock(spec=["TCP4ClientEndpoint"], TCP4ClientEndpoint=connector)

        pool = ConnectionPool(
            reactor=self.reactor,
            tls_factory=self.hs.get_federation_tls_options(),
            endpoints=endpoints,
        )

        host = RemoteAddress(
            name="example.com", addresses=["0.1.2.3"], port=80, protocol=Protocols.HTTP
        )

        connection = ensureDeferred(pool.request_connection(host))
        self.pump()
        self.assertEqual(len(connections), 1)

        protocol = connections[0][2].buildProtocol(None)
        transport = StringTransport()
        protocol.makeConnection(transport)
        connections[0][0].callback(protocol)
        resolved = self.successResultOf(connection)

        self.assertIsInstance(resolved, Connection)
