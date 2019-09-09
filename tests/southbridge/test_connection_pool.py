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

from synapse.southbridge.connection_pool import Connection, ConnectionPool
from synapse.southbridge.objects import Protocols, RemoteAddress

from tests.unittest import HomeserverTestCase


class FakeConnector(object):
    pass


class ConnectionPoolTests(HomeserverTestCase):
    def make_pool(self):
        return ConnectionPool(
            reactor=self.reactor, tls_factory=self.hs.get_federation_tls_options()
        )

    def test_basic(self):
        """
        When a connection is requested of the pool, it returns it when the
        connection is made.
        """
        pool = self.make_pool()
        host = RemoteAddress(
            name="example.com", addresses=["0.1.2.3"], port=80, protocol=Protocols.HTTP
        )

        connection = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 0))

        protocol, transport = self.connect_tcp(0)
        self.assertEqual(self.reactor.getTCPClientCounts(), (0, 1))
        resolved = self.successResultOf(connection)

        self.assertIsInstance(resolved, Connection)

    def test_concurrent(self):
        """
        When a connection is requested of the pool and none are available, it
        will open a new connection.
        """
        pool = self.make_pool()
        host = RemoteAddress(
            name="example.com", addresses=["0.1.2.3"], port=80, protocol=Protocols.HTTP
        )

        connection_1 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 0))

        self.connect_tcp(0)
        resolved_1 = self.successResultOf(connection_1)

        connection_2 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 1))
        protocol, transport = self.connect_tcp(0)
        resolved_2 = self.successResultOf(connection_2)

        self.assertIsNot(resolved_1, resolved_2)

    def test_connection_reuse(self):
        """
        When a connection is requested from the pool, relinquished, and then
        requested again, it will be the same connection if it still exists.
        """
        pool = self.make_pool()
        host = RemoteAddress(
            name="example.com", addresses=["0.1.2.3"], port=80, protocol=Protocols.HTTP
        )

        connection_1 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 0))

        self.connect_tcp(0)
        resolved_1 = self.successResultOf(connection_1)
        resolved_1.relinquish()

        connection_2 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (0, 1))
        resolved_2 = self.successResultOf(connection_2)

        self.assertEqual(self.reactor.getTCPClientCounts(), (0, 1))
        self.assertIs(resolved_1, resolved_2)

    def test_connection_reuse_attempt_fail(self):
        """
        When a connection is requested from the pool, relinquished, disconnects,
        and then the same connection is requested again, a new connection will
        be made.
        """
        pool = self.make_pool()
        host = RemoteAddress(
            name="example.com", addresses=["0.1.2.3"], port=80, protocol=Protocols.HTTP
        )

        connection_1 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 0))

        self.connect_tcp(0)
        resolved_1 = self.successResultOf(connection_1)
        resolved_1.transport.loseConnection()
        self.assertFalse(resolved_1._connected)

        connection_2 = ensureDeferred(pool.request_connection(host))
        self.assertEqual(self.reactor.getTCPClientCounts(), (1, 0))
        protocol, transport = self.connect_tcp(0)
        resolved_2 = self.successResultOf(connection_2)

        self.assertIsNot(resolved_1, resolved_2)
