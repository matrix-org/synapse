# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

from mock import Mock

from twisted.internet.error import ConnectingCancelledError, DNSLookupError
from twisted.web.error import ResponseNeverReceived

from synapse.http.matrixfederationclient import MatrixFederationHttpClient

from tests.unittest import HomeserverTestCase


class FederationClientTests(HomeserverTestCase):

    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(reactor=reactor, clock=clock)
        hs.tls_client_options_factory = None
        return hs

    def prepare(self, reactor, clock, homeserver):

        self.cl = MatrixFederationHttpClient(self.hs)
        self.reactor.lookups["testserv"] = "1.2.3.4"


    def test_dns_error(self):
        """
        If the DNS raising returns an error, it will bubble up.
        """
        d = self.cl.put_json("testserv2:8008", "foo/bar", timeout=10000)
        self.pump()

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, DNSLookupError)

    def test_client_never_connect(self):

        d = self.cl.put_json("testserv:8008", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertFalse(d.called)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        # Deferred is still without a result
        self.assertFalse(d.called)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, ConnectingCancelledError)

    def test_client_connect_no_response(self):

        d = self.cl.put_json("testserv:8008", "foo/bar", timeout=10000)

        self.pump()

        # Nothing happened yet
        self.assertFalse(d.called)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], '1.2.3.4')
        self.assertEqual(clients[0][1], 8008)

        conn = Mock()

        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred is still without a result
        self.assertFalse(d.called)

        # Push by enough to time it out
        self.reactor.advance(10.5)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, ResponseNeverReceived)
