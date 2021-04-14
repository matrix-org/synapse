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
from unittest.mock import Mock

from netaddr import IPSet

from twisted.internet import defer
from twisted.internet.error import DNSLookupError

from synapse.http import RequestTimedOutError
from synapse.http.client import SimpleHttpClient
from synapse.server import HomeServer

from tests.unittest import HomeserverTestCase


class SimpleHttpClientTests(HomeserverTestCase):
    def prepare(self, reactor, clock, hs: "HomeServer"):
        # Add a DNS entry for a test server
        self.reactor.lookups["testserv"] = "1.2.3.4"

        self.cl = hs.get_simple_http_client()

    def test_dns_error(self):
        """
        If the DNS lookup returns an error, it will bubble up.
        """
        d = defer.ensureDeferred(self.cl.get_json("http://testserv2:8008/foo/bar"))
        self.pump()

        f = self.failureResultOf(d)
        self.assertIsInstance(f.value, DNSLookupError)

    def test_client_connection_refused(self):
        d = defer.ensureDeferred(self.cl.get_json("http://testserv:8008/foo/bar"))

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        (host, port, factory, _timeout, _bindAddress) = clients[0]
        self.assertEqual(host, "1.2.3.4")
        self.assertEqual(port, 8008)
        e = Exception("go away")
        factory.clientConnectionFailed(None, e)
        self.pump(0.5)

        f = self.failureResultOf(d)

        self.assertIs(f.value, e)

    def test_client_never_connect(self):
        """
        If the HTTP request is not connected and is timed out, it'll give a
        ConnectingCancelledError or TimeoutError.
        """
        d = defer.ensureDeferred(self.cl.get_json("http://testserv:8008/foo/bar"))

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], "1.2.3.4")
        self.assertEqual(clients[0][1], 8008)

        # Deferred is still without a result
        self.assertNoResult(d)

        # Push by enough to time it out
        self.reactor.advance(120)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestTimedOutError)

    def test_client_connect_no_response(self):
        """
        If the HTTP request is connected, but gets no response before being
        timed out, it'll give a ResponseNeverReceived.
        """
        d = defer.ensureDeferred(self.cl.get_json("http://testserv:8008/foo/bar"))

        self.pump()

        # Nothing happened yet
        self.assertNoResult(d)

        # Make sure treq is trying to connect
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0][0], "1.2.3.4")
        self.assertEqual(clients[0][1], 8008)

        conn = Mock()
        client = clients[0][2].buildProtocol(None)
        client.makeConnection(conn)

        # Deferred is still without a result
        self.assertNoResult(d)

        # Push by enough to time it out
        self.reactor.advance(120)
        f = self.failureResultOf(d)

        self.assertIsInstance(f.value, RequestTimedOutError)

    def test_client_ip_range_blacklist(self):
        """Ensure that Synapse does not try to connect to blacklisted IPs"""

        # Add some DNS entries we'll blacklist
        self.reactor.lookups["internal"] = "127.0.0.1"
        self.reactor.lookups["internalv6"] = "fe80:0:0:0:0:8a2e:370:7337"
        ip_blacklist = IPSet(["127.0.0.0/8", "fe80::/64"])

        cl = SimpleHttpClient(self.hs, ip_blacklist=ip_blacklist)

        # Try making a GET request to a blacklisted IPv4 address
        # ------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(cl.get_json("http://internal:8008/foo/bar"))
        self.pump(1)

        # Check that it was unable to resolve the address
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 0)

        self.failureResultOf(d, DNSLookupError)

        # Try making a POST request to a blacklisted IPv6 address
        # -------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(
            cl.post_json_get_json("http://internalv6:8008/foo/bar", {})
        )

        # Move the reactor forwards
        self.pump(1)

        # Check that it was unable to resolve the address
        clients = self.reactor.tcpClients
        self.assertEqual(len(clients), 0)

        # Check that it was due to a blacklisted DNS lookup
        self.failureResultOf(d, DNSLookupError)

        # Try making a GET request to a non-blacklisted IPv4 address
        # ----------------------------------------------------------
        # Make the request
        d = defer.ensureDeferred(cl.get_json("http://testserv:8008/foo/bar"))

        # Nothing has happened yet
        self.assertNoResult(d)

        # Move the reactor forwards
        self.pump(1)

        # Check that it was able to resolve the address
        clients = self.reactor.tcpClients
        self.assertNotEqual(len(clients), 0)

        # Connection will still fail as this IP address does not resolve to anything
        self.failureResultOf(d, RequestTimedOutError)
