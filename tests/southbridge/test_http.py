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

from twisted.internet.defer import ensureDeferred

from synapse.southbridge.connection_pool import Connection, ConnectionPool
from synapse.southbridge.http import HTTP11Agent
from synapse.southbridge.objects import Protocols, RemoteAddress

from tests.unittest import HomeserverTestCase


class FakeConnector(object):
    pass


class HTTPTests(HomeserverTestCase):
    def make_pool(self):
        return ConnectionPool(
            reactor=self.reactor, tls_factory=self.hs.get_federation_tls_options()
        )

    def make_agent(self):
        pool = self.make_pool()
        agent = HTTP11Agent(reactor=self.reactor, pool=pool)
        return agent

    def test_malformed(self):
        """
        A garbage response will lead to the request failing.
        """
        agent = self.make_agent()
        self.reactor.lookups["example.com"] = "1.1.1.1"

        d = agent.request(b"GET", b"http://example.com")
        protocol, transport = self.connect_tcp(0)

        protocol.dataReceived(b"arba\r\n\r\n")
        self.failureResultOf(d)

    def test_success(self):
        """
        A garbage response will lead to the request failing.
        """
        agent = self.make_agent()
        self.reactor.lookups["example.com"] = "1.1.1.1"

        d = agent.request(b"GET", b"http://example.com")
        protocol, transport = self.connect_tcp(0)

        protocol.dataReceived(
            b"HTTP/1.1 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: 0\r\n\r\n"
        )
        result = self.successResultOf(d)
