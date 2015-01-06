# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from twisted.internet.endpoints import SSL4ClientEndpoint, TCP4ClientEndpoint
from twisted.internet import defer
from twisted.internet.error import ConnectError
from twisted.names import client, dns
from twisted.names.error import DNSNameError

import collections
import logging
import random


logger = logging.getLogger(__name__)


def matrix_federation_endpoint(reactor, destination, ssl_context_factory=None,
                               timeout=None):
    """Construct an endpoint for the given matrix destination.

    Args:
        reactor: Twisted reactor.
        destination (bytes): The name of the server to connect to.
        ssl_context_factory (twisted.internet.ssl.ContextFactory): Factory
            which generates SSL contexts to use for TLS.
        timeout (int): connection timeout in seconds
    """

    domain_port = destination.split(":")
    domain = domain_port[0]
    port = int(domain_port[1]) if domain_port[1:] else None

    endpoint_kw_args = {}

    if timeout is not None:
        endpoint_kw_args.update(timeout=timeout)

    if ssl_context_factory is None:
        transport_endpoint = TCP4ClientEndpoint
        default_port = 8008
    else:
        transport_endpoint = SSL4ClientEndpoint
        endpoint_kw_args.update(sslContextFactory=ssl_context_factory)
        default_port = 8448

    if port is None:
        return SRVClientEndpoint(
            reactor, "matrix", domain, protocol="tcp",
            default_port=default_port, endpoint=transport_endpoint,
            endpoint_kw_args=endpoint_kw_args
        )
    else:
        return transport_endpoint(reactor, domain, port, **endpoint_kw_args)


class SRVClientEndpoint(object):
    """An endpoint which looks up SRV records for a service.
    Cycles through the list of servers starting with each call to connect
    picking the next server.
    Implements twisted.internet.interfaces.IStreamClientEndpoint.
    """

    _Server = collections.namedtuple(
        "_Server", "priority weight host port"
    )

    def __init__(self, reactor, service, domain, protocol="tcp",
                 default_port=None, endpoint=TCP4ClientEndpoint,
                 endpoint_kw_args={}):
        self.reactor = reactor
        self.service_name = "_%s._%s.%s" % (service, protocol, domain)

        if default_port is not None:
            self.default_server = self._Server(
                host=domain,
                port=default_port,
                priority=0,
                weight=0
            )
        else:
            self.default_server = None

        self.endpoint = endpoint
        self.endpoint_kw_args = endpoint_kw_args

        self.servers = None
        self.used_servers = None

    @defer.inlineCallbacks
    def fetch_servers(self):
        try:
            answers, auth, add = yield client.lookupService(self.service_name)
        except DNSNameError:
            answers = []

        if (len(answers) == 1
                and answers[0].type == dns.SRV
                and answers[0].payload
                and answers[0].payload.target == dns.Name('.')):
            raise ConnectError("Service %s unavailable", self.service_name)

        self.servers = []
        self.used_servers = []

        for answer in answers:
            if answer.type != dns.SRV or not answer.payload:
                continue
            payload = answer.payload
            self.servers.append(self._Server(
                host=str(payload.target),
                port=int(payload.port),
                priority=int(payload.priority),
                weight=int(payload.weight)
            ))

        self.servers.sort()

    def pick_server(self):
        if not self.servers:
            if self.used_servers:
                self.servers = self.used_servers
                self.used_servers = []
                self.servers.sort()
            elif self.default_server:
                return self.default_server
            else:
                raise ConnectError(
                    "Not server available for %s", self.service_name
                )

        min_priority = self.servers[0].priority
        weight_indexes = list(
            (index, server.weight + 1)
            for index, server in enumerate(self.servers)
            if server.priority == min_priority
        )

        total_weight = sum(weight for index, weight in weight_indexes)
        target_weight = random.randint(0, total_weight)

        for index, weight in weight_indexes:
            target_weight -= weight
            if target_weight <= 0:
                server = self.servers[index]
                del self.servers[index]
                self.used_servers.append(server)
                return server

    @defer.inlineCallbacks
    def connect(self, protocolFactory):
        if self.servers is None:
            yield self.fetch_servers()
        server = self.pick_server()
        logger.info("Connecting to %s:%s", server.host, server.port)
        endpoint = self.endpoint(
            self.reactor, server.host, server.port, **self.endpoint_kw_args
        )
        connection = yield endpoint.connect(protocolFactory)
        defer.returnValue(connection)
