# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.internet import defer, reactor
from twisted.internet.error import ConnectError
from twisted.names import client, dns
from twisted.names.error import DNSNameError, DomainError

import collections
import logging
import random
import time


logger = logging.getLogger(__name__)


SERVER_CACHE = {}


_Server = collections.namedtuple(
    "_Server", "priority weight host port expires"
)


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
        transport_endpoint = HostnameEndpoint
        default_port = 8008
    else:
        def transport_endpoint(reactor, host, port, timeout):
            return wrapClientTLS(
                ssl_context_factory,
                HostnameEndpoint(reactor, host, port, timeout=timeout))
        default_port = 8448

    if port is None:
        return _WrappingEndpointFac(SRVClientEndpoint(
            reactor, "matrix", domain, protocol="tcp",
            default_port=default_port, endpoint=transport_endpoint,
            endpoint_kw_args=endpoint_kw_args
        ))
    else:
        return _WrappingEndpointFac(transport_endpoint(
            reactor, domain, port, **endpoint_kw_args
        ))


class _WrappingEndpointFac(object):
    def __init__(self, endpoint_fac):
        self.endpoint_fac = endpoint_fac

    @defer.inlineCallbacks
    def connect(self, protocolFactory):
        conn = yield self.endpoint_fac.connect(protocolFactory)
        conn = _WrappedConnection(conn)
        defer.returnValue(conn)


class _WrappedConnection(object):
    """Wraps a connection and calls abort on it if it hasn't seen any action
    for 2.5-3 minutes.
    """
    __slots__ = ["conn", "last_request"]

    def __init__(self, conn):
        object.__setattr__(self, "conn", conn)
        object.__setattr__(self, "last_request", time.time())

    def __getattr__(self, name):
        return getattr(self.conn, name)

    def __setattr__(self, name, value):
        setattr(self.conn, name, value)

    def _time_things_out_maybe(self):
        # We use a slightly shorter timeout here just in case the callLater is
        # triggered early. Paranoia ftw.
        # TODO: Cancel the previous callLater rather than comparing time.time()?
        if time.time() - self.last_request >= 2.5 * 60:
            self.abort()
            # Abort the underlying TLS connection. The abort() method calls
            # loseConnection() on the underlying TLS connection which tries to
            # shutdown the connection cleanly. We call abortConnection()
            # since that will promptly close the underlying TCP connection.
            self.transport.abortConnection()

    def request(self, request):
        self.last_request = time.time()

        # Time this connection out if we haven't send a request in the last
        # N minutes
        # TODO: Cancel the previous callLater?
        reactor.callLater(3 * 60, self._time_things_out_maybe)

        d = self.conn.request(request)

        def update_request_time(res):
            self.last_request = time.time()
            # TODO: Cancel the previous callLater?
            reactor.callLater(3 * 60, self._time_things_out_maybe)
            return res

        d.addCallback(update_request_time)

        return d


class SpiderEndpoint(object):
    """An endpoint which refuses to connect to blacklisted IP addresses
    Implements twisted.internet.interfaces.IStreamClientEndpoint.
    """
    def __init__(self, reactor, host, port, blacklist, whitelist,
                 endpoint=HostnameEndpoint, endpoint_kw_args={}):
        self.reactor = reactor
        self.host = host
        self.port = port
        self.blacklist = blacklist
        self.whitelist = whitelist
        self.endpoint = endpoint
        self.endpoint_kw_args = endpoint_kw_args

    @defer.inlineCallbacks
    def connect(self, protocolFactory):
        address = yield self.reactor.resolve(self.host)

        from netaddr import IPAddress
        ip_address = IPAddress(address)

        if ip_address in self.blacklist:
            if self.whitelist is None or ip_address not in self.whitelist:
                raise ConnectError(
                    "Refusing to spider blacklisted IP address %s" % address
                )

        logger.info("Connecting to %s:%s", address, self.port)
        endpoint = self.endpoint(
            self.reactor, address, self.port, **self.endpoint_kw_args
        )
        connection = yield endpoint.connect(protocolFactory)
        defer.returnValue(connection)


class SRVClientEndpoint(object):
    """An endpoint which looks up SRV records for a service.
    Cycles through the list of servers starting with each call to connect
    picking the next server.
    Implements twisted.internet.interfaces.IStreamClientEndpoint.
    """

    def __init__(self, reactor, service, domain, protocol="tcp",
                 default_port=None, endpoint=HostnameEndpoint,
                 endpoint_kw_args={}):
        self.reactor = reactor
        self.service_name = "_%s._%s.%s" % (service, protocol, domain)

        if default_port is not None:
            self.default_server = _Server(
                host=domain,
                port=default_port,
                priority=0,
                weight=0,
                expires=0,
            )
        else:
            self.default_server = None

        self.endpoint = endpoint
        self.endpoint_kw_args = endpoint_kw_args

        self.servers = None
        self.used_servers = None

    @defer.inlineCallbacks
    def fetch_servers(self):
        self.used_servers = []
        self.servers = yield resolve_service(self.service_name)

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
                    "Not server available for %s" % self.service_name
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


@defer.inlineCallbacks
def resolve_service(service_name, dns_client=client, cache=SERVER_CACHE, clock=time):
    cache_entry = cache.get(service_name, None)
    if cache_entry:
        if all(s.expires > int(clock.time()) for s in cache_entry):
            servers = list(cache_entry)
            defer.returnValue(servers)

    servers = []

    try:
        try:
            answers, _, _ = yield dns_client.lookupService(service_name)
        except DNSNameError:
            defer.returnValue([])

        if (len(answers) == 1
                and answers[0].type == dns.SRV
                and answers[0].payload
                and answers[0].payload.target == dns.Name('.')):
            raise ConnectError("Service %s unavailable" % service_name)

        for answer in answers:
            if answer.type != dns.SRV or not answer.payload:
                continue

            payload = answer.payload
            host = str(payload.target)
            srv_ttl = answer.ttl

            try:
                answers, _, _ = yield dns_client.lookupAddress(host)
            except DNSNameError:
                continue

            for answer in answers:
                if answer.type == dns.A and answer.payload:
                    ip = answer.payload.dottedQuad()
                    host_ttl = min(srv_ttl, answer.ttl)

                    servers.append(_Server(
                        host=ip,
                        port=int(payload.port),
                        priority=int(payload.priority),
                        weight=int(payload.weight),
                        expires=int(clock.time()) + host_ttl,
                    ))

        servers.sort()
        cache[service_name] = list(servers)
    except DomainError as e:
        # We failed to resolve the name (other than a NameError)
        # Try something in the cache, else rereaise
        cache_entry = cache.get(service_name, None)
        if cache_entry:
            logger.warn(
                "Failed to resolve %r, falling back to cache. %r",
                service_name, e
            )
            servers = list(cache_entry)
        else:
            raise e

    defer.returnValue(servers)
