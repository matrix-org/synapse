# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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
import logging

import attr
from netaddr import IPAddress
from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.web.client import URI, Agent, HTTPConnectionPool
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent

from synapse.http.federation.srv_resolver import SrvResolver, pick_server_from_list
from synapse.util.logcontext import make_deferred_yieldable

logger = logging.getLogger(__name__)


@implementer(IAgent)
class MatrixFederationAgent(object):
    """An Agent-like thing which provides a `request` method which will look up a matrix
    server and send an HTTP request to it.

    Doesn't implement any retries. (Those are done in MatrixFederationHttpClient.)

    Args:
        reactor (IReactor): twisted reactor to use for underlying requests

        tls_client_options_factory (ClientTLSOptionsFactory|None):
            factory to use for fetching client tls options, or none to disable TLS.

        srv_resolver (SrvResolver|None):
            SRVResolver impl to use for looking up SRV records. None to use a default
            implementation.
    """

    def __init__(
        self, reactor, tls_client_options_factory, _srv_resolver=None,
    ):
        self._reactor = reactor
        self._tls_client_options_factory = tls_client_options_factory
        if _srv_resolver is None:
            _srv_resolver = SrvResolver()
        self._srv_resolver = _srv_resolver

        self._pool = HTTPConnectionPool(reactor)
        self._pool.retryAutomatically = False
        self._pool.maxPersistentPerHost = 5
        self._pool.cachedConnectionTimeout = 2 * 60

    @defer.inlineCallbacks
    def request(self, method, uri, headers=None, bodyProducer=None):
        """
        Args:
            method (bytes): HTTP method: GET/POST/etc

            uri (bytes): Absolute URI to be retrieved

            headers (twisted.web.http_headers.Headers|None):
                HTTP headers to send with the request, or None to
                send no extra headers.

            bodyProducer (twisted.web.iweb.IBodyProducer|None):
                An object which can generate bytes to make up the
                body of this request (for example, the properly encoded contents of
                a file for a file upload).  Or None if the request is to have
                no body.

        Returns:
            Deferred[twisted.web.iweb.IResponse]:
                fires when the header of the response has been received (regardless of the
                response status code). Fails if there is any problem which prevents that
                response from being received (including problems that prevent the request
                from being sent).
        """
        parsed_uri = URI.fromBytes(uri, defaultPort=-1)
        res = yield self._route_matrix_uri(parsed_uri)

        # set up the TLS connection params
        #
        # XXX disabling TLS is really only supported here for the benefit of the
        # unit tests. We should make the UTs cope with TLS rather than having to make
        # the code support the unit tests.
        if self._tls_client_options_factory is None:
            tls_options = None
        else:
            tls_options = self._tls_client_options_factory.get_options(
                res.tls_server_name.decode("ascii")
            )

        # make sure that the Host header is set correctly
        if headers is None:
            headers = Headers()
        else:
            headers = headers.copy()

        if not headers.hasHeader(b'host'):
            headers.addRawHeader(b'host', res.host_header)

        class EndpointFactory(object):
            @staticmethod
            def endpointForURI(_uri):
                logger.info("Connecting to %s:%s", res.target_host, res.target_port)
                ep = HostnameEndpoint(self._reactor, res.target_host, res.target_port)
                if tls_options is not None:
                    ep = wrapClientTLS(tls_options, ep)
                return ep

        agent = Agent.usingEndpointFactory(self._reactor, EndpointFactory(), self._pool)
        res = yield make_deferred_yieldable(
            agent.request(method, uri, headers, bodyProducer)
        )
        defer.returnValue(res)

    @defer.inlineCallbacks
    def _route_matrix_uri(self, parsed_uri):
        """Helper for `request`: determine the routing for a Matrix URI

        Args:
            parsed_uri (twisted.web.client.URI): uri to route. Note that it should be
                parsed with URI.fromBytes(uri, defaultPort=-1) to set the `port` to -1
                if there is no explicit port given.

        Returns:
            Deferred[_RoutingResult]
        """
        # check for an IP literal
        try:
            ip_address = IPAddress(parsed_uri.host.decode("ascii"))
        except Exception:
            # not an IP address
            ip_address = None

        if ip_address:
            port = parsed_uri.port
            if port == -1:
                port = 8448
            defer.returnValue(_RoutingResult(
                host_header=parsed_uri.netloc,
                tls_server_name=parsed_uri.host,
                target_host=parsed_uri.host,
                target_port=port,
            ))

        if parsed_uri.port != -1:
            # there is an explicit port
            defer.returnValue(_RoutingResult(
                host_header=parsed_uri.netloc,
                tls_server_name=parsed_uri.host,
                target_host=parsed_uri.host,
                target_port=parsed_uri.port,
            ))

        # try a SRV lookup
        service_name = b"_matrix._tcp.%s" % (parsed_uri.host,)
        server_list = yield self._srv_resolver.resolve_service(service_name)

        if not server_list:
            target_host = parsed_uri.host
            port = 8448
            logger.debug(
                "No SRV record for %s, using %s:%i",
                parsed_uri.host.decode("ascii"), target_host.decode("ascii"), port,
            )
        else:
            target_host, port = pick_server_from_list(server_list)
            logger.debug(
                "Picked %s:%i from SRV records for %s",
                target_host.decode("ascii"), port, parsed_uri.host.decode("ascii"),
            )

        defer.returnValue(_RoutingResult(
            host_header=parsed_uri.netloc,
            tls_server_name=parsed_uri.host,
            target_host=target_host,
            target_port=port,
        ))


@attr.s
class _RoutingResult(object):
    """The result returned by `_route_matrix_uri`.

    Contains the parameters needed to direct a federation connection to a particular
    server.

    Where a SRV record points to several servers, this object contains a single server
    chosen from the list.
    """

    host_header = attr.ib()
    """
    The value we should assign to the Host header (host:port from the matrix
    URI, or .well-known).

    :type: bytes
    """

    tls_server_name = attr.ib()
    """
    The server name we should set in the SNI (typically host, without port, from the
    matrix URI or .well-known)

    :type: bytes
    """

    target_host = attr.ib()
    """
    The hostname (or IP literal) we should route the TCP connection to (the target of the
    SRV record, or the hostname from the URL/.well-known)

    :type: bytes
    """

    target_port = attr.ib()
    """
    The port we should route the TCP connection to (the target of the SRV record, or
    the port from the URL/.well-known, or 8448)

    :type: int
    """
