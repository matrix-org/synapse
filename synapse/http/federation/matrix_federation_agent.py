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

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.web.client import URI, Agent, HTTPConnectionPool
from twisted.web.iweb import IAgent

from synapse.http.endpoint import parse_server_name
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

        parsed_uri = URI.fromBytes(uri)
        server_name_bytes = parsed_uri.netloc
        host, port = parse_server_name(server_name_bytes.decode("ascii"))

        # XXX disabling TLS is really only supported here for the benefit of the
        # unit tests. We should make the UTs cope with TLS rather than having to make
        # the code support the unit tests.
        if self._tls_client_options_factory is None:
            tls_options = None
        else:
            tls_options = self._tls_client_options_factory.get_options(host)

        if port is not None:
            target = (host, port)
        else:
            service_name = b"_matrix._tcp.%s" % (server_name_bytes, )
            server_list = yield self._srv_resolver.resolve_service(service_name)
            if not server_list:
                target = (host, 8448)
                logger.debug("No SRV record for %s, using %s", host, target)
            else:
                target = pick_server_from_list(server_list)

        class EndpointFactory(object):
            @staticmethod
            def endpointForURI(_uri):
                logger.info("Connecting to %s:%s", target[0], target[1])
                ep = HostnameEndpoint(self._reactor, host=target[0], port=target[1])
                if tls_options is not None:
                    ep = wrapClientTLS(tls_options, ep)
                return ep

        agent = Agent.usingEndpointFactory(self._reactor, EndpointFactory(), self._pool)
        res = yield make_deferred_yieldable(
            agent.request(method, uri, headers, bodyProducer)
        )
        defer.returnValue(res)
