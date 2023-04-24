# Copyright 2023 The Matrix.org Foundation C.I.C.
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
from typing import Optional

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.python.failure import Failure
from twisted.web.client import (
    URI,
    HTTPConnectionPool,
    _AgentBase,
    _DeprecatedToCurrentPolicyForHTTPS,
)
from twisted.web.error import SchemeNotSupported
from twisted.web.http_headers import Headers
from twisted.web.iweb import (
    IAgent,
    IAgentEndpointFactory,
    IBodyProducer,
    IPolicyForHTTPS,
    IResponse,
)

from synapse.types import ISynapseReactor

logger = logging.getLogger(__name__)


@implementer(IAgentEndpointFactory)
class ReplicationEndpointFactory:
    """Connect to a given TCP socket"""

    def __init__(
        self,
        reactor: ISynapseReactor,
        context_factory: Optional[IPolicyForHTTPS],
    ) -> None:
        self.reactor = reactor
        self.context_factory = context_factory

    def endpointForURI(self, uri: URI) -> IStreamClientEndpoint:
        """
        This part of the factory decides what kind of endpoint is being connected to.

        Args:
            uri: The pre-parsed URI object containing all the uri data

        Returns: The correct client endpoint object
        """
        if b"http" in uri.scheme:
            endpoint = HostnameEndpoint(self.reactor, uri.host, int(uri.port))
            if uri.scheme == b"https":
                endpoint = wrapClientTLS(self.context_factory, endpoint)
            return endpoint
        else:
            raise SchemeNotSupported()


@implementer(IAgent)
class ReplicationAgent(_AgentBase):
    """
    This Agent is solely for the purposes of connecting to Synapse replication
    endpoints, and can handle https and http connections. Appropriate comments are
    copied from Twisted's Agent Class.

    Attributes:
        _endpointFactory: The IAgentEndpointFactory which will
            be used to create endpoints for outgoing TCP connections.
    """

    def __init__(
        self,
        reactor: ISynapseReactor,
        contextFactory: Optional[IPolicyForHTTPS] = None,
        connectTimeout: Optional[float] = None,
        bindAddress: Optional[bytes] = None,
        pool: Optional[HTTPConnectionPool] = None,
    ):
        """
        Create a ReplicationAgent.

        Args:
            reactor: A reactor for this Agent to place outgoing connections.
            hs: The HomeServer instance
            contextFactory: A factory for TLS contexts, to control the
                verification parameters of OpenSSL.  The default is to use a
                BrowserLikePolicyForHTTPS, so unless you have special
                requirements you can leave this as-is.
            connectTimeout: The amount of time that this Agent will wait
                for the peer to accept a connection.
            bindAddress: The local address for client sockets to bind to.
            pool: An HTTPConnectionPool instance, or None, in which
                case a non-persistent HTTPConnectionPool instance will be
                created.
        """
        if not IPolicyForHTTPS.providedBy(contextFactory):
            logger.warning(
                f"{contextFactory} was passed as the HTTPS policy for an "
                "Agent, but it does not provide IPolicyForHTTPS.  Since Twisted 14.0, "
                "you must pass a provider of IPolicyForHTTPS.",
            )
            contextFactory = _DeprecatedToCurrentPolicyForHTTPS(contextFactory)

        _AgentBase.__init__(self, reactor, pool)
        endpoint_factory = ReplicationEndpointFactory(reactor, contextFactory)
        self._endpointFactory = endpoint_factory

    def _getEndpoint(self, uri: URI) -> IStreamClientEndpoint:
        """
        Get an endpoint for the given URI, using self._endpointFactory.
            uri: The URI of the request.
        Returns: An endpoint which can be used to connect to given address.
        """
        return self._endpointFactory.endpointForURI(uri)

    def request(
        self,
        method: bytes,
        uri: bytes,
        headers: Optional[Headers] = None,
        bodyProducer: Optional[IBodyProducer] = None,
    ) -> "defer.Deferred[IResponse]":
        """
        Issue a request to the server indicated by the given uri.
        An existing connection from the connection pool may be used or a new
        one may be created.
        Currently, HTTP and HTTPS schemes are supported in uri.

        See: twisted.web.iweb.IAgent.request
        """
        # This function is overridden in preparation of future work:
        # * So as to properly set a key for the pool and
        # * to remove an _ensureValidURI() that will be in the way.
        parsedURI = URI.fromBytes(uri)
        try:
            endpoint = self._getEndpoint(parsedURI)
        except SchemeNotSupported:
            return defer.fail(Failure())

        # This sets the Pool key to be:
        #  (http(s), <host:ip>)
        key = (parsedURI.scheme, parsedURI.netloc)

        # _requestWithEndpoint comes from _AgentBase class
        return self._requestWithEndpoint(
            key,
            endpoint,
            method,
            parsedURI,
            headers,
            bodyProducer,
            parsedURI.originForm,
        )
