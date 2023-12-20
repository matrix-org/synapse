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
from typing import Optional, Tuple

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import (
    HostnameEndpoint,
    UNIXClientEndpoint,
    wrapClientTLS,
)
from twisted.internet.interfaces import IStreamClientEndpoint
from twisted.python.failure import Failure
from twisted.web.client import URI, HTTPConnectionPool, _AgentBase
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
class BasicEndpointFactory:
    """Connect to a given TCP or UNIX socket"""

    def __init__(
        self,
        reactor: ISynapseReactor,
        context_factory: IPolicyForHTTPS,
    ) -> None:
        self.reactor = reactor
        self.context_factory = context_factory

    def endpointForURI(self, uri: URI) -> IStreamClientEndpoint:
        """
        This part of the factory decides what kind of endpoint is being connected to
        based on the uri scheme.

        Args:
            uri: The pre-parsed URI object containing all the uri data

        Returns: The correct client endpoint object
        """

        # both http and https start with http, use that fact
        if uri.scheme.startswith(b"http"):
            endpoint = HostnameEndpoint(
                self.reactor,
                uri.host,
                uri.port,
            )
            if uri.scheme == b"https":
                endpoint = wrapClientTLS(
                    # The 'port' argument below isn't actually used by the function.
                    # uri.host is in bytes
                    self.context_factory.creatorForNetloc(
                        uri.host,
                        uri.port,
                    ),
                    endpoint,
                )
            return endpoint
        elif uri.scheme == b"unix":
            # The uri.path was sanitized in request() from ApplicationServiceAgent
            return UNIXClientEndpoint(self.reactor, uri.path)
        else:
            raise SchemeNotSupported(f"Unsupported scheme: {uri.scheme}")


@implementer(IAgent)
class ApplicationServiceAgent(_AgentBase):
    def __init__(
        self,
        reactor: ISynapseReactor,
        contextFactory: IPolicyForHTTPS,
        connectTimeout: Optional[float] = None,
        bindAddress: Optional[bytes] = None,
        pool: Optional[HTTPConnectionPool] = None,
    ) -> None:
        _AgentBase.__init__(self, reactor, pool)
        # After above, these are set:
        #  self._reactor = reactor
        #  self._pool = pool(Which will be a 'non-persistent' pool if None)
        self._endpointFactory = BasicEndpointFactory(self._reactor, contextFactory)
        self._timeout = connectTimeout

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

        Currently, HTTP, HTTPS and UNIX schemes are supported in uri.

        This is copied from twisted.web.client.Agent, except:

        * It uses a different pool key (combining the scheme with either host & port or
          socket path).
        * It doesn't check a uri against _ensureValidURI(), as the strictness of
          IDNA2008 shouldn't be necessary when dealing with an appservice. Should allow
          for lax docker names and isn't relevant for Unix sockets.(It is also not used
          anywhere in Synapse, and doesn't come into Twisted until 19.7.0 which is well
          above the current minimum version supported anyway)

        See: twisted.web.iweb.IAgent.request
        """
        uri = uri.strip()
        # First check if the uri is for a Unix Socket
        if uri.startswith(b"unix") and b":" in uri:
            (
                uri_socket_path,
                path_and_query_uri,
            ) = _split_uri_bytes_on_colon_for_unix_socket(uri)
            endpoint_uri = URI.fromBytes(uri_socket_path)
            parsed_uri = URI.fromBytes(path_and_query_uri)
            # The parsed_uri will need to have a 'http://localhost' placeholder(I think)
            parsed_uri.scheme = b"http"
            parsed_uri.netloc = b"localhost"
        else:
            parsed_uri = URI.fromBytes(uri)
            # netloc will be either a hostname or a [host|ip]:port
            endpoint_uri = URI.fromBytes(parsed_uri.scheme + b"://" + parsed_uri.netloc)

        # Then create the Endpoint which will be used by the pool key and the request
        try:
            endpoint = self._endpointFactory.endpointForURI(endpoint_uri)
        except SchemeNotSupported:
            return defer.fail(Failure())

        # Identify the pool key
        if isinstance(endpoint, UNIXClientEndpoint):
            key = (endpoint_uri.scheme, endpoint_uri.path)
        else:
            key = (endpoint_uri.scheme, endpoint_uri.netloc)

        # _requestWithEndpoint comes from _AgentBase class
        return self._requestWithEndpoint(
            key,
            endpoint,
            method,
            parsed_uri,
            headers,
            bodyProducer,
            parsed_uri.originForm,
        )


def _split_uri_bytes_on_colon_for_unix_socket(uri: bytes) -> Tuple[bytes, bytes]:
    """
    Helper to take the byte string of uri:
    * split it at the (second) colon, and
    * sanitize the number of `/` at the leading edge of the socket file path

    Given a byte string of the format 'unix:/path/to.socket:/some_path?query?blah=1'
    break the string at the colon following the socket file name and return both parts.

    Note: between the 'scheme' and the 'file path' can be between one and three '/'
    marks. URI can handle one or three but not two, cleanly. This will be sanitized to a
    single '/' as it looks cleanest(and reduces superfluous bytes).

    Returns
        2-Tuple of byte strings appropriate for consumption by URI.fromBytes()
    """
    # (using 'unix:/var/run/synapse.socket' as an example...)
    # the URI object parses(via urllib.parse.urlparse()) a Unix Socket uri into:
    # uri.scheme = b'unix'
    # uri.path = b'/var/run/synapse.socket'
    # long as the original uri it was parsed from has either one or three `/`s
    # after the first `:` after the scheme.
    # If for some reason there are only two, the uri will be parsed as:
    # (using 'unix://var/run/synapse.socket' as an example...)
    # uri.scheme = b'unix'
    # uri.netloc = b'var'
    # uri.path = b'/run/synapse.socket'
    # To deal with all that, just strip off the leading '/' and add a single to clean it
    assert uri.startswith(b"unix")
    list_of_uri_parts = uri.split(b":")
    # [0] = 'unix'
    # [1] = '///path/to.socket' or '/path/to.socket' (doesn't matter)
    # [2] = the rest of the path and query for the request
    # Rejoin the first two parts,
    unix_socket_path = list_of_uri_parts[0] + b":/" + list_of_uri_parts[1].lstrip(b"/")
    uri_path_and_query = list_of_uri_parts[2]
    return unix_socket_path, uri_path_and_query
