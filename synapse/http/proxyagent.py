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
import logging
import re
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse
from urllib.request import (  # type: ignore[attr-defined]
    getproxies_environment,
    proxy_bypass_environment,
)

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.internet.interfaces import IReactorCore, IStreamClientEndpoint
from twisted.python.failure import Failure
from twisted.web.client import (
    URI,
    BrowserLikePolicyForHTTPS,
    HTTPConnectionPool,
    _AgentBase,
)
from twisted.web.error import SchemeNotSupported
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IBodyProducer, IPolicyForHTTPS

from synapse.http import redact_uri
from synapse.http.connectproxyclient import HTTPConnectProxyEndpoint, ProxyCredentials
from synapse.types import ISynapseReactor

logger = logging.getLogger(__name__)

_VALID_URI = re.compile(rb"\A[\x21-\x7e]+\Z")


@implementer(IAgent)
class ProxyAgent(_AgentBase):
    """An Agent implementation which will use an HTTP proxy if one was requested

    Args:
        reactor: twisted reactor to place outgoing
            connections.

        proxy_reactor: twisted reactor to use for connections to the proxy server
                       reactor might have some blacklisting applied (i.e. for DNS queries),
                       but we need unblocked access to the proxy.

        contextFactory: A factory for TLS contexts, to control the
            verification parameters of OpenSSL.  The default is to use a
            `BrowserLikePolicyForHTTPS`, so unless you have special
            requirements you can leave this as-is.

        connectTimeout: The amount of time that this Agent will wait
            for the peer to accept a connection, in seconds. If 'None',
            HostnameEndpoint's default (30s) will be used.
            This is used for connections to both proxies and destination servers.

        bindAddress: The local address for client sockets to bind to.

        pool: connection pool to be used. If None, a
            non-persistent pool instance will be created.

        use_proxy: Whether proxy settings should be discovered and used
            from conventional environment variables.

    Raises:
        ValueError if use_proxy is set and the environment variables
            contain an invalid proxy specification.
        RuntimeError if no tls_options_factory is given for a https connection
    """

    def __init__(
        self,
        reactor: IReactorCore,
        proxy_reactor: Optional[ISynapseReactor] = None,
        contextFactory: Optional[IPolicyForHTTPS] = None,
        connectTimeout: Optional[float] = None,
        bindAddress: Optional[bytes] = None,
        pool: Optional[HTTPConnectionPool] = None,
        use_proxy: bool = False,
    ):
        contextFactory = contextFactory or BrowserLikePolicyForHTTPS()

        _AgentBase.__init__(self, reactor, pool)

        if proxy_reactor is None:
            self.proxy_reactor = reactor
        else:
            self.proxy_reactor = proxy_reactor

        self._endpoint_kwargs: Dict[str, Any] = {}
        if connectTimeout is not None:
            self._endpoint_kwargs["timeout"] = connectTimeout
        if bindAddress is not None:
            self._endpoint_kwargs["bindAddress"] = bindAddress

        http_proxy = None
        https_proxy = None
        no_proxy = None
        if use_proxy:
            proxies = getproxies_environment()
            http_proxy = proxies["http"].encode() if "http" in proxies else None
            https_proxy = proxies["https"].encode() if "https" in proxies else None
            no_proxy = proxies["no"] if "no" in proxies else None

        self.http_proxy_endpoint, self.http_proxy_creds = http_proxy_endpoint(
            http_proxy, self.proxy_reactor, contextFactory, **self._endpoint_kwargs
        )

        self.https_proxy_endpoint, self.https_proxy_creds = http_proxy_endpoint(
            https_proxy, self.proxy_reactor, contextFactory, **self._endpoint_kwargs
        )

        self.no_proxy = no_proxy

        self._policy_for_https = contextFactory
        self._reactor = reactor

    def request(
        self,
        method: bytes,
        uri: bytes,
        headers: Optional[Headers] = None,
        bodyProducer: Optional[IBodyProducer] = None,
    ) -> defer.Deferred:
        """
        Issue a request to the server indicated by the given uri.

        Supports `http` and `https` schemes.

        An existing connection from the connection pool may be used or a new one may be
        created.

        See also: twisted.web.iweb.IAgent.request

        Args:
            method: The request method to use, such as `GET`, `POST`, etc

            uri: The location of the resource to request.

            headers: Extra headers to send with the request

            bodyProducer: An object which can generate bytes to make up the body of
                this request (for example, the properly encoded contents of a file for
                a file upload). Or, None if the request is to have no body.

        Returns:
            Deferred[IResponse]: completes when the header of the response has
                 been received (regardless of the response status code).

                 Can fail with:
                    SchemeNotSupported: if the uri is not http or https

                    twisted.internet.error.TimeoutError if the server we are connecting
                        to (proxy or destination) does not accept a connection before
                        connectTimeout.

                    ... other things too.
        """
        uri = uri.strip()
        if not _VALID_URI.match(uri):
            raise ValueError(f"Invalid URI {uri!r}")

        parsed_uri = URI.fromBytes(uri)
        pool_key = f"{parsed_uri.scheme!r}{parsed_uri.host!r}{parsed_uri.port}"
        request_path = parsed_uri.originForm

        should_skip_proxy = False
        if self.no_proxy is not None:
            should_skip_proxy = proxy_bypass_environment(
                parsed_uri.host.decode(),
                proxies={"no": self.no_proxy},
            )

        if (
            parsed_uri.scheme == b"http"
            and self.http_proxy_endpoint
            and not should_skip_proxy
        ):
            # Determine whether we need to set Proxy-Authorization headers
            if self.http_proxy_creds:
                # Set a Proxy-Authorization header
                if headers is None:
                    headers = Headers()
                headers.addRawHeader(
                    b"Proxy-Authorization",
                    self.http_proxy_creds.as_proxy_authorization_value(),
                )
            # Cache *all* connections under the same key, since we are only
            # connecting to a single destination, the proxy:
            pool_key = "http-proxy"
            endpoint = self.http_proxy_endpoint
            request_path = uri
        elif (
            parsed_uri.scheme == b"https"
            and self.https_proxy_endpoint
            and not should_skip_proxy
        ):
            endpoint = HTTPConnectProxyEndpoint(
                self.proxy_reactor,
                self.https_proxy_endpoint,
                parsed_uri.host,
                parsed_uri.port,
                self.https_proxy_creds,
            )
        else:
            # not using a proxy
            endpoint = HostnameEndpoint(
                self._reactor, parsed_uri.host, parsed_uri.port, **self._endpoint_kwargs
            )

        logger.debug(
            "Requesting %s via %s",
            redact_uri(uri.decode("ascii", errors="replace")),
            endpoint,
        )

        if parsed_uri.scheme == b"https":
            tls_connection_creator = self._policy_for_https.creatorForNetloc(
                parsed_uri.host, parsed_uri.port
            )
            endpoint = wrapClientTLS(tls_connection_creator, endpoint)
        elif parsed_uri.scheme == b"http":
            pass
        else:
            return defer.fail(
                Failure(
                    SchemeNotSupported("Unsupported scheme: %r" % (parsed_uri.scheme,))
                )
            )

        return self._requestWithEndpoint(
            pool_key, endpoint, method, parsed_uri, headers, bodyProducer, request_path
        )


def http_proxy_endpoint(
    proxy: Optional[bytes],
    reactor: IReactorCore,
    tls_options_factory: Optional[IPolicyForHTTPS],
    **kwargs: object,
) -> Tuple[Optional[IStreamClientEndpoint], Optional[ProxyCredentials]]:
    """Parses an http proxy setting and returns an endpoint for the proxy

    Args:
        proxy: the proxy setting in the form: [scheme://][<username>:<password>@]<host>[:<port>]
            This currently supports http:// and https:// proxies.
            A hostname without scheme is assumed to be http.

        reactor: reactor to be used to connect to the proxy

        tls_options_factory: the TLS options to use when connecting through a https proxy

        kwargs: other args to be passed to HostnameEndpoint

    Returns:
        a tuple of
            endpoint to use to connect to the proxy, or None
            ProxyCredentials or if no credentials were found, or None

    Raise:
        ValueError if proxy has no hostname or unsupported scheme.
        RuntimeError if no tls_options_factory is given for a https connection
    """
    if proxy is None:
        return None, None

    # Note: urlsplit/urlparse cannot be used here as that does not work (for Python
    # 3.9+) on scheme-less proxies, e.g. host:port.
    scheme, host, port, credentials = parse_proxy(proxy)

    proxy_endpoint = HostnameEndpoint(reactor, host, port, **kwargs)

    if scheme == b"https":
        if tls_options_factory:
            tls_options = tls_options_factory.creatorForNetloc(host, port)
            proxy_endpoint = wrapClientTLS(tls_options, proxy_endpoint)
        else:
            raise RuntimeError(
                f"No TLS options for a https connection via proxy {proxy!s}"
            )

    return proxy_endpoint, credentials


def parse_proxy(
    proxy: bytes, default_scheme: bytes = b"http", default_port: int = 1080
) -> Tuple[bytes, bytes, int, Optional[ProxyCredentials]]:
    """
    Parse a proxy connection string.

    Given a HTTP proxy URL, breaks it down into components and checks that it
    has a hostname (otherwise it is not useful to us when trying to find a
    proxy) and asserts that the URL has a scheme we support.


    Args:
        proxy: The proxy connection string. Must be in the form '[scheme://][<username>:<password>@]host[:port]'.
        default_scheme: The default scheme to return if one is not found in `proxy`. Defaults to http
        default_port: The default port to return if one is not found in `proxy`. Defaults to 1080

    Returns:
        A tuple containing the scheme, hostname, port and ProxyCredentials.
            If no credentials were found, the ProxyCredentials instance is replaced with None.

    Raise:
        ValueError if proxy has no hostname or unsupported scheme.
    """
    # First check if we have a scheme present
    # Note: urlsplit/urlparse cannot be used (for Python # 3.9+) on scheme-less proxies, e.g. host:port.
    if b"://" not in proxy:
        proxy = b"".join([default_scheme, b"://", proxy])

    url = urlparse(proxy)

    if not url.hostname:
        raise ValueError("Proxy URL did not contain a hostname! Please specify one.")

    if url.scheme not in (b"http", b"https"):
        raise ValueError(
            f"Unknown proxy scheme {url.scheme!s}; only 'http' and 'https' is supported."
        )

    credentials = None
    if url.username and url.password:
        credentials = ProxyCredentials(b"".join([url.username, b":", url.password]))

    return url.scheme, url.hostname, url.port or default_port, credentials
