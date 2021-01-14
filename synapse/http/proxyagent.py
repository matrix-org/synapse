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
import logging
import re

from zope.interface import implementer

from twisted.internet import defer
from twisted.internet.endpoints import HostnameEndpoint, wrapClientTLS
from twisted.python.failure import Failure
from twisted.web.client import URI, BrowserLikePolicyForHTTPS, _AgentBase
from twisted.web.error import SchemeNotSupported
from twisted.web.iweb import IAgent

from synapse.http.connectproxyclient import HTTPConnectProxyEndpoint

logger = logging.getLogger(__name__)

_VALID_URI = re.compile(br"\A[\x21-\x7e]+\Z")


@implementer(IAgent)
class ProxyAgent(_AgentBase):
    """An Agent implementation which will use an HTTP proxy if one was requested

    Args:
        reactor: twisted reactor to place outgoing
            connections.

        proxy_reactor: twisted reactor to use for connections to the proxy server
                       reactor might have some blacklisting applied (i.e. for DNS queries),
                       but we need unblocked access to the proxy.

        contextFactory (IPolicyForHTTPS): A factory for TLS contexts, to control the
            verification parameters of OpenSSL.  The default is to use a
            `BrowserLikePolicyForHTTPS`, so unless you have special
            requirements you can leave this as-is.

        connectTimeout (Optional[float]): The amount of time that this Agent will wait
            for the peer to accept a connection, in seconds. If 'None',
            HostnameEndpoint's default (30s) will be used.

            This is used for connections to both proxies and destination servers.

        bindAddress (bytes): The local address for client sockets to bind to.

        pool (HTTPConnectionPool|None): connection pool to be used. If None, a
            non-persistent pool instance will be created.
    """

    def __init__(
        self,
        reactor,
        proxy_reactor=None,
        contextFactory=BrowserLikePolicyForHTTPS(),
        connectTimeout=None,
        bindAddress=None,
        pool=None,
        http_proxy=None,
        https_proxy=None,
    ):
        _AgentBase.__init__(self, reactor, pool)

        if proxy_reactor is None:
            self.proxy_reactor = reactor
        else:
            self.proxy_reactor = proxy_reactor

        self._endpoint_kwargs = {}
        if connectTimeout is not None:
            self._endpoint_kwargs["timeout"] = connectTimeout
        if bindAddress is not None:
            self._endpoint_kwargs["bindAddress"] = bindAddress

        self.http_proxy_endpoint = _http_proxy_endpoint(
            http_proxy, self.proxy_reactor, **self._endpoint_kwargs
        )

        self.https_proxy_endpoint = _http_proxy_endpoint(
            https_proxy, self.proxy_reactor, **self._endpoint_kwargs
        )

        self._policy_for_https = contextFactory
        self._reactor = reactor

    def request(self, method, uri, headers=None, bodyProducer=None):
        """
        Issue a request to the server indicated by the given uri.

        Supports `http` and `https` schemes.

        An existing connection from the connection pool may be used or a new one may be
        created.

        See also: twisted.web.iweb.IAgent.request

        Args:
            method (bytes): The request method to use, such as `GET`, `POST`, etc

            uri (bytes): The location of the resource to request.

            headers (Headers|None): Extra headers to send with the request

            bodyProducer (IBodyProducer|None): An object which can generate bytes to
                make up the body of this request (for example, the properly encoded
                contents of a file for a file upload). Or, None if the request is to
                have no body.

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
            raise ValueError("Invalid URI {!r}".format(uri))

        parsed_uri = URI.fromBytes(uri)
        pool_key = (parsed_uri.scheme, parsed_uri.host, parsed_uri.port)
        request_path = parsed_uri.originForm

        if parsed_uri.scheme == b"http" and self.http_proxy_endpoint:
            # Cache *all* connections under the same key, since we are only
            # connecting to a single destination, the proxy:
            pool_key = ("http-proxy", self.http_proxy_endpoint)
            endpoint = self.http_proxy_endpoint
            request_path = uri
        elif parsed_uri.scheme == b"https" and self.https_proxy_endpoint:
            endpoint = HTTPConnectProxyEndpoint(
                self.proxy_reactor,
                self.https_proxy_endpoint,
                parsed_uri.host,
                parsed_uri.port,
            )
        else:
            # not using a proxy
            endpoint = HostnameEndpoint(
                self._reactor, parsed_uri.host, parsed_uri.port, **self._endpoint_kwargs
            )

        logger.debug("Requesting %s via %s", uri, endpoint)

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


def _http_proxy_endpoint(proxy, reactor, **kwargs):
    """Parses an http proxy setting and returns an endpoint for the proxy

    Args:
        proxy (bytes|None):  the proxy setting
        reactor: reactor to be used to connect to the proxy
        kwargs: other args to be passed to HostnameEndpoint

    Returns:
        interfaces.IStreamClientEndpoint|None: endpoint to use to connect to the proxy,
            or None
    """
    if proxy is None:
        return None

    # currently we only support hostname:port. Some apps also support
    # protocol://<host>[:port], which allows a way of requiring a TLS connection to the
    # proxy.

    host, port = parse_host_port(proxy, default_port=1080)
    return HostnameEndpoint(reactor, host, port, **kwargs)


def parse_host_port(hostport, default_port=None):
    # could have sworn we had one of these somewhere else...
    if b":" in hostport:
        host, port = hostport.rsplit(b":", 1)
        try:
            port = int(port)
            return host, port
        except ValueError:
            # the thing after the : wasn't a valid port; presumably this is an
            # IPv6 address.
            pass

    return hostport, default_port
