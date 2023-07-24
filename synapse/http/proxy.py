#  Copyright 2023 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

import json
import logging
import urllib.parse
from typing import TYPE_CHECKING, Any, Optional, Set, Tuple, cast

from twisted.internet import protocol
from twisted.internet.interfaces import ITCPTransport
from twisted.internet.protocol import connectionDone
from twisted.python import failure
from twisted.python.failure import Failure
from twisted.web.client import ResponseDone
from twisted.web.http_headers import Headers
from twisted.web.iweb import IResponse
from twisted.web.resource import IResource
from twisted.web.server import Request, Site

from synapse.api.errors import Codes, InvalidProxyCredentialsError
from synapse.http import QuieterFileBodyProducer
from synapse.http.server import _AsyncResource
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.types import ISynapseReactor
from synapse.util.async_helpers import timeout_deferred

if TYPE_CHECKING:
    from synapse.http.site import SynapseRequest
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# "Hop-by-hop" headers (as opposed to "end-to-end" headers) as defined by RFC2616
# section 13.5.1 and referenced in RFC9110 section 7.6.1. These are meant to only be
# consumed by the immediate recipient and not be forwarded on.
HOP_BY_HOP_HEADERS = {
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailers",
    "Transfer-Encoding",
    "Upgrade",
}


def parse_connection_header_value(
    connection_header_value: Optional[bytes],
) -> Set[str]:
    """
    Parse the `Connection` header to determine which headers we should not be copied
    over from the remote response.

    As defined by RFC2616 section 14.10 and RFC9110 section 7.6.1

    Example: `Connection: close, X-Foo, X-Bar` will return `{"Close", "X-Foo", "X-Bar"}`

    Even though "close" is a special directive, let's just treat it as just another
    header for simplicity. If people want to check for this directive, they can simply
    check for `"Close" in headers`.

    Args:
        connection_header_value: The value of the `Connection` header.

    Returns:
        The set of header names that should not be copied over from the remote response.
        The keys are capitalized in canonical capitalization.
    """
    headers = Headers()
    extra_headers_to_remove: Set[str] = set()
    if connection_header_value:
        extra_headers_to_remove = {
            headers._canonicalNameCaps(connection_option.strip()).decode("ascii")
            for connection_option in connection_header_value.split(b",")
        }

    return extra_headers_to_remove


class ProxyResource(_AsyncResource):
    """
    A stub resource that proxies any requests with a `matrix-federation://` scheme
    through the given `federation_agent` to the remote homeserver and ferries back the
    info.
    """

    isLeaf = True

    def __init__(self, reactor: ISynapseReactor, hs: "HomeServer"):
        super().__init__(True)

        self.reactor = reactor
        self.agent = hs.get_federation_http_client().agent

        self._proxy_authorization_secret = hs.config.worker.worker_replication_secret

    def _check_auth(self, request: Request) -> None:
        # The `matrix-federation://` proxy functionality can only be used with auth.
        # Protect homserver admins forgetting to configure a secret.
        assert self._proxy_authorization_secret is not None

        # Get the authorization header.
        auth_headers = request.requestHeaders.getRawHeaders(b"Proxy-Authorization")

        if not auth_headers:
            raise InvalidProxyCredentialsError(
                "Missing Proxy-Authorization header.", Codes.MISSING_TOKEN
            )
        if len(auth_headers) > 1:
            raise InvalidProxyCredentialsError(
                "Too many Proxy-Authorization headers.", Codes.UNAUTHORIZED
            )
        parts = auth_headers[0].split(b" ")
        if parts[0] == b"Bearer" and len(parts) == 2:
            received_secret = parts[1].decode("ascii")
            if self._proxy_authorization_secret == received_secret:
                # Success!
                return

        raise InvalidProxyCredentialsError(
            "Invalid Proxy-Authorization header.", Codes.UNAUTHORIZED
        )

    async def _async_render(self, request: "SynapseRequest") -> Tuple[int, Any]:
        uri = urllib.parse.urlparse(request.uri)
        assert uri.scheme == b"matrix-federation"

        # Check the authorization headers before handling the request.
        self._check_auth(request)

        headers = Headers()
        for header_name in (b"User-Agent", b"Authorization", b"Content-Type"):
            header_value = request.getHeader(header_name)
            if header_value:
                headers.addRawHeader(header_name, header_value)

        request_deferred = run_in_background(
            self.agent.request,
            request.method,
            request.uri,
            headers=headers,
            bodyProducer=QuieterFileBodyProducer(request.content),
        )
        request_deferred = timeout_deferred(
            request_deferred,
            # This should be set longer than the timeout in `MatrixFederationHttpClient`
            # so that it has enough time to complete and pass us the data before we give
            # up.
            timeout=90,
            reactor=self.reactor,
        )

        response = await make_deferred_yieldable(request_deferred)

        return response.code, response

    def _send_response(
        self,
        request: "SynapseRequest",
        code: int,
        response_object: Any,
    ) -> None:
        response = cast(IResponse, response_object)
        response_headers = cast(Headers, response.headers)

        request.setResponseCode(code)

        # The `Connection` header also defines which headers should not be copied over.
        connection_header = response_headers.getRawHeaders(b"connection")
        extra_headers_to_remove = parse_connection_header_value(
            connection_header[0] if connection_header else None
        )

        # Copy headers.
        for k, v in response_headers.getAllRawHeaders():
            # Do not copy over any hop-by-hop headers. These are meant to only be
            # consumed by the immediate recipient and not be forwarded on.
            header_key = k.decode("ascii")
            if (
                header_key in HOP_BY_HOP_HEADERS
                or header_key in extra_headers_to_remove
            ):
                continue

            request.responseHeaders.setRawHeaders(k, v)

        response.deliverBody(_ProxyResponseBody(request))

    def _send_error_response(
        self,
        f: failure.Failure,
        request: "SynapseRequest",
    ) -> None:
        if isinstance(f.value, InvalidProxyCredentialsError):
            error_response_code = f.value.code
            error_response_json = {"errcode": f.value.errcode, "err": f.value.msg}
        else:
            error_response_code = 502
            error_response_json = {
                "errcode": Codes.UNKNOWN,
                "err": "ProxyResource: Error when proxying request: %s %s -> %s"
                % (
                    request.method.decode("ascii"),
                    request.uri.decode("ascii"),
                    f,
                ),
            }

        request.setResponseCode(error_response_code)
        request.setHeader(b"Content-Type", b"application/json")
        request.write((json.dumps(error_response_json)).encode())
        request.finish()


class _ProxyResponseBody(protocol.Protocol):
    """
    A protocol that proxies the given remote response data back out to the given local
    request.
    """

    transport: Optional[ITCPTransport] = None

    def __init__(self, request: "SynapseRequest") -> None:
        self._request = request

    def dataReceived(self, data: bytes) -> None:
        # Avoid sending response data to the local request that already disconnected
        if self._request._disconnected and self.transport is not None:
            # Close the connection (forcefully) since all the data will get
            # discarded anyway.
            self.transport.abortConnection()
            return

        self._request.write(data)

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        # If the local request is already finished (successfully or failed), don't
        # worry about sending anything back.
        if self._request.finished:
            return

        if reason.check(ResponseDone):
            self._request.finish()
        else:
            # Abort the underlying request since our remote request also failed.
            self._request.transport.abortConnection()


class ProxySite(Site):
    """
    Proxies any requests with a `matrix-federation://` scheme through the given
    `federation_agent`. Otherwise, behaves like a normal `Site`.
    """

    def __init__(
        self,
        resource: IResource,
        reactor: ISynapseReactor,
        hs: "HomeServer",
    ):
        super().__init__(resource, reactor=reactor)

        self._proxy_resource = ProxyResource(reactor, hs=hs)

    def getResourceFor(self, request: "SynapseRequest") -> IResource:
        uri = urllib.parse.urlparse(request.uri)
        if uri.scheme == b"matrix-federation":
            return self._proxy_resource

        return super().getResourceFor(request)
