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

import logging
import urllib.parse
from typing import TYPE_CHECKING, Any, Optional, Tuple, cast

from twisted.internet import protocol
from twisted.internet.interfaces import ITCPTransport
from twisted.internet.protocol import connectionDone
from twisted.python import failure
from twisted.python.failure import Failure
from twisted.web.client import ResponseDone
from twisted.web.http import PotentialDataLoss
from twisted.web.http_headers import Headers
from twisted.web.iweb import IAgent, IResponse
from twisted.web.resource import IResource
from twisted.web.server import Site

from synapse.http import QuieterFileBodyProducer
from synapse.http.server import _AsyncResource
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.types import ISynapseReactor
from synapse.util.async_helpers import timeout_deferred

if TYPE_CHECKING:
    from synapse.http.site import SynapseRequest

logger = logging.getLogger(__name__)


class ProxyResource(_AsyncResource):
    isLeaf = True

    def __init__(self, reactor: ISynapseReactor, federation_agent: IAgent):
        super().__init__(True)

        self.reactor = reactor
        self.agent = federation_agent

    async def _async_render(self, request: "SynapseRequest") -> Tuple[int, Any]:
        uri = urllib.parse.urlparse(request.uri)
        assert uri.scheme == b"matrix-federation"

        logger.info("Got proxy request %s", request.uri)

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
            timeout=90,
            reactor=self.reactor,
        )

        response = await make_deferred_yieldable(request_deferred)

        logger.info("Got proxy response %s", response.code)

        return response.code, response

    def _send_response(
        self,
        request: "SynapseRequest",
        code: int,
        response_object: Any,
    ) -> None:
        response = cast(IResponse, response_object)

        request.setResponseCode(code)

        # Copy headers.
        for k, v in response.headers.getAllRawHeaders():
            request.responseHeaders.setRawHeaders(k, v)

        response.deliverBody(_ProxyResponseBody(request))

    def _send_error_response(
        self,
        f: failure.Failure,
        request: "SynapseRequest",
    ) -> None:
        request.setResponseCode(502)
        request.finish()


class _ProxyResponseBody(protocol.Protocol):
    transport: Optional[ITCPTransport] = None

    def __init__(self, request: "SynapseRequest") -> None:
        self._request = request

    def dataReceived(self, data: bytes) -> None:
        if self._request._disconnected and self.transport is not None:
            self.transport.abortConnection()
            return

        self._request.write(data)

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        if self._request.finished:
            return

        if reason.check(ResponseDone):
            self._request.finish()
        elif reason.check(PotentialDataLoss):
            # TODO: ARGH
            self._request.finish()
        else:
            self._request.transport.abortConnection()


class ProxySite(Site):
    def __init__(
        self,
        resource: IResource,
        reactor: ISynapseReactor,
        federation_agent: IAgent,
    ):
        super().__init__(resource, reactor=reactor)

        self._proxy_resource = ProxyResource(reactor, federation_agent)

    def getResourceFor(self, request: "SynapseRequest") -> IResource:
        uri = urllib.parse.urlparse(request.uri)
        if uri.scheme == b"matrix-federation":
            return self._proxy_resource

        return super().getResourceFor(request)
