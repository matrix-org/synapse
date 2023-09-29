# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from http.client import TEMPORARY_REDIRECT
from typing import TYPE_CHECKING, Optional

from synapse.http.server import HttpServer, respond_with_redirect
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RendezvousServlet(RestServlet):
    """
    This is a placeholder implementation of [MSC3886](https://github.com/matrix-org/matrix-spec-proposals/pull/3886)
    simple client rendezvous capability that is used by the "Sign in with QR" functionality.

    This implementation only serves as a 307 redirect to a configured server rather than being a full implementation.

    A module that implements the full functionality is available at: https://pypi.org/project/matrix-http-rendezvous-synapse/.

    Request:

    POST /rendezvous HTTP/1.1
    Content-Type: ...

    ...

    Response:

    HTTP/1.1 307
    Location: <configured endpoint>
    """

    PATTERNS = client_patterns(
        "/org.matrix.msc3886/rendezvous$", releases=[], v1=False, unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        redirection_target: Optional[str] = hs.config.experimental.msc3886_endpoint
        assert (
            redirection_target is not None
        ), "Servlet is only registered if there is a redirection target"
        self.endpoint = redirection_target.encode("utf-8")

    async def on_POST(self, request: SynapseRequest) -> None:
        respond_with_redirect(
            request, self.endpoint, statusCode=TEMPORARY_REDIRECT, cors=True
        )

    # PUT, GET and DELETE are not implemented as they should be fulfilled by the redirect target.


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.experimental.msc3886_endpoint is not None:
        RendezvousServlet(hs).register(http_server)
