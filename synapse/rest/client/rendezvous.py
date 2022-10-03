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

from http.client import TEMPORARY_REDIRECT
import logging
from typing import TYPE_CHECKING

from synapse.http.server import HttpServer, respond_with_redirect
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RendezvousServlet(RestServlet):
    """
    Get a token that can be used with `m.login.token` to log in a second device.

    Request:

    POST /rendezvous HTTP/1.1
    Content-Type: ...

    ...

    Response:

    HTTP/1.1 302
    Location: <configured endpoint>
    """

    PATTERNS = client_patterns(
        "/org.matrix.msc3886/rendezvous$", releases=[], v1=False, unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.endpoint = hs.config.experimental.msc3886_endpoint.encode("utf-8")

    async def on_POST(self, request: SynapseRequest) -> None:
        respond_with_redirect(request, self.endpoint, statusCode=TEMPORARY_REDIRECT, cors=True)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if not hs.config.experimental.msc3886_endpoint is None:
        RendezvousServlet(hs).register(http_server)
