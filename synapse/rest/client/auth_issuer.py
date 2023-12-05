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
import typing
from typing import Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if typing.TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class AuthIssuerServlet(RestServlet):
    """
    Advertises what OpenID Connect issuer clients should use to authorise users.
    """

    PATTERNS = client_patterns(
        "/org.matrix.msc2965/auth_issuer$",
        unstable=True,
        releases=(),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._config = hs.config

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        if self._config.experimental.msc3861.enabled:
            return 200, {"issuer": self._config.experimental.msc3861.issuer}
        else:
            # Wouldn't expect this to be reached: the servelet shouldn't have been
            # registered. Still, fail gracefully if we are registered for some reason.
            raise SynapseError(
                404,
                "OIDC discovery has not been configured on this homeserver",
                Codes.NOT_FOUND,
            )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    # We use the MSC3861 values as they are used by multiple MSCs
    if hs.config.experimental.msc3861.enabled:
        AuthIssuerServlet(hs).register(http_server)
