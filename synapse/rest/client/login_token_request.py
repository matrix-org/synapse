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
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns, interactive_auth_handler
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class LoginTokenRequestServlet(RestServlet):
    """
    Get a token that can be used with `m.login.token` to log in a second device.

    Request:

    POST /login/token HTTP/1.1
    Content-Type: application/json

    {}

    Response:

    HTTP/1.1 200 OK
    {
        "login_token": "ABDEFGH",
        "expires_in": 3600,
    }
    """

    PATTERNS = client_patterns(
        "/org.matrix.msc3882/login/token$", releases=[], v1=False, unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.server_name = hs.config.server.server_name
        self.macaroon_gen = hs.get_macaroon_generator()
        self.auth_handler = hs.get_auth_handler()
        self.token_timeout = hs.config.experimental.msc3882_token_timeout
        self.ui_auth = hs.config.experimental.msc3882_ui_auth

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)

        if self.ui_auth:
            await self.auth_handler.validate_user_via_ui_auth(
                requester,
                request,
                body,
                "issue a new access token for your account",
                can_skip_ui_auth=False,  # Don't allow skipping of UI auth
            )

        login_token = self.macaroon_gen.generate_short_term_login_token(
            user_id=requester.user.to_string(),
            auth_provider_id="org.matrix.msc3882.login_token_request",
            duration_in_ms=self.token_timeout,
        )

        return (
            200,
            {
                "login_token": login_token,
                "expires_in": self.token_timeout // 1000,
            },
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.experimental.msc3882_enabled:
        LoginTokenRequestServlet(hs).register(http_server)
