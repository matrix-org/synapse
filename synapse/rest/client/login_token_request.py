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

from synapse.api.ratelimiting import Ratelimiter
from synapse.config.ratelimiting import RatelimitSettings
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

    POST /login/get_token HTTP/1.1
    Content-Type: application/json

    {}

    Response:

    HTTP/1.1 200 OK
    {
        "login_token": "ABDEFGH",
        "expires_in_ms": 3600000,
    }
    """

    PATTERNS = [
        *client_patterns(
            "/login/get_token$", releases=["v1"], v1=False, unstable=False
        ),
        # TODO: this is no longer needed once unstable MSC3882 does not need to be supported:
        *client_patterns(
            "/org.matrix.msc3882/login/token$", releases=[], v1=False, unstable=True
        ),
    ]

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self._main_store = hs.get_datastores().main
        self.auth_handler = hs.get_auth_handler()
        self.token_timeout = hs.config.auth.login_via_existing_token_timeout
        self._require_ui_auth = hs.config.auth.login_via_existing_require_ui_auth

        # Ratelimit aggressively to a maximum of 1 request per minute.
        #
        # This endpoint can be used to spawn additional sessions and could be
        # abused by a malicious client to create many sessions.
        self._ratelimiter = Ratelimiter(
            store=self._main_store,
            clock=hs.get_clock(),
            cfg=RatelimitSettings(
                key="<login token request>",
                per_second=1 / 60,
                burst_count=1,
            ),
        )

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)

        if self._require_ui_auth:
            await self.auth_handler.validate_user_via_ui_auth(
                requester,
                request,
                body,
                "issue a new access token for your account",
                can_skip_ui_auth=False,  # Don't allow skipping of UI auth
            )

        # Ensure that this endpoint isn't being used too often. (Ensure this is
        # done *after* UI auth.)
        await self._ratelimiter.ratelimit(None, requester.user.to_string().lower())

        login_token = await self.auth_handler.create_login_token_for_user_id(
            user_id=requester.user.to_string(),
            duration_ms=self.token_timeout,
        )

        return (
            200,
            {
                "login_token": login_token,
                # TODO: this is no longer needed once unstable MSC3882 does not need to be supported:
                "expires_in": self.token_timeout // 1000,
                "expires_in_ms": self.token_timeout,
            },
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.config.auth.login_via_existing_enabled:
        LoginTokenRequestServlet(hs).register(http_server)
