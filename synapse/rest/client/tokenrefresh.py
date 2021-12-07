# Copyright 2015, 2016 OpenMarket Ltd
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

from typing import TYPE_CHECKING

from twisted.web.server import Request

from synapse.api.errors import AuthError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer


class TokenRefreshRestServlet(RestServlet):
    """
    Exchanges refresh tokens for a pair of an access token and a new refresh
    token.
    """

    PATTERNS = client_patterns("/tokenrefresh")

    def __init__(self, hs: "HomeServer"):
        super().__init__()

    async def on_POST(self, request: Request) -> None:
        raise AuthError(403, "tokenrefresh is no longer supported.")


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    TokenRefreshRestServlet(hs).register(http_server)
