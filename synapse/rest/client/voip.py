# Copyright 2014-2016 OpenMarket Ltd
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

import base64
import hashlib
import hmac
from typing import TYPE_CHECKING, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


class VoipRestServlet(RestServlet):
    PATTERNS = client_patterns("/voip/turnServer$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(
            request, self.hs.config.voip.turn_allow_guests
        )

        turnUris = self.hs.config.voip.turn_uris
        turnSecret = self.hs.config.voip.turn_shared_secret
        turnUsername = self.hs.config.voip.turn_username
        turnPassword = self.hs.config.voip.turn_password
        userLifetime = self.hs.config.voip.turn_user_lifetime

        if turnUris and turnSecret and userLifetime:
            expiry = (self.hs.get_clock().time_msec() + userLifetime) / 1000
            username = "%d:%s" % (expiry, requester.user.to_string())

            mac = hmac.new(
                turnSecret.encode(), msg=username.encode(), digestmod=hashlib.sha1
            )
            # We need to use standard padded base64 encoding here
            # encode_base64 because we need to add the standard padding to get the
            # same result as the TURN server.
            password = base64.b64encode(mac.digest()).decode("ascii")

        elif turnUris and turnUsername and turnPassword and userLifetime:
            username = turnUsername
            password = turnPassword

        else:
            return 200, {}

        return (
            200,
            {
                "username": username,
                "password": password,
                "ttl": userLifetime // 1000,
                "uris": turnUris,
            },
        )


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    VoipRestServlet(hs).register(http_server)
