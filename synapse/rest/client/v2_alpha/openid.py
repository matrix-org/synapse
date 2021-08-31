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


import logging

from synapse.api.errors import AuthError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.util.stringutils import random_string

from ._base import client_patterns

logger = logging.getLogger(__name__)


class IdTokenServlet(RestServlet):
    """
    Get a bearer token that may be passed to a third party to confirm ownership
    of a matrix user id.

    The format of the response could be made compatible with the format given
    in http://openid.net/specs/openid-connect-core-1_0.html#TokenResponse

    But instead of returning a signed "id_token" the response contains the
    name of the issuing matrix homeserver. This means that for now the third
    party will need to check the validity of the "id_token" against the
    federation /openid/userinfo endpoint of the homeserver.

    Request:

    POST /user/{user_id}/openid/request_token?access_token=... HTTP/1.1

    {}

    Response:

    HTTP/1.1 200 OK
    {
        "access_token": "ABDEFGH",
        "token_type": "Bearer",
        "matrix_server_name": "example.com",
        "expires_in": 3600,
    }
    """

    PATTERNS = client_patterns("/user/(?P<user_id>[^/]*)/openid/request_token")

    EXPIRES_MS = 3600 * 1000

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.server_name = hs.config.server_name

    async def on_POST(self, request, user_id):
        requester = await self.auth.get_user_by_req(request)
        if user_id != requester.user.to_string():
            raise AuthError(403, "Cannot request tokens for other users.")

        # Parse the request body to make sure it's JSON, but ignore the contents
        # for now.
        parse_json_object_from_request(request)

        token = random_string(24)
        ts_valid_until_ms = self.clock.time_msec() + self.EXPIRES_MS

        await self.store.insert_open_id_token(token, ts_valid_until_ms, user_id)

        return (
            200,
            {
                "access_token": token,
                "token_type": "Bearer",
                "matrix_server_name": self.server_name,
                "expires_in": self.EXPIRES_MS / 1000,
            },
        )


def register_servlets(hs, http_server):
    IdTokenServlet(hs).register(http_server)
