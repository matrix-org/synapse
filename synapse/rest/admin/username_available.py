# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.http.servlet import RestServlet, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class UsernameAvailableRestServlet(RestServlet):
    """An admin API to check if a given username is available, regardless of whether registration is enabled.

    Example:
        GET /_synapse/admin/v1/username_available?username=foo
        200 OK
        {
            "available": true
        }
    """

    PATTERNS = admin_patterns("/username_available$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.registration_handler = hs.get_registration_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        username = parse_string(request, "username", required=True)
        await self.registration_handler.check_username(username)
        return HTTPStatus.OK, {"available": True}
