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
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import AuthError, NotFoundError, StoreError, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict, UserID

from ._base import client_patterns, set_timeline_upper_limit

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class GetFilterRestServlet(RestServlet):
    PATTERNS = client_patterns("/user/(?P<user_id>[^/]*)/filter/(?P<filter_id>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.filtering = hs.get_filtering()

    async def on_GET(
        self, request: SynapseRequest, user_id: str, filter_id: str
    ) -> Tuple[int, JsonDict]:
        target_user = UserID.from_string(user_id)
        requester = await self.auth.get_user_by_req(request)

        if target_user != requester.user:
            raise AuthError(403, "Cannot get filters for other users")

        if not self.hs.is_mine(target_user):
            raise AuthError(403, "Can only get filters for local users")

        try:
            filter_id_int = int(filter_id)
        except Exception:
            raise SynapseError(400, "Invalid filter_id")

        try:
            filter_collection = await self.filtering.get_user_filter(
                user_localpart=target_user.localpart, filter_id=filter_id_int
            )
        except StoreError as e:
            if e.code != 404:
                raise
            raise NotFoundError("No such filter")

        return 200, filter_collection.get_filter_json()


class CreateFilterRestServlet(RestServlet):
    PATTERNS = client_patterns("/user/(?P<user_id>[^/]*)/filter")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.filtering = hs.get_filtering()

    async def on_POST(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:

        target_user = UserID.from_string(user_id)
        requester = await self.auth.get_user_by_req(request)

        if target_user != requester.user:
            raise AuthError(403, "Cannot create filters for other users")

        if not self.hs.is_mine(target_user):
            raise AuthError(403, "Can only create filters for local users")

        content = parse_json_object_from_request(request)
        set_timeline_upper_limit(content, self.hs.config.server.filter_timeline_limit)

        filter_id = await self.filtering.add_user_filter(
            user_localpart=target_user.localpart, user_filter=content
        )

        return 200, {"filter_id": str(filter_id)}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    GetFilterRestServlet(hs).register(http_server)
    CreateFilterRestServlet(hs).register(http_server)
