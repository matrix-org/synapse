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

""" This module contains REST servlets to do with profile: /profile/<paths> """
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class ProfileDisplaynameRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)/displayname", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester_user = None

        if self.hs.config.server.require_auth_for_profile_requests:
            requester = await self.auth.get_user_by_req(request)
            requester_user = requester.user

        if not UserID.is_valid(user_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Invalid user id", Codes.INVALID_PARAM
            )

        user = UserID.from_string(user_id)
        await self.profile_handler.check_profile_query_allowed(user, requester_user)

        displayname = await self.profile_handler.get_displayname(user)

        ret = {}
        if displayname is not None:
            ret["displayname"] = displayname

        return 200, ret

    async def on_PUT(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user = UserID.from_string(user_id)
        is_admin = await self.auth.is_server_admin(requester.user)

        content = parse_json_object_from_request(request)

        try:
            new_name = content["displayname"]
        except Exception:
            raise SynapseError(
                code=400,
                msg="Unable to parse name",
                errcode=Codes.BAD_JSON,
            )

        await self.profile_handler.set_displayname(user, requester, new_name, is_admin)

        return 200, {}


class ProfileAvatarURLRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)/avatar_url", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester_user = None

        if self.hs.config.server.require_auth_for_profile_requests:
            requester = await self.auth.get_user_by_req(request)
            requester_user = requester.user

        if not UserID.is_valid(user_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Invalid user id", Codes.INVALID_PARAM
            )

        user = UserID.from_string(user_id)
        await self.profile_handler.check_profile_query_allowed(user, requester_user)

        avatar_url = await self.profile_handler.get_avatar_url(user)

        ret = {}
        if avatar_url is not None:
            ret["avatar_url"] = avatar_url

        return 200, ret

    async def on_PUT(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)
        is_admin = await self.auth.is_server_admin(requester.user)

        content = parse_json_object_from_request(request)
        try:
            new_avatar_url = content["avatar_url"]
        except KeyError:
            raise SynapseError(
                400, "Missing key 'avatar_url'", errcode=Codes.MISSING_PARAM
            )

        await self.profile_handler.set_avatar_url(
            user, requester, new_avatar_url, is_admin
        )

        return 200, {}


class ProfileRestServlet(RestServlet):
    PATTERNS = client_patterns("/profile/(?P<user_id>[^/]*)", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.profile_handler = hs.get_profile_handler()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester_user = None

        if self.hs.config.server.require_auth_for_profile_requests:
            requester = await self.auth.get_user_by_req(request)
            requester_user = requester.user

        if not UserID.is_valid(user_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "Invalid user id", Codes.INVALID_PARAM
            )

        user = UserID.from_string(user_id)
        await self.profile_handler.check_profile_query_allowed(user, requester_user)

        displayname = await self.profile_handler.get_displayname(user)
        avatar_url = await self.profile_handler.get_avatar_url(user)

        ret = {}
        if displayname is not None:
            ret["displayname"] = displayname
        if avatar_url is not None:
            ret["avatar_url"] = avatar_url

        return 200, ret


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ProfileDisplaynameRestServlet(hs).register(http_server)
    ProfileAvatarURLRestServlet(hs).register(http_server)
    ProfileRestServlet(hs).register(http_server)
