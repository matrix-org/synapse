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

import logging
from typing import TYPE_CHECKING, List, Optional, Tuple

from pydantic import StrictStr
from typing_extensions import Literal

from twisted.web.server import Request

from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_and_validate_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.rest.models import RequestBodyModel
from synapse.types import JsonDict, RoomAlias

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ClientDirectoryServer(hs).register(http_server)
    ClientDirectoryListServer(hs).register(http_server)
    ClientAppserviceDirectoryListServer(hs).register(http_server)


class ClientDirectoryServer(RestServlet):
    PATTERNS = client_patterns("/directory/room/(?P<room_alias>[^/]*)$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastores().main
        self.directory_handler = hs.get_directory_handler()
        self.auth = hs.get_auth()

    async def on_GET(self, request: Request, room_alias: str) -> Tuple[int, JsonDict]:
        if not RoomAlias.is_valid(room_alias):
            raise SynapseError(400, "Room alias invalid", errcode=Codes.INVALID_PARAM)
        room_alias_obj = RoomAlias.from_string(room_alias)

        res = await self.directory_handler.get_association(room_alias_obj)

        return 200, res

    class PutBody(RequestBodyModel):
        # TODO: get Pydantic to validate that this is a valid room id?
        room_id: StrictStr
        # `servers` is unspecced
        servers: Optional[List[StrictStr]] = None

    async def on_PUT(
        self, request: SynapseRequest, room_alias: str
    ) -> Tuple[int, JsonDict]:
        if not RoomAlias.is_valid(room_alias):
            raise SynapseError(400, "Room alias invalid", errcode=Codes.INVALID_PARAM)
        room_alias_obj = RoomAlias.from_string(room_alias)

        content = parse_and_validate_json_object_from_request(request, self.PutBody)

        logger.debug("Got content: %s", content)
        logger.debug("Got room name: %s", room_alias_obj.to_string())

        logger.debug("Got room_id: %s", content.room_id)
        logger.debug("Got servers: %s", content.servers)

        room = await self.store.get_room(content.room_id)
        if room is None:
            raise SynapseError(400, "Room does not exist")

        requester = await self.auth.get_user_by_req(request)

        await self.directory_handler.create_association(
            requester, room_alias_obj, content.room_id, content.servers
        )

        return 200, {}

    async def on_DELETE(
        self, request: SynapseRequest, room_alias: str
    ) -> Tuple[int, JsonDict]:
        if not RoomAlias.is_valid(room_alias):
            raise SynapseError(400, "Room alias invalid", errcode=Codes.INVALID_PARAM)
        room_alias_obj = RoomAlias.from_string(room_alias)
        requester = await self.auth.get_user_by_req(request)

        if requester.app_service:
            await self.directory_handler.delete_appservice_association(
                requester.app_service, room_alias_obj
            )

            logger.info(
                "Application service at %s deleted alias %s",
                requester.app_service.url,
                room_alias_obj.to_string(),
            )

        else:
            await self.directory_handler.delete_association(requester, room_alias_obj)

            logger.info(
                "User %s deleted alias %s",
                requester.user.to_string(),
                room_alias_obj.to_string(),
            )

        return 200, {}


class ClientDirectoryListServer(RestServlet):
    PATTERNS = client_patterns("/directory/list/room/(?P<room_id>[^/]*)$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastores().main
        self.directory_handler = hs.get_directory_handler()
        self.auth = hs.get_auth()

    async def on_GET(self, request: Request, room_id: str) -> Tuple[int, JsonDict]:
        room = await self.store.get_room(room_id)
        if room is None:
            raise NotFoundError("Unknown room")

        return 200, {"visibility": "public" if room["is_public"] else "private"}

    class PutBody(RequestBodyModel):
        visibility: Literal["public", "private"] = "public"

    async def on_PUT(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        content = parse_and_validate_json_object_from_request(request, self.PutBody)

        await self.directory_handler.edit_published_room_list(
            requester, room_id, content.visibility
        )

        return 200, {}


class ClientAppserviceDirectoryListServer(RestServlet):
    PATTERNS = client_patterns(
        "/directory/list/appservice/(?P<network_id>[^/]*)/(?P<room_id>[^/]*)$", v1=True
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastores().main
        self.directory_handler = hs.get_directory_handler()
        self.auth = hs.get_auth()

    class PutBody(RequestBodyModel):
        visibility: Literal["public", "private"] = "public"

    async def on_PUT(
        self, request: SynapseRequest, network_id: str, room_id: str
    ) -> Tuple[int, JsonDict]:
        content = parse_and_validate_json_object_from_request(request, self.PutBody)
        return await self._edit(request, network_id, room_id, content.visibility)

    async def on_DELETE(
        self, request: SynapseRequest, network_id: str, room_id: str
    ) -> Tuple[int, JsonDict]:
        return await self._edit(request, network_id, room_id, "private")

    async def _edit(
        self,
        request: SynapseRequest,
        network_id: str,
        room_id: str,
        visibility: Literal["public", "private"],
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        if not requester.app_service:
            raise AuthError(
                403, "Only appservices can edit the appservice published room list"
            )

        await self.directory_handler.edit_published_appservice_room_list(
            requester.app_service.id, network_id, room_id, visibility
        )

        return 200, {}
