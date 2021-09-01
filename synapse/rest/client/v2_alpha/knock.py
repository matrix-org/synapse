# Copyright 2020 Sorunome
# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from twisted.web.server import Request

from synapse.api.constants import Membership
from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_strings_from_args,
)
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import set_tag
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import JsonDict, RoomAlias, RoomID

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

from ._base import client_patterns

logger = logging.getLogger(__name__)


class KnockRoomAliasServlet(RestServlet):
    """
    POST /knock/{roomIdOrAlias}
    """

    PATTERNS = client_patterns("/knock/(?P<room_identifier>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.txns = HttpTransactionCache(hs)
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()

    async def on_POST(
        self,
        request: SynapseRequest,
        room_identifier: str,
        txn_id: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)
        event_content = None
        if "reason" in content:
            event_content = {"reason": content["reason"]}

        if RoomID.is_valid(room_identifier):
            room_id = room_identifier

            # twisted.web.server.Request.args is incorrectly defined as Optional[Any]
            args: Dict[bytes, List[bytes]] = request.args  # type: ignore

            remote_room_hosts = parse_strings_from_args(
                args, "server_name", required=False
            )
        elif RoomAlias.is_valid(room_identifier):
            handler = self.room_member_handler
            room_alias = RoomAlias.from_string(room_identifier)
            room_id_obj, remote_room_hosts = await handler.lookup_room_alias(room_alias)
            room_id = room_id_obj.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        await self.room_member_handler.update_membership(
            requester=requester,
            target=requester.user,
            room_id=room_id,
            action=Membership.KNOCK,
            txn_id=txn_id,
            third_party_signed=None,
            remote_room_hosts=remote_room_hosts,
            content=event_content,
        )

        return 200, {"room_id": room_id}

    def on_PUT(self, request: Request, room_identifier: str, txn_id: str):
        set_tag("txn_id", txn_id)

        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, room_identifier, txn_id
        )


def register_servlets(hs, http_server):
    KnockRoomAliasServlet(hs).register(http_server)
