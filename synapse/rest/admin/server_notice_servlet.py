# Copyright 2019 New Vector Ltd
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
from typing import TYPE_CHECKING, Optional, Tuple

from synapse.api.constants import EventTypes
from synapse.api.errors import SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.rest.admin import assert_requester_is_admin
from synapse.rest.admin._base import admin_patterns
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer


class SendServerNoticeServlet(RestServlet):
    """Servlet which will send a server notice to a given user

    POST /_synapse/admin/v1/send_server_notice
    {
        "user_id": "@target_user:server_name",
        "content": {
            "msgtype": "m.text",
            "body": "This is my message"
        }
    }

    returns:

    {
        "event_id": "$1895723857jgskldgujpious"
    }
    """

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.txns = HttpTransactionCache(hs)

    def register(self, json_resource: HttpServer):
        PATTERN = "/send_server_notice"
        json_resource.register_paths(
            "POST", admin_patterns(PATTERN + "$"), self.on_POST, self.__class__.__name__
        )
        json_resource.register_paths(
            "PUT",
            admin_patterns(PATTERN + "/(?P<txn_id>[^/]*)$"),
            self.on_PUT,
            self.__class__.__name__,
        )

    async def on_POST(
        self, request: SynapseRequest, txn_id: Optional[str] = None
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ("user_id", "content"))
        event_type = body.get("type", EventTypes.Message)
        state_key = body.get("state_key")

        # We grab the server notices manager here as its initialisation has a check for worker processes,
        # but worker processes still need to initialise SendServerNoticeServlet (as it is part of the
        # admin api).
        if not self.hs.get_server_notices_manager().is_enabled():
            raise SynapseError(400, "Server notices are not enabled on this server")

        user_id = body["user_id"]
        UserID.from_string(user_id)
        if not self.hs.is_mine_id(user_id):
            raise SynapseError(400, "Server notices can only be sent to local users")

        event = await self.hs.get_server_notices_manager().send_notice(
            user_id=body["user_id"],
            type=event_type,
            state_key=state_key,
            event_content=body["content"],
        )

        return 200, {"event_id": event.event_id}

    def on_PUT(self, request: SynapseRequest, txn_id: str) -> Tuple[int, JsonDict]:
        return self.txns.fetch_or_execute_request(
            request, self.on_POST, request, txn_id
        )
