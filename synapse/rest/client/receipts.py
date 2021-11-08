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
import re
from typing import TYPE_CHECKING, Tuple

from synapse.api.constants import ReadReceiptEventFields
from synapse.api.errors import Codes, SynapseError
from synapse.http import get_request_user_agent
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

pattern = re.compile(r"(?:Element|SchildiChat)/1\.[012]\.")

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReceiptRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)"
        "/receipt/(?P<receipt_type>[^/]*)"
        "/(?P<event_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.receipts_handler = hs.get_receipts_handler()
        self.presence_handler = hs.get_presence_handler()

    async def on_POST(
        self, request: SynapseRequest, room_id: str, receipt_type: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        if receipt_type != "m.read":
            raise SynapseError(400, "Receipt type must be 'm.read'")

        # Do not allow older SchildiChat and Element Android clients (prior to Element/1.[012].x) to send an empty body.
        user_agent = get_request_user_agent(request)
        allow_empty_body = False
        if "Android" in user_agent:
            if pattern.match(user_agent) or "Riot" in user_agent:
                allow_empty_body = True
        body = parse_json_object_from_request(request, allow_empty_body)
        hidden = body.get(ReadReceiptEventFields.MSC2285_HIDDEN, False)

        if not isinstance(hidden, bool):
            raise SynapseError(
                400,
                "Param %s must be a boolean, if given"
                % ReadReceiptEventFields.MSC2285_HIDDEN,
                Codes.BAD_JSON,
            )

        await self.presence_handler.bump_presence_active_time(requester.user)

        await self.receipts_handler.received_client_receipt(
            room_id,
            receipt_type,
            user_id=requester.user.to_string(),
            event_id=event_id,
            hidden=hidden,
        )

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReceiptRestServlet(hs).register(http_server)
