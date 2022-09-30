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

from synapse.api.constants import ReceiptTypes
from synapse.api.errors import SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

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
        self.auth = hs.get_auth()
        self.receipts_handler = hs.get_receipts_handler()
        self.read_marker_handler = hs.get_read_marker_handler()
        self.presence_handler = hs.get_presence_handler()

        self._known_receipt_types = {
            ReceiptTypes.READ,
            ReceiptTypes.READ_PRIVATE,
            ReceiptTypes.FULLY_READ,
        }
        self._msc3771_enabled = hs.config.experimental.msc3771_enabled

    async def on_POST(
        self, request: SynapseRequest, room_id: str, receipt_type: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        if receipt_type not in self._known_receipt_types:
            raise SynapseError(
                400,
                f"Receipt type must be {', '.join(self._known_receipt_types)}",
            )

        body = parse_json_object_from_request(request)

        # Pull the thread ID, if one exists.
        thread_id = None
        if self._msc3771_enabled:
            if "thread_id" in body:
                thread_id = body.get("thread_id")
                if not thread_id or not isinstance(thread_id, str):
                    raise SynapseError(
                        400, "thread_id field must be a non-empty string"
                    )

        await self.presence_handler.bump_presence_active_time(requester.user)

        if receipt_type == ReceiptTypes.FULLY_READ:
            await self.read_marker_handler.received_client_read_marker(
                room_id,
                user_id=requester.user.to_string(),
                event_id=event_id,
            )
        else:
            await self.receipts_handler.received_client_receipt(
                room_id,
                receipt_type,
                user_id=requester.user.to_string(),
                event_id=event_id,
                thread_id=thread_id,
            )

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReceiptRestServlet(hs).register(http_server)
