# Copyright 2017 Vector Creations Ltd
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
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReadMarkerRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/read_markers$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.config = hs.config
        self.receipts_handler = hs.get_receipts_handler()
        self.read_marker_handler = hs.get_read_marker_handler()
        self.presence_handler = hs.get_presence_handler()

        self._known_receipt_types = {
            ReceiptTypes.READ,
            ReceiptTypes.FULLY_READ,
            ReceiptTypes.READ_PRIVATE,
        }

    async def on_POST(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)

        await self.presence_handler.bump_presence_active_time(requester.user)

        body = parse_json_object_from_request(request)

        unrecognized_types = set(body.keys()) - self._known_receipt_types
        if unrecognized_types:
            # It's fine if there are unrecognized receipt types, but let's log
            # it to help debug clients that have typoed the receipt type.
            #
            # We specifically *don't* error here, as a) it stops us processing
            # the valid receipts, and b) we need to be extensible on receipt
            # types.
            logger.info("Ignoring unrecognized receipt types: %s", unrecognized_types)

        for receipt_type in self._known_receipt_types:
            event_id = body.get(receipt_type, None)
            # TODO Add validation to reject non-string event IDs.
            if not event_id:
                continue

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
                    # Setting the thread ID is not possible with the /read_markers endpoint.
                    thread_id=None,
                )

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReadMarkerRestServlet(hs).register(http_server)
