# Copyright 2016 OpenMarket Ltd
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
from synapse.events.utils import (
    SerializeEventConfig,
    format_event_for_client_v2_without_room_id,
)
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class NotificationsServlet(RestServlet):
    PATTERNS = client_patterns("/notifications$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        from_token = parse_string(request, "from", required=False)
        limit = parse_integer(request, "limit", default=50)
        only = parse_string(request, "only", required=False)

        limit = min(limit, 500)

        push_actions = await self.store.get_push_actions_for_user(
            user_id, from_token, limit, only_highlight=(only == "highlight")
        )

        receipts_by_room = await self.store.get_receipts_for_user_with_orderings(
            user_id,
            [
                ReceiptTypes.READ,
                ReceiptTypes.READ_PRIVATE,
            ],
        )

        notif_event_ids = [pa.event_id for pa in push_actions]
        notif_events = await self.store.get_events(notif_event_ids)

        returned_push_actions = []

        next_token = None

        for pa in push_actions:
            returned_pa = {
                "room_id": pa.room_id,
                "profile_tag": pa.profile_tag,
                "actions": pa.actions,
                "ts": pa.received_ts,
                "event": (
                    self._event_serializer.serialize_event(
                        notif_events[pa.event_id],
                        self.clock.time_msec(),
                        config=SerializeEventConfig(
                            event_format=format_event_for_client_v2_without_room_id
                        ),
                    )
                ),
            }

            if pa.room_id not in receipts_by_room:
                returned_pa["read"] = False
            else:
                receipt = receipts_by_room[pa.room_id]

                returned_pa["read"] = (
                    receipt["topological_ordering"],
                    receipt["stream_ordering"],
                ) >= (pa.topological_ordering, pa.stream_ordering)
            returned_push_actions.append(returned_pa)
            next_token = str(pa.stream_ordering)

        return 200, {"notifications": returned_push_actions, "next_token": next_token}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    NotificationsServlet(hs).register(http_server)
