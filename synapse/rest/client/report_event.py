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
from http import HTTPStatus
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReportEventRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/report/(?P<event_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self._event_handler = self.hs.get_event_handler()

    async def on_POST(
        self, request: SynapseRequest, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        body = parse_json_object_from_request(request)

        if not isinstance(body.get("reason", ""), str):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'reason' must be a string",
                Codes.BAD_JSON,
            )
        if type(body.get("score", 0)) is not int:  # noqa: E721
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'score' must be an integer",
                Codes.BAD_JSON,
            )

        try:
            event = await self._event_handler.get_event(
                requester.user, room_id, event_id, show_redacted=False
            )
        except AuthError:
            # The event exists, but this user is not allowed to access this event.
            event = None

        if event is None:
            raise NotFoundError(
                "Unable to report event: "
                "it does not exist or you aren't able to see it."
            )

        await self.store.add_event_report(
            room_id=room_id,
            event_id=event_id,
            user_id=user_id,
            reason=body.get("reason"),
            content=body,
            received_ts=self.clock.time_msec(),
        )

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReportEventRestServlet(hs).register(http_server)
