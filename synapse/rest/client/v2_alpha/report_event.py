# -*- coding: utf-8 -*-
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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Don't import HomeServer directly, otherwise we'll create a
    # circular dependency.
    from synapse.server import HomeServer

from synapse.api.errors import Codes, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ReportEventRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/report/(?P<event_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.abuse_report_handler = hs.get_abuse_report_handler()
        self._rate_limiter = Ratelimiter(
            store=hs.get_datastore(),
            clock=hs.get_clock(),
            rate_hz=1,  # Limit to 1 message per second
            burst_count=10,  # Limit to 10 successive messages
        )

    async def on_POST(self, request: SynapseRequest, room_id, event_id):
        requester = await self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)
        await self._rate_limiter.ratelimit(requester=requester)

        if not isinstance(body["reason"], str):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'reason' must be a string",
                Codes.BAD_JSON,
            )
        if not isinstance(body["score"], int):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'score' must be an integer",
                Codes.BAD_JSON,
            )
        nature = body.get("nature", None)
        if nature is not None:
            if nature not in ["abuse.spam", "abuse.moderation"]:
                nature = None

        await self.abuse_report_handler.report(
            requester.user,
            body,
            room_id,
            event_id,
            body["reason"],
            body["score"],
            nature,
        )

        return 200, {}


def register_servlets(hs, http_server):
    ReportEventRestServlet(hs).register(http_server)
