# -*- coding: utf-8 -*-
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

from synapse.http.servlet import RestServlet, parse_json_object_from_request

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ReadMarkerRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/read_markers$")

    def __init__(self, hs):
        super().__init__()
        self.auth = hs.get_auth()
        self.receipts_handler = hs.get_receipts_handler()
        self.read_marker_handler = hs.get_read_marker_handler()
        self.presence_handler = hs.get_presence_handler()

    async def on_POST(self, request, room_id):
        requester = await self.auth.get_user_by_req(request)

        await self.presence_handler.bump_presence_active_time(requester.user)

        body = parse_json_object_from_request(request)

        read_event_id = body.get("m.read", None)
        if read_event_id:
            await self.receipts_handler.received_client_receipt(
                room_id,
                "m.read",
                user_id=requester.user.to_string(),
                event_id=read_event_id,
            )

        read_marker_event_id = body.get("m.fully_read", None)
        if read_marker_event_id:
            await self.read_marker_handler.received_client_read_marker(
                room_id,
                user_id=requester.user.to_string(),
                event_id=read_marker_event_id,
            )

        return 200, {}


def register_servlets(hs, http_server):
    ReadMarkerRestServlet(hs).register(http_server)
