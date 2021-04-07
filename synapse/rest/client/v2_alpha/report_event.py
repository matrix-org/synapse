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
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Don't import HomeServer directly, otherwise we'll create a
    # circular dependency.
    from synapse.server import HomeServer

from synapse.http.servlet import RestServlet, parse_json_object_from_request

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ReportEventRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/report/(?P<event_id>[^/]*)$")

    def __init__(self, hs: HomeServer):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.abuse_report_handler = hs.get_abuse_reporter()

    async def on_POST(self, request, room_id, event_id):
        requester = await self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)
        self.abuse_report_handler.report(requester.user, body, room_id, event_id)


def register_servlets(hs, http_server):
    ReportEventRestServlet(hs).register(http_server)
