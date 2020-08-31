# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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

from synapse.http.servlet import (
    RestServlet,
    parse_integer,
    parse_string,
)
from synapse.rest.admin._base import (
    assert_requester_is_admin,
    admin_patterns,
)

logger = logging.getLogger(__name__)


class EventReportsRestServlet(RestServlet):
    """
    List all reported events that are known to the homeserver. Results are returned
    in a dictionary containing report information. Supports pagination.
    This needs user to have administrator access in Synapse.

    GET /_synapse/admin/v1/event_reports?from=0&limit=10
    returns:
        200 OK with list of reports if success otherwise an error.

    Args
        The parameters `from` and `limit` are required only for pagination.
        By default, a `limit` of 100 is used.
        The parameter `user_id` can be used to filter by user id.
        The parameter `room_id` can be used to filter by room id.
    Returns:
        A list of reported events and an integer representing the total number of
        reported events that exist given this query
    """

    PATTERNS = admin_patterns("/event_reports$")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(self, request):
        await assert_requester_is_admin(self.auth, request)

        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)
        user_id = parse_string(request, "user_id", default=None)
        room_id = parse_string(request, "room_id", default=None)

        event_reports, total = await self.store.get_event_reports_paginate(
            start, limit, user_id, room_id
        )
        ret = {"event_reports": event_reports, "total": total}
        if len(event_reports) >= limit:
            ret["next_token"] = str(start + len(event_reports))

        return 200, ret
