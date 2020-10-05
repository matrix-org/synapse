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

from synapse.api.errors import Codes, SynapseError
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.rest.admin._base import admin_patterns, assert_requester_is_admin

logger = logging.getLogger(__name__)


class EventReportsRestServlet(RestServlet):
    """
    List all reported events that are known to the homeserver. Results are returned
    in a dictionary containing report information. Supports pagination.
    The requester must have administrator access in Synapse.

    GET /_synapse/admin/v1/event_reports
    returns:
        200 OK with list of reports if success otherwise an error.

    Args:
        The parameters `from` and `limit` are required only for pagination.
        By default, a `limit` of 100 is used.
        The parameter `dir` can be used to define the order of results.
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
        direction = parse_string(request, "dir", default="b")
        user_id = parse_string(request, "user_id")
        room_id = parse_string(request, "room_id")

        if start < 0:
            raise SynapseError(
                400,
                "The start parameter must be a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if limit < 0:
            raise SynapseError(
                400,
                "The limit parameter must be a positive integer.",
                errcode=Codes.INVALID_PARAM,
            )

        if direction not in ("f", "b"):
            raise SynapseError(
                400, "Unknown direction: %s" % (direction,), errcode=Codes.INVALID_PARAM
            )

        event_reports, total = await self.store.get_event_reports_paginate(
            start, limit, direction, user_id, room_id
        )
        ret = {"event_reports": event_reports, "total": total}
        if (start + limit) < total:
            ret["next_token"] = start + len(event_reports)

        return 200, ret
