# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import re

from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.rest.admin import assert_requester_is_admin


class PurgeRoomServlet(RestServlet):
    """Servlet which will remove all trace of a room from the database

    POST /_synapse/admin/v1/purge_room
    {
        "room_id": "!room:id"
    }

    returns:

    {}
    """

    PATTERNS = (re.compile("^/_synapse/admin/v1/purge_room$"),)

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        self.hs = hs
        self.auth = hs.get_auth()
        self.pagination_handler = hs.get_pagination_handler()

    async def on_POST(self, request):
        await assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ("room_id",))

        await self.pagination_handler.purge_room(body["room_id"])

        return 200, {}
