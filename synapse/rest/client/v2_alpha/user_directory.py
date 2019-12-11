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

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request

from ._base import client_patterns

logger = logging.getLogger(__name__)


class UserDirectorySearchRestServlet(RestServlet):
    PATTERNS = client_patterns("/user_directory/search$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(UserDirectorySearchRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.user_directory_handler = hs.get_user_directory_handler()

    async def on_POST(self, request):
        """Searches for users in directory

        Returns:
            dict of the form::

                {
                    "limited": <bool>,  # whether there were more results or not
                    "results": [  # Ordered by best match first
                        {
                            "user_id": <user_id>,
                            "display_name": <display_name>,
                            "avatar_url": <avatar_url>
                        }
                    ]
                }
        """
        requester = await self.auth.get_user_by_req(request, allow_guest=False)
        user_id = requester.user.to_string()

        if not self.hs.config.user_directory_search_enabled:
            return 200, {"limited": False, "results": []}

        body = parse_json_object_from_request(request)

        limit = body.get("limit", 10)
        limit = min(limit, 50)

        try:
            search_term = body["search_term"]
        except Exception:
            raise SynapseError(400, "`search_term` is required field")

        results = await self.user_directory_handler.search_users(
            user_id, search_term, limit
        )

        return 200, results


def register_servlets(hs, http_server):
    UserDirectorySearchRestServlet(hs).register(http_server)
