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
from typing import Dict

from signedjson.sign import sign_json

from synapse.api.errors import Codes, SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.types import UserID

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
        self.http_client = hs.get_simple_http_client()

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

        if self.hs.config.user_directory_defer_to_id_server:
            signed_body = sign_json(
                body, self.hs.hostname, self.hs.config.signing_key[0]
            )
            url = "%s/_matrix/identity/api/v1/user_directory/search" % (
                self.hs.config.user_directory_defer_to_id_server,
            )
            resp = await self.http_client.post_json_get_json(url, signed_body)
            return 200, resp

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


class SingleUserInfoServlet(RestServlet):
    """
    Deprecated and replaced by `/users/info`

    GET /user/{user_id}/info HTTP/1.1
    """

    PATTERNS = client_patterns("/user/(?P<user_id>[^/]*)/info$")

    def __init__(self, hs):
        super(SingleUserInfoServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.transport_layer = hs.get_federation_transport_client()
        registry = hs.get_federation_registry()

        if not registry.query_handlers.get("user_info"):
            registry.register_query_handler("user_info", self._on_federation_query)

    async def on_GET(self, request, user_id):
        # Ensure the user is authenticated
        await self.auth.get_user_by_req(request)

        user = UserID.from_string(user_id)
        if not self.hs.is_mine(user):
            # Attempt to make a federation request to the server that owns this user
            args = {"user_id": user_id}
            res = await self.transport_layer.make_query(
                user.domain, "user_info", args, retry_on_dns_fail=True
            )
            return 200, res

        user_id_to_info = await self.store.get_info_for_users([user_id])
        return 200, user_id_to_info[user_id]

    async def _on_federation_query(self, args):
        """Called when a request for user information appears over federation

        Args:
            args (dict): Dictionary of query arguments provided by the request

        Returns:
            Deferred[dict]: Deactivation and expiration information for a given user
        """
        user_id = args.get("user_id")
        if not user_id:
            raise SynapseError(400, "user_id not provided")

        user = UserID.from_string(user_id)
        if not self.hs.is_mine(user):
            raise SynapseError(400, "User is not hosted on this homeserver")

        user_ids_to_info_dict = await self.store.get_info_for_users([user_id])
        return user_ids_to_info_dict[user_id]


class UserInfoServlet(RestServlet):
    """Bulk version of `/user/{user_id}/info` endpoint

    GET /users/info HTTP/1.1

    Returns a dictionary of user_id to info dictionary. Supports remote users
    """

    PATTERNS = client_patterns("/users/info$", unstable=True, releases=())

    def __init__(self, hs):
        super(UserInfoServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.transport_layer = hs.get_federation_transport_client()

    async def on_POST(self, request):
        # Ensure the user is authenticated
        await self.auth.get_user_by_req(request)

        # Extract the user_ids from the request
        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, required=["user_ids"])

        user_ids = body["user_ids"]
        if not isinstance(user_ids, list):
            raise SynapseError(
                400,
                "'user_ids' must be a list of user ID strings",
                errcode=Codes.INVALID_PARAM,
            )

        # Separate local and remote users
        local_user_ids = set()
        remote_server_to_user_ids = {}  # type: Dict[str, set]
        for user_id in user_ids:
            user = UserID.from_string(user_id)

            if self.hs.is_mine(user):
                local_user_ids.add(user_id)
            else:
                remote_server_to_user_ids.setdefault(user.domain, set())
                remote_server_to_user_ids[user.domain].add(user_id)

        # Retrieve info of all local users
        user_id_to_info_dict = await self.store.get_info_for_users(local_user_ids)

        # Request info of each remote user from their remote homeserver
        for server_name, user_id_set in remote_server_to_user_ids.items():
            # Make a request to the given server about their own users
            res = await self.transport_layer.get_info_of_users(
                server_name, list(user_id_set)
            )

            for user_id, info in res:
                user_id_to_info_dict[user_id] = info

        return 200, user_id_to_info_dict


def register_servlets(hs, http_server):
    UserDirectorySearchRestServlet(hs).register(http_server)
    SingleUserInfoServlet(hs).register(http_server)
    UserInfoServlet(hs).register(http_server)
