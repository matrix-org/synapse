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

from signedjson.sign import sign_json

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request
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

    @defer.inlineCallbacks
    def on_POST(self, request):
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
        requester = yield self.auth.get_user_by_req(request, allow_guest=False)
        user_id = requester.user.to_string()

        if not self.hs.config.user_directory_search_enabled:
            defer.returnValue((200, {
                "limited": False,
                "results": [],
            }))

        body = parse_json_object_from_request(request)

        if self.hs.config.user_directory_defer_to_id_server:
            signed_body = sign_json(body, self.hs.hostname, self.hs.config.signing_key[0])
            url = "%s/_matrix/identity/api/v1/user_directory/search" % (
                self.hs.config.user_directory_defer_to_id_server,
            )
            resp = yield self.http_client.post_json_get_json(url, signed_body)
            defer.returnValue((200, resp))

        limit = body.get("limit", 10)
        limit = min(limit, 50)

        try:
            search_term = body["search_term"]
        except Exception:
            raise SynapseError(400, "`search_term` is required field")

        results = yield self.user_directory_handler.search_users(
            user_id, search_term, limit,
        )

        defer.returnValue((200, results))


class UserInfoServlet(RestServlet):
    """
    GET /user/{user_id}/info HTTP/1.1
    """
    PATTERNS = client_patterns(
        "/user/(?P<user_id>[^/]*)/info$"
    )

    def __init__(self, hs):
        super(UserInfoServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.clock = hs.get_clock()
        self.transport_layer = hs.get_federation_transport_client()
        registry = hs.get_federation_registry()

        if not registry.query_handlers.get("user_info"):
            registry.register_query_handler(
                "user_info", self._on_federation_query
            )

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        # Ensure the user is authenticated
        yield self.auth.get_user_by_req(request, allow_guest=False)

        user = UserID.from_string(user_id)
        if not self.hs.is_mine(user):
            # Attempt to make a federation request to the server that owns this user
            args = {"user_id": user_id}
            res = yield self.transport_layer.make_query(
                user.domain, "user_info", args, retry_on_dns_fail=True,
            )
            defer.returnValue((200, res))

        res = yield self._get_user_info(user_id)
        defer.returnValue((200, res))

    @defer.inlineCallbacks
    def _on_federation_query(self, args):
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

        res = yield self._get_user_info(user_id)
        defer.returnValue(res)

    @defer.inlineCallbacks
    def _get_user_info(self, user_id):
        """Retrieve information about a given user

        Args:
            user_id (str): The User ID of a given user on this homeserver

        Returns:
            Deferred[dict]: Deactivation and expiration information for a given user
        """
        # Check whether user is deactivated
        is_deactivated = yield self.store.get_user_deactivated_status(user_id)

        # Check whether user is expired
        expiration_ts = yield self.store.get_expiration_ts_for_user(user_id)
        is_expired = (
            expiration_ts is not None and self.clock.time_msec() >= expiration_ts
        )

        res = {
            "expired": is_expired,
            "deactivated": is_deactivated,
        }
        defer.returnValue(res)


def register_servlets(hs, http_server):
    UserDirectorySearchRestServlet(hs).register(http_server)
    UserInfoServlet(hs).register(http_server)
