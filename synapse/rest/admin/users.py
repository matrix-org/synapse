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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.rest.admin import assert_requester_is_admin
from synapse.types import UserID


class UserAdminServlet(RestServlet):
    """
    Set whether or not a user is a server administrator.

    Note that only local users can be server administrators, and that an
    administrator may not demote themselves.

    Only server administrators can use this API.

    Example:
        PUT /_synapse/admin/v1/users/@reivilibre:librepush.net/admin
        {
            "admin": true
        }
    """

    PATTERNS = (re.compile("^/_synapse/admin/v1/users/(?P<user_id>@[^/]*)/admin$"),)

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.handlers = hs.get_handlers()

    @defer.inlineCallbacks
    def on_PUT(self, request, user_id):
        yield assert_requester_is_admin(self.auth, request)
        requester = yield self.auth.get_user_by_req(request)
        auth_user = requester.user

        target_user = UserID.from_string(user_id)

        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["admin"])

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Only local users can be admins of this homeserver")

        set_admin_to = bool(body["admin"])

        if target_user == auth_user and not set_admin_to:
            raise SynapseError(400, "You may not demote yourself.")

        ret = yield self.handlers.admin_handler.set_user_server_admin(
            target_user, set_admin_to
        )

        return (200, ret)
