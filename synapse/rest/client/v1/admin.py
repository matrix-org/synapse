# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.api.errors import AuthError, SynapseError
from synapse.types import UserID

from base import ClientV1RestServlet, client_path_pattern

import logging

logger = logging.getLogger(__name__)


class WhoisRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/admin/whois/(?P<user_id>[^/]*)")

    @defer.inlineCallbacks
    def on_GET(self, request, user_id):
        target_user = UserID.from_string(user_id)
        auth_user, client = yield self.auth.get_user_by_req(request)
        is_admin = yield self.auth.is_server_admin(auth_user)

        if not is_admin and target_user != auth_user:
            raise AuthError(403, "You are not a server admin")

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "Can only whois a local user")

        ret = yield self.handlers.admin_handler.get_whois(target_user)

        defer.returnValue((200, ret))


def register_servlets(hs, http_server):
    WhoisRestServlet(hs).register(http_server)
