# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from synapse.api.constants import LoginType
from synapse.api.errors import LoginError, SynapseError, Codes
from synapse.http.servlet import RestServlet

from ._base import client_v2_pattern, parse_json_dict_from_request

import logging


logger = logging.getLogger(__name__)


class PasswordRestServlet(RestServlet):
    PATTERN = client_v2_pattern("/account/password")

    def __init__(self, hs):
        super(PasswordRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_handlers().auth_handler
        self.login_handler = hs.get_handlers().login_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_dict_from_request(request)

        authed, result = yield self.auth_handler.check_auth([
            [LoginType.PASSWORD]
        ], body)

        if not authed:
            defer.returnValue((401, result))

        auth_user = None

        if LoginType.PASSWORD in result:
            # if using password, they should also be logged in
            auth_user, client = yield self.auth.get_user_by_req(request)
            if auth_user.to_string() != result[LoginType.PASSWORD]:
                raise LoginError(400, "", Codes.UNKNOWN)
        else:
            logger.error("Auth succeeded but no known type!", result.keys())
            raise SynapseError(500, "", Codes.UNKNOWN)

        user_id = auth_user.to_string()

        if 'new_password' not in body:
            raise SynapseError(400, "", Codes.MISSING_PARAM)
        new_password = body['new_password']

        yield self.login_handler.set_password(
            user_id, new_password, client.token_id
        )

        defer.returnValue((200, {}))

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    PasswordRestServlet(hs).register(http_server)
