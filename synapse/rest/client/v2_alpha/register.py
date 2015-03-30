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

from ._base import client_v2_pattern, parse_request_allow_empty

import logging


logger = logging.getLogger(__name__)


class RegisterRestServlet(RestServlet):
    PATTERN = client_v2_pattern("/register")

    def __init__(self, hs):
        super(RegisterRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_handlers().auth_handler
        self.registration_handler = hs.get_handlers().registration_handler

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_request_allow_empty(request)

        authed, result = yield self.auth_handler.check_auth([
            [LoginType.RECAPTCHA],
            [LoginType.EMAIL_IDENTITY, LoginType.RECAPTCHA],
            [LoginType.APPLICATION_SERVICE]
        ], body)

        if not authed:
            defer.returnValue((401, result))

        is_application_server = LoginType.APPLICATION_SERVICE in result
        is_using_shared_secret = LoginType.SHARED_SECRET in result

        can_register = (
            not self.hs.config.disable_registration
            or is_application_server
            or is_using_shared_secret
        )
        if not can_register:
            raise SynapseError(403, "Registration has been disabled")

        if 'username' not in body or 'password' not in body:
            raise SynapseError(400, "", Codes.MISSING_PARAM)
        desired_username = body['username']
        new_password = body['password']

        (user_id, token) = yield self.registration_handler.register(
            localpart=desired_username,
            password=new_password
        )
        result = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))

    def on_OPTIONS(self, _):
        return 200, {}


def register_servlets(hs, http_server):
    RegisterRestServlet(hs).register(http_server)