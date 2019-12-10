# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

import base64
import hashlib
import hmac

from synapse.http.servlet import RestServlet
from synapse.rest.client.v2_alpha._base import client_patterns


class VoipRestServlet(RestServlet):
    PATTERNS = client_patterns("/voip/turnServer$", v1=True)

    def __init__(self, hs):
        super(VoipRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(
            request, self.hs.config.turn_allow_guests
        )

        turnUris = self.hs.config.turn_uris
        turnSecret = self.hs.config.turn_shared_secret
        turnUsername = self.hs.config.turn_username
        turnPassword = self.hs.config.turn_password
        userLifetime = self.hs.config.turn_user_lifetime

        if turnUris and turnSecret and userLifetime:
            expiry = (self.hs.get_clock().time_msec() + userLifetime) / 1000
            username = "%d:%s" % (expiry, requester.user.to_string())

            mac = hmac.new(
                turnSecret.encode(), msg=username.encode(), digestmod=hashlib.sha1
            )
            # We need to use standard padded base64 encoding here
            # encode_base64 because we need to add the standard padding to get the
            # same result as the TURN server.
            password = base64.b64encode(mac.digest())

        elif turnUris and turnUsername and turnPassword and userLifetime:
            username = turnUsername
            password = turnPassword

        else:
            return 200, {}

        return (
            200,
            {
                "username": username,
                "password": password,
                "ttl": userLifetime / 1000,
                "uris": turnUris,
            },
        )

    def on_OPTIONS(self, request):
        return 200, {}


def register_servlets(hs, http_server):
    VoipRestServlet(hs).register(http_server)
