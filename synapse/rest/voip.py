# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from base import RestServlet, client_path_pattern

from syutil.base64util import encode_base64

import hmac
import hashlib


class VoipRestServlet(RestServlet):
    PATTERN = client_path_pattern("/voip/turnuris$")

    @defer.inlineCallbacks
    def on_GET(self, request):
        auth_user = yield self.auth.get_user_by_req(request)

        turnUri = self.hs.config.turn_uri
        turnSecret = self.hs.config.turn_shared_secret
        userLifetime = self.hs.config.turn_user_lifetime
        if not turnUri or not turnSecret or not userLifetime:
            defer.returnValue( (200, {"uris": []}) )

        expiry = self.hs.get_clock().time_msec() + userLifetime
        username = "%d:%s" % (expiry, auth_user.to_string())
         
        mac = hmac.new(turnSecret, msg=username, digestmod=hashlib.sha1)
        password = encode_base64(mac.digest())

        defer.returnValue( (200, {
            'username': username,
            'password': password,
            'ttl': userLifetime / 1000,
            'uris': [
                turnUri,
            ]
        }) )

    def on_OPTIONS(self, request):
        return (200, {})


def register_servlets(hs, http_server):
    VoipRestServlet(hs).register(http_server)
