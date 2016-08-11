# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.api.errors import AuthError, StoreError, SynapseError
from synapse.http.servlet import RestServlet, parse_json_object_from_request

from ._base import client_v2_patterns


class TokenRefreshRestServlet(RestServlet):
    """
    Exchanges refresh tokens for a pair of an access token and a new refresh
    token.
    """
    PATTERNS = client_v2_patterns("/tokenrefresh")

    def __init__(self, hs):
        super(TokenRefreshRestServlet, self).__init__()
        self.hs = hs
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_POST(self, request):
        body = parse_json_object_from_request(request)
        try:
            old_refresh_token = body["refresh_token"]
            auth_handler = self.hs.get_auth_handler()
            refresh_result = yield self.store.exchange_refresh_token(
                old_refresh_token, auth_handler.generate_refresh_token
            )
            (user_id, new_refresh_token, device_id) = refresh_result
            new_access_token = yield auth_handler.issue_access_token(
                user_id, device_id
            )
            defer.returnValue((200, {
                "access_token": new_access_token,
                "refresh_token": new_refresh_token,
            }))
        except KeyError:
            raise SynapseError(400, "Missing required key 'refresh_token'.")
        except StoreError:
            raise AuthError(403, "Did not recognize refresh token")


def register_servlets(hs, http_server):
    TokenRefreshRestServlet(hs).register(http_server)
