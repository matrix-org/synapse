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

from synapse.api.errors import AuthError
from synapse.http.servlet import RestServlet

from ._base import client_v2_patterns


class TokenRefreshRestServlet(RestServlet):
    """
    Exchanges refresh tokens for a pair of an access token and a new refresh
    token.
    """
    PATTERNS = client_v2_patterns("/tokenrefresh")

    def __init__(self, hs):
        super(TokenRefreshRestServlet, self).__init__()

    @defer.inlineCallbacks
    def on_POST(self, request):
        raise AuthError(403, "tokenrefresh is no longer supported.")


def register_servlets(hs, http_server):
    TokenRefreshRestServlet(hs).register(http_server)
