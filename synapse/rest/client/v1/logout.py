# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

from synapse.api.auth import get_access_token_from_request

from .base import ClientV1RestServlet, client_path_patterns

import logging


logger = logging.getLogger(__name__)


class LogoutRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/logout$")

    def __init__(self, hs):
        super(LogoutRestServlet, self).__init__(hs)
        self.store = hs.get_datastore()

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        access_token = get_access_token_from_request(request)
        yield self.store.delete_access_token(access_token)
        defer.returnValue((200, {}))


class LogoutAllRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/logout/all$")

    def __init__(self, hs):
        super(LogoutAllRestServlet, self).__init__(hs)
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()
        yield self.store.user_delete_access_tokens(user_id)
        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    LogoutRestServlet(hs).register(http_server)
    LogoutAllRestServlet(hs).register(http_server)
