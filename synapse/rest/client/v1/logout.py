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

import logging

from twisted.internet import defer

from synapse.api.errors import AuthError

from .base import ClientV1RestServlet, client_path_patterns

logger = logging.getLogger(__name__)


class LogoutRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/logout$")

    def __init__(self, hs):
        super(LogoutRestServlet, self).__init__(hs)
        self._auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        try:
            requester = yield self.auth.get_user_by_req(request)
        except AuthError:
            # this implies the access token has already been deleted.
            defer.returnValue((401, {
                "errcode": "M_UNKNOWN_TOKEN",
                "error": "Access Token unknown or expired"
            }))
        else:
            if requester.device_id is None:
                # the acccess token wasn't associated with a device.
                # Just delete the access token
                access_token = self._auth.get_access_token_from_request(request)
                yield self._auth_handler.delete_access_token(access_token)
            else:
                yield self._device_handler.delete_device(
                    requester.user.to_string(), requester.device_id)

        defer.returnValue((200, {}))


class LogoutAllRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/logout/all$")

    def __init__(self, hs):
        super(LogoutAllRestServlet, self).__init__(hs)
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        # first delete all of the user's devices
        yield self._device_handler.delete_all_devices_for_user(user_id)

        # .. and then delete any access tokens which weren't associated with
        # devices.
        yield self._auth_handler.delete_access_tokens_for_user(user_id)
        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    LogoutRestServlet(hs).register(http_server)
    LogoutAllRestServlet(hs).register(http_server)
