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

from synapse.http.server import finish_request, set_cors_headers
from synapse.http.servlet import RestServlet
from synapse.rest.client.v2_alpha._base import client_patterns

logger = logging.getLogger(__name__)


class LogoutRestServlet(RestServlet):
    PATTERNS = client_patterns("/logout$", v1=True)

    def __init__(self, hs):
        super(LogoutRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()

    def on_OPTIONS(self, request):
        return 200, {}

    async def _logout(self, requester, request):
        if requester.device_id is None:
            # the acccess token wasn't associated with a device.
            # Just delete the access token
            access_token = self.auth.get_access_token_from_request(request)
            await self._auth_handler.delete_access_token(access_token)
        else:
            await self._device_handler.delete_device(
                requester.user.to_string(), requester.device_id
            )

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)

        await self._logout(requester, request)

        return 200, {}


class LogoutAllRestServlet(RestServlet):
    PATTERNS = client_patterns("/logout/all$", v1=True)

    def __init__(self, hs):
        super(LogoutAllRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self._auth_handler = hs.get_auth_handler()
        self._device_handler = hs.get_device_handler()

    def on_OPTIONS(self, request):
        return 200, {}

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        # first delete all of the user's devices
        await self._device_handler.delete_all_devices_for_user(user_id)

        # .. and then delete any access tokens which weren't associated with
        # devices.
        await self._auth_handler.delete_access_tokens_for_user(user_id)
        return 200, {}


class SAMLLogoutServlet(LogoutRestServlet):
    def __init__(self, hs):
        super().__init__(hs)
        self._saml_handler = hs.get_saml_handler()

    async def on_POST(self, request):
        requester = await self.auth.get_user_by_req(request)
        # Try to use the SAML logout endpoint.
        # It may fail if the user logged in via m.login.password
        # TODO: find a way to know is the user logged in via
        # m.login.password or via m.login.sso / .token
        logout_url = self._saml_handler.create_logout_request(
            requester.user.to_string(),
            self.auth.get_access_token_from_request(request),
        )
        if logout_url:
            set_cors_headers(request)
            request.redirect(logout_url)
            finish_request(request)
            # We've already sent the response, so return None to stop
            # JsonResource sending another.
            return None
        else:
            # The user probally logged in via m.login.password
            # Use the standard LogoutRestServlet._logout().
            await self._logout(requester, request)

        return 200, {}


def register_servlets(hs, http_server):
    if hs.config.saml2_enabled:
        SAMLLogoutServlet(hs).register(http_server)
    else:
        LogoutRestServlet(hs).register(http_server)
    LogoutAllRestServlet(hs).register(http_server)
