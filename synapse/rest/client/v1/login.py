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

from synapse.api.errors import SynapseError
from synapse.types import UserID
from base import ClientV1RestServlet, client_path_pattern

import simplejson as json


class LoginRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login$")
    PASS_TYPE = "m.login.password"

    def on_GET(self, request):
        return (200, {"flows": [{"type": LoginRestServlet.PASS_TYPE}]})

    def on_OPTIONS(self, request):
        return (200, {})

    @defer.inlineCallbacks
    def on_POST(self, request):
        login_submission = _parse_json(request)
        try:
            if login_submission["type"] == LoginRestServlet.PASS_TYPE:
                result = yield self.do_password_login(login_submission)
                defer.returnValue(result)
            else:
                raise SynapseError(400, "Bad login type.")
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

    @defer.inlineCallbacks
    def do_password_login(self, login_submission):
        if not login_submission["user"].startswith('@'):
            login_submission["user"] = UserID.create(
                login_submission["user"], self.hs.hostname).to_string()

        handler = self.handlers.login_handler
        token = yield handler.login(
            user=login_submission["user"],
            password=login_submission["password"])

        result = {
            "user_id": login_submission["user"],  # may have changed
            "access_token": token,
            "home_server": self.hs.hostname,
        }

        defer.returnValue((200, result))


class LoginFallbackRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login/fallback$")

    def on_GET(self, request):
        # TODO(kegan): This should be returning some HTML which is capable of
        # hitting LoginRestServlet
        return (200, {})


class PasswordResetRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/login/reset")

    @defer.inlineCallbacks
    def on_POST(self, request):
        reset_info = _parse_json(request)
        try:
            email = reset_info["email"]
            user_id = reset_info["user_id"]
            handler = self.handlers.login_handler
            yield handler.reset_password(user_id, email)
            # purposefully give no feedback to avoid people hammering different
            # combinations.
            defer.returnValue((200, {}))
        except KeyError:
            raise SynapseError(
                400,
                "Missing keys. Requires 'email' and 'user_id'."
            )


def _parse_json(request):
    try:
        content = json.loads(request.content.read())
        if type(content) != dict:
            raise SynapseError(400, "Content must be a JSON object.")
        return content
    except ValueError:
        raise SynapseError(400, "Content not JSON.")


def register_servlets(hs, http_server):
    LoginRestServlet(hs).register(http_server)
    # TODO PasswordResetRestServlet(hs).register(http_server)
