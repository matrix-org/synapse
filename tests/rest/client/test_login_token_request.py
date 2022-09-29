# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from twisted.test.proto_helpers import MemoryReactor

from synapse.rest import admin
from synapse.rest.client import login, login_token_request
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config

endpoint = "/_matrix/client/unstable/org.matrix.msc3882/login/token"


class LoginTokenRequestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
        admin.register_servlets,
        login_token_request.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.hs = self.setup_test_homeserver()
        self.hs.config.registration.enable_registration = True
        self.hs.config.registration.registrations_require_3pid = []
        self.hs.config.registration.auto_join_rooms = []
        self.hs.config.captcha.enable_registration_captcha = False

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user = "user123"
        self.password = "password"

    def test_disabled(self) -> None:
        channel = self.make_request("POST", endpoint, {}, access_token=None)
        self.assertEqual(channel.code, 400)

        self.register_user(self.user, self.password)
        token = self.login(self.user, self.password)

        channel = self.make_request("POST", endpoint, {}, access_token=token)
        self.assertEqual(channel.code, 400)

    @override_config({"experimental_features": {"msc3882_enabled": True}})
    def test_require_auth(self) -> None:
        channel = self.make_request("POST", endpoint, {}, access_token=None)
        self.assertEqual(channel.code, 401)

    @override_config({"experimental_features": {"msc3882_enabled": True}})
    def test_uia_on(self) -> None:
        user_id = self.register_user(self.user, self.password)
        token = self.login(self.user, self.password)

        channel = self.make_request("POST", endpoint, {}, access_token=token)
        self.assertEqual(channel.code, 401)
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        session = channel.json_body["session"]

        uia = {
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": self.user},
                "password": self.password,
                "session": session,
            },
        }

        channel = self.make_request("POST", endpoint, uia, access_token=token)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["expires_in"], 300)

        login_token = channel.json_body["login_token"]

        channel = self.make_request(
            "POST",
            "/login",
            content={"type": "m.login.token", "token": login_token},
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(channel.json_body["user_id"], user_id)

    @override_config(
        {"experimental_features": {"msc3882_enabled": True, "msc3882_ui_auth": False}}
    )
    def test_uia_off(self) -> None:
        user_id = self.register_user(self.user, self.password)
        token = self.login(self.user, self.password)

        channel = self.make_request("POST", endpoint, {}, access_token=token)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["expires_in"], 300)

        login_token = channel.json_body["login_token"]

        channel = self.make_request(
            "POST",
            "/login",
            content={"type": "m.login.token", "token": login_token},
        )
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(channel.json_body["user_id"], user_id)

    @override_config(
        {
            "experimental_features": {
                "msc3882_enabled": True,
                "msc3882_ui_auth": False,
                "msc3882_token_timeout": "15s",
            }
        }
    )
    def test_expires_in(self) -> None:
        self.register_user(self.user, self.password)
        token = self.login(self.user, self.password)

        channel = self.make_request("POST", endpoint, {}, access_token=token)
        self.assertEqual(channel.code, 200)
        self.assertEqual(channel.json_body["expires_in"], 15)
