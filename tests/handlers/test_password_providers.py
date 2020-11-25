# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

"""Tests for the password_auth_provider interface"""

from typing import Any, Type

from mock import Mock

from twisted.internet import defer

import synapse
from synapse.rest.client.v1 import login

from tests import unittest
from tests.server import FakeChannel
from tests.unittest import override_config

# (possibly experimental) login flows we expect to appear in the list after the normal
# ones
ADDITIONAL_LOGIN_FLOWS = [{"type": "uk.half-shot.msc2778.login.application_service"}]

# a mock instance which the dummy auth providers delegate to, so we can see what's going
# on
mock_password_provider = Mock()


class PasswordOnlyAuthProvider:
    @staticmethod
    def parse_config(self):
        pass

    def __init__(self, config, account_handler):
        pass

    def check_password(self, *args):
        return mock_password_provider.check_password(*args)


class CustomAuthProvider:
    @staticmethod
    def parse_config(self):
        pass

    def __init__(self, config, account_handler):
        pass

    def get_supported_login_types(self):
        return {"test.login_type": ["test_field"]}

    def check_auth(self, *args):
        return mock_password_provider.check_auth(*args)


def providers_config(*providers: Type[Any]) -> dict:
    """Returns a config dict that will enable the given password auth providers"""
    return {
        "password_providers": [
            {"module": "%s.%s" % (__name__, provider.__qualname__), "config": {},}
            for provider in providers
        ]
    }


class PasswordAuthProviderTests(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]

    def setUp(self):
        mock_password_provider.reset_mock()
        super().setUp()

    @override_config(providers_config(PasswordOnlyAuthProvider))
    def test_password_only_auth_provider_login(self):
        # login flows should only have m.login.password
        flows = self._get_login_flows()
        self.assertEqual(flows, [{"type": "m.login.password"}] + ADDITIONAL_LOGIN_FLOWS)

        # check_password must return an awaitable
        mock_password_provider.check_password.return_value = defer.succeed(True)
        channel = self._send_password_login("u", "p")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@u:test", channel.json_body["user_id"])
        mock_password_provider.check_password.assert_called_once_with("@u:test", "p")
        mock_password_provider.reset_mock()

        # login with mxid should work too
        channel = self._send_password_login("@u:bz", "p")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@u:bz", channel.json_body["user_id"])
        mock_password_provider.check_password.assert_called_once_with("@u:bz", "p")
        mock_password_provider.reset_mock()

    @override_config(providers_config(PasswordOnlyAuthProvider))
    def test_password_auth_local_user_fallback(self):
        """rejected login should fall back to local db"""
        self.register_user("localuser", "localpass")

        # check_password must return an awaitable
        mock_password_provider.check_password.return_value = defer.succeed(False)
        channel = self._send_password_login("u", "p")
        self.assertEqual(channel.code, 403, channel.result)

        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@localuser:test", channel.json_body["user_id"])

    @override_config(
        {
            **providers_config(PasswordOnlyAuthProvider),
            "password_config": {"localdb_enabled": False},
        }
    )
    def test_password_auth_no_local_user_fallback(self):
        """even though we have a local password for a user, localdb_enabled can block it"""
        self.register_user("localuser", "localpass")

        # check_password must return an awaitable
        mock_password_provider.check_password.return_value = defer.succeed(False)
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 403, channel.result)

    @override_config(
        {
            **providers_config(PasswordOnlyAuthProvider),
            "password_config": {"enabled": False},
        }
    )
    def test_password_auth_disabled(self):
        """password auth doesn't work if it's disabled across the board"""
        # login flows should be empty
        flows = self._get_login_flows()
        self.assertEqual(flows, ADDITIONAL_LOGIN_FLOWS)

        # login shouldn't work and should be rejected with a 400 ("unknown login type")
        channel = self._send_password_login("u", "p")
        self.assertEqual(channel.code, 400, channel.result)
        mock_password_provider.check_password.assert_not_called()

    @override_config(providers_config(CustomAuthProvider))
    def test_custom_auth_provider_login(self):
        # login flows should have the custom flow and m.login.password, since we
        # haven't disabled local password lookup.
        # (password must come first, because reasons)
        flows = self._get_login_flows()
        self.assertEqual(
            flows,
            [{"type": "m.login.password"}, {"type": "test.login_type"}]
            + ADDITIONAL_LOGIN_FLOWS,
        )

        # login with missing param should be rejected
        channel = self._send_login("test.login_type", "u")
        self.assertEqual(channel.code, 400, channel.result)
        mock_password_provider.check_auth.assert_not_called()

        mock_password_provider.check_auth.return_value = defer.succeed("@user:bz")
        channel = self._send_login("test.login_type", "u", test_field="y")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@user:bz", channel.json_body["user_id"])
        mock_password_provider.check_auth.assert_called_once_with(
            "u", "test.login_type", {"test_field": "y"}
        )

    @override_config(providers_config(CustomAuthProvider))
    def test_custom_auth_provider_callback(self):
        callback = Mock(return_value=defer.succeed(None))

        mock_password_provider.check_auth.return_value = defer.succeed(
            ("@user:bz", callback)
        )
        channel = self._send_login("test.login_type", "u", test_field="y")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@user:bz", channel.json_body["user_id"])
        mock_password_provider.check_auth.assert_called_once_with(
            "u", "test.login_type", {"test_field": "y"}
        )

        # check the args to the callback
        callback.assert_called_once()
        call_args, call_kwargs = callback.call_args
        # should be one positional arg
        self.assertEqual(len(call_args), 1)
        self.assertEqual(call_args[0]["user_id"], "@user:bz")
        for p in ["user_id", "access_token", "device_id", "home_server"]:
            self.assertIn(p, call_args[0])

    @override_config(
        {**providers_config(CustomAuthProvider), "password_config": {"enabled": False},}
    )
    def test_custom_auth_password_disabled(self):
        """Test login with a custom auth provider where password login is disabled"""
        self.register_user("localuser", "localpass")

        flows = self._get_login_flows()
        self.assertEqual(flows, [{"type": "test.login_type"}] + ADDITIONAL_LOGIN_FLOWS)

        # login shouldn't work and should be rejected with a 400 ("unknown login type")
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 400, channel.result)
        mock_password_provider.check_auth.assert_not_called()

    @override_config(
        {
            **providers_config(CustomAuthProvider),
            "password_config": {"localdb_enabled": False},
        }
    )
    def test_custom_auth_no_local_user_fallback(self):
        """Test login with a custom auth provider where the local db is disabled"""
        self.register_user("localuser", "localpass")

        flows = self._get_login_flows()
        self.assertEqual(flows, [{"type": "test.login_type"}] + ADDITIONAL_LOGIN_FLOWS)

        # password login shouldn't work and should be rejected with a 400
        # ("unknown login type")
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 400, channel.result)

    test_custom_auth_no_local_user_fallback.skip = "currently broken"

    def _get_login_flows(self):
        _, channel = self.make_request("GET", "/_matrix/client/r0/login")
        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["flows"]

    def _send_password_login(self, user: str, password: str) -> FakeChannel:
        return self._send_login(type="m.login.password", user=user, password=password)

    def _send_login(self, type, user, **params) -> FakeChannel:
        params.update({"user": user, "type": type})
        _, channel = self.make_request("POST", "/_matrix/client/r0/login", params,)
        return channel
