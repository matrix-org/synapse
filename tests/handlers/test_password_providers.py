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

from typing import Any, Type, Union

from mock import Mock

from twisted.internet import defer

import synapse
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import devices
from synapse.types import JsonDict

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
    """A password_provider which only implements `check_password`."""

    @staticmethod
    def parse_config(self):
        pass

    def __init__(self, config, account_handler):
        pass

    def check_password(self, *args):
        return mock_password_provider.check_password(*args)


class CustomAuthProvider:
    """A password_provider which implements a custom login type."""

    @staticmethod
    def parse_config(self):
        pass

    def __init__(self, config, account_handler):
        pass

    def get_supported_login_types(self):
        return {"test.login_type": ["test_field"]}

    def check_auth(self, *args):
        return mock_password_provider.check_auth(*args)


class PasswordCustomAuthProvider:
    """A password_provider which implements password login via `check_auth`, as well
    as a custom type."""

    @staticmethod
    def parse_config(self):
        pass

    def __init__(self, config, account_handler):
        pass

    def get_supported_login_types(self):
        return {"m.login.password": ["password"], "test.login_type": ["test_field"]}

    def check_auth(self, *args):
        return mock_password_provider.check_auth(*args)


def providers_config(*providers: Type[Any]) -> dict:
    """Returns a config dict that will enable the given password auth providers"""
    return {
        "password_providers": [
            {"module": "%s.%s" % (__name__, provider.__qualname__), "config": {}}
            for provider in providers
        ]
    }


class PasswordAuthProviderTests(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        devices.register_servlets,
    ]

    def setUp(self):
        # we use a global mock device, so make sure we are starting with a clean slate
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

        # try a weird username / pass. Honestly it's unclear what we *expect* to happen
        # in these cases, but at least we can guard against the API changing
        # unexpectedly
        channel = self._send_password_login(" USER🙂NAME ", " pASS\U0001F622word ")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@ USER🙂NAME :test", channel.json_body["user_id"])
        mock_password_provider.check_password.assert_called_once_with(
            "@ USER🙂NAME :test", " pASS😢word "
        )

    @override_config(providers_config(PasswordOnlyAuthProvider))
    def test_password_only_auth_provider_ui_auth(self):
        """UI Auth should delegate correctly to the password provider"""

        # create the user, otherwise access doesn't work
        module_api = self.hs.get_module_api()
        self.get_success(module_api.register_user("u"))

        # log in twice, to get two devices
        mock_password_provider.check_password.return_value = defer.succeed(True)
        tok1 = self.login("u", "p")
        self.login("u", "p", device_id="dev2")
        mock_password_provider.reset_mock()

        # have the auth provider deny the request to start with
        mock_password_provider.check_password.return_value = defer.succeed(False)

        # make the initial request which returns a 401
        session = self._start_delete_device_session(tok1, "dev2")
        mock_password_provider.check_password.assert_not_called()

        # Make another request providing the UI auth flow.
        channel = self._authed_delete_device(tok1, "dev2", session, "u", "p")
        self.assertEqual(channel.code, 401)  # XXX why not a 403?
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        mock_password_provider.check_password.assert_called_once_with("@u:test", "p")
        mock_password_provider.reset_mock()

        # Finally, check the request goes through when we allow it
        mock_password_provider.check_password.return_value = defer.succeed(True)
        channel = self._authed_delete_device(tok1, "dev2", session, "u", "p")
        self.assertEqual(channel.code, 200)
        mock_password_provider.check_password.assert_called_once_with("@u:test", "p")

    @override_config(providers_config(PasswordOnlyAuthProvider))
    def test_local_user_fallback_login(self):
        """rejected login should fall back to local db"""
        self.register_user("localuser", "localpass")

        # check_password must return an awaitable
        mock_password_provider.check_password.return_value = defer.succeed(False)
        channel = self._send_password_login("u", "p")
        self.assertEqual(channel.code, 403, channel.result)

        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@localuser:test", channel.json_body["user_id"])

    @override_config(providers_config(PasswordOnlyAuthProvider))
    def test_local_user_fallback_ui_auth(self):
        """rejected login should fall back to local db"""
        self.register_user("localuser", "localpass")

        # have the auth provider deny the request
        mock_password_provider.check_password.return_value = defer.succeed(False)

        # log in twice, to get two devices
        tok1 = self.login("localuser", "localpass")
        self.login("localuser", "localpass", device_id="dev2")
        mock_password_provider.check_password.reset_mock()

        # first delete should give a 401
        session = self._start_delete_device_session(tok1, "dev2")
        mock_password_provider.check_password.assert_not_called()

        # Wrong password
        channel = self._authed_delete_device(tok1, "dev2", session, "localuser", "xxx")
        self.assertEqual(channel.code, 401)  # XXX why not a 403?
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        mock_password_provider.check_password.assert_called_once_with(
            "@localuser:test", "xxx"
        )
        mock_password_provider.reset_mock()

        # Right password
        channel = self._authed_delete_device(
            tok1, "dev2", session, "localuser", "localpass"
        )
        self.assertEqual(channel.code, 200)
        mock_password_provider.check_password.assert_called_once_with(
            "@localuser:test", "localpass"
        )

    @override_config(
        {
            **providers_config(PasswordOnlyAuthProvider),
            "password_config": {"localdb_enabled": False},
        }
    )
    def test_no_local_user_fallback_login(self):
        """localdb_enabled can block login with the local password
        """
        self.register_user("localuser", "localpass")

        # check_password must return an awaitable
        mock_password_provider.check_password.return_value = defer.succeed(False)
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 403)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        mock_password_provider.check_password.assert_called_once_with(
            "@localuser:test", "localpass"
        )

    @override_config(
        {
            **providers_config(PasswordOnlyAuthProvider),
            "password_config": {"localdb_enabled": False},
        }
    )
    def test_no_local_user_fallback_ui_auth(self):
        """localdb_enabled can block ui auth with the local password
        """
        self.register_user("localuser", "localpass")

        # allow login via the auth provider
        mock_password_provider.check_password.return_value = defer.succeed(True)

        # log in twice, to get two devices
        tok1 = self.login("localuser", "p")
        self.login("localuser", "p", device_id="dev2")
        mock_password_provider.check_password.reset_mock()

        # first delete should give a 401
        channel = self._delete_device(tok1, "dev2")
        self.assertEqual(channel.code, 401)
        # m.login.password UIA is permitted because the auth provider allows it,
        # even though the localdb does not.
        self.assertEqual(channel.json_body["flows"], [{"stages": ["m.login.password"]}])
        session = channel.json_body["session"]
        mock_password_provider.check_password.assert_not_called()

        # now try deleting with the local password
        mock_password_provider.check_password.return_value = defer.succeed(False)
        channel = self._authed_delete_device(
            tok1, "dev2", session, "localuser", "localpass"
        )
        self.assertEqual(channel.code, 401)  # XXX why not a 403?
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        mock_password_provider.check_password.assert_called_once_with(
            "@localuser:test", "localpass"
        )

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
        mock_password_provider.reset_mock()

        # try a weird username. Again, it's unclear what we *expect* to happen
        # in these cases, but at least we can guard against the API changing
        # unexpectedly
        mock_password_provider.check_auth.return_value = defer.succeed(
            "@ MALFORMED! :bz"
        )
        channel = self._send_login("test.login_type", " USER🙂NAME ", test_field=" abc ")
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual("@ MALFORMED! :bz", channel.json_body["user_id"])
        mock_password_provider.check_auth.assert_called_once_with(
            " USER🙂NAME ", "test.login_type", {"test_field": " abc "}
        )

    @override_config(providers_config(CustomAuthProvider))
    def test_custom_auth_provider_ui_auth(self):
        # register the user and log in twice, to get two devices
        self.register_user("localuser", "localpass")
        tok1 = self.login("localuser", "localpass")
        self.login("localuser", "localpass", device_id="dev2")

        # make the initial request which returns a 401
        channel = self._delete_device(tok1, "dev2")
        self.assertEqual(channel.code, 401)
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])
        self.assertIn({"stages": ["test.login_type"]}, channel.json_body["flows"])
        session = channel.json_body["session"]

        # missing param
        body = {
            "auth": {
                "type": "test.login_type",
                "identifier": {"type": "m.id.user", "user": "localuser"},
                "session": session,
            },
        }

        channel = self._delete_device(tok1, "dev2", body)
        self.assertEqual(channel.code, 400)
        # there's a perfectly good M_MISSING_PARAM errcode, but heaven forfend we should
        # use it...
        self.assertIn("Missing parameters", channel.json_body["error"])
        mock_password_provider.check_auth.assert_not_called()
        mock_password_provider.reset_mock()

        # right params, but authing as the wrong user
        mock_password_provider.check_auth.return_value = defer.succeed("@user:bz")
        body["auth"]["test_field"] = "foo"
        channel = self._delete_device(tok1, "dev2", body)
        self.assertEqual(channel.code, 403)
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")
        mock_password_provider.check_auth.assert_called_once_with(
            "localuser", "test.login_type", {"test_field": "foo"}
        )
        mock_password_provider.reset_mock()

        # and finally, succeed
        mock_password_provider.check_auth.return_value = defer.succeed(
            "@localuser:test"
        )
        channel = self._delete_device(tok1, "dev2", body)
        self.assertEqual(channel.code, 200)
        mock_password_provider.check_auth.assert_called_once_with(
            "localuser", "test.login_type", {"test_field": "foo"}
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
        {**providers_config(CustomAuthProvider), "password_config": {"enabled": False}}
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
            "password_config": {"enabled": False, "localdb_enabled": False},
        }
    )
    def test_custom_auth_password_disabled_localdb_enabled(self):
        """Check the localdb_enabled == enabled == False

        Regression test for https://github.com/matrix-org/synapse/issues/8914: check
        that setting *both* `localdb_enabled` *and* `password: enabled` to False doesn't
        cause an exception.
        """
        self.register_user("localuser", "localpass")

        flows = self._get_login_flows()
        self.assertEqual(flows, [{"type": "test.login_type"}] + ADDITIONAL_LOGIN_FLOWS)

        # login shouldn't work and should be rejected with a 400 ("unknown login type")
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 400, channel.result)
        mock_password_provider.check_auth.assert_not_called()

    @override_config(
        {
            **providers_config(PasswordCustomAuthProvider),
            "password_config": {"enabled": False},
        }
    )
    def test_password_custom_auth_password_disabled_login(self):
        """log in with a custom auth provider which implements password, but password
        login is disabled"""
        self.register_user("localuser", "localpass")

        flows = self._get_login_flows()
        self.assertEqual(flows, [{"type": "test.login_type"}] + ADDITIONAL_LOGIN_FLOWS)

        # login shouldn't work and should be rejected with a 400 ("unknown login type")
        channel = self._send_password_login("localuser", "localpass")
        self.assertEqual(channel.code, 400, channel.result)
        mock_password_provider.check_auth.assert_not_called()

    @override_config(
        {
            **providers_config(PasswordCustomAuthProvider),
            "password_config": {"enabled": False},
        }
    )
    def test_password_custom_auth_password_disabled_ui_auth(self):
        """UI Auth with a custom auth provider which implements password, but password
        login is disabled"""
        # register the user and log in twice via the test login type to get two devices,
        self.register_user("localuser", "localpass")
        mock_password_provider.check_auth.return_value = defer.succeed(
            "@localuser:test"
        )
        channel = self._send_login("test.login_type", "localuser", test_field="")
        self.assertEqual(channel.code, 200, channel.result)
        tok1 = channel.json_body["access_token"]

        channel = self._send_login(
            "test.login_type", "localuser", test_field="", device_id="dev2"
        )
        self.assertEqual(channel.code, 200, channel.result)

        # make the initial request which returns a 401
        channel = self._delete_device(tok1, "dev2")
        self.assertEqual(channel.code, 401)
        # Ensure that flows are what is expected. In particular, "password" should *not*
        # be present.
        self.assertIn({"stages": ["test.login_type"]}, channel.json_body["flows"])
        session = channel.json_body["session"]

        mock_password_provider.reset_mock()

        # check that auth with password is rejected
        body = {
            "auth": {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "localuser"},
                "password": "localpass",
                "session": session,
            },
        }

        channel = self._delete_device(tok1, "dev2", body)
        self.assertEqual(channel.code, 400)
        self.assertEqual(
            "Password login has been disabled.", channel.json_body["error"]
        )
        mock_password_provider.check_auth.assert_not_called()
        mock_password_provider.reset_mock()

        # successful auth
        body["auth"]["type"] = "test.login_type"
        body["auth"]["test_field"] = "x"
        channel = self._delete_device(tok1, "dev2", body)
        self.assertEqual(channel.code, 200)
        mock_password_provider.check_auth.assert_called_once_with(
            "localuser", "test.login_type", {"test_field": "x"}
        )

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

    def _get_login_flows(self) -> JsonDict:
        channel = self.make_request("GET", "/_matrix/client/r0/login")
        self.assertEqual(channel.code, 200, channel.result)
        return channel.json_body["flows"]

    def _send_password_login(self, user: str, password: str) -> FakeChannel:
        return self._send_login(type="m.login.password", user=user, password=password)

    def _send_login(self, type, user, **params) -> FakeChannel:
        params.update({"identifier": {"type": "m.id.user", "user": user}, "type": type})
        channel = self.make_request("POST", "/_matrix/client/r0/login", params)
        return channel

    def _start_delete_device_session(self, access_token, device_id) -> str:
        """Make an initial delete device request, and return the UI Auth session ID"""
        channel = self._delete_device(access_token, device_id)
        self.assertEqual(channel.code, 401)
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])
        return channel.json_body["session"]

    def _authed_delete_device(
        self,
        access_token: str,
        device_id: str,
        session: str,
        user_id: str,
        password: str,
    ) -> FakeChannel:
        """Make a delete device request, authenticating with the given uid/password"""
        return self._delete_device(
            access_token,
            device_id,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": user_id},
                    "password": password,
                    "session": session,
                },
            },
        )

    def _delete_device(
        self, access_token: str, device: str, body: Union[JsonDict, bytes] = b"",
    ) -> FakeChannel:
        """Delete an individual device."""
        channel = self.make_request(
            "DELETE", "devices/" + device, body, access_token=access_token
        )
        return channel
