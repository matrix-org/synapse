# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2017-2018 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import datetime
import os
from typing import Any, Dict, List, Tuple

import pkg_resources

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import (
    APP_SERVICE_REGISTRATION_TYPE,
    ApprovalNoticeMedium,
    LoginType,
)
from synapse.api.errors import Codes
from synapse.appservice import ApplicationService
from synapse.rest.client import account, account_validity, login, logout, register, sync
from synapse.server import HomeServer
from synapse.storage._base import db_to_json
from synapse.types import JsonDict
from synapse.util import Clock

from tests import unittest
from tests.unittest import override_config


class RegisterRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
        register.register_servlets,
        synapse.rest.admin.register_servlets,
    ]
    url = b"/_matrix/client/r0/register"

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["allow_guest_access"] = True
        return config

    def test_POST_appservice_registration_valid(self) -> None:
        user_id = "@as_user_kermit:test"
        as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            as_token,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )

        self.hs.get_datastores().main.services_cache.append(appservice)
        request_data = {
            "username": "as_user_kermit",
            "type": APP_SERVICE_REGISTRATION_TYPE,
        }

        channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )

        self.assertEqual(channel.code, 200, msg=channel.result)
        det_data = {"user_id": user_id, "home_server": self.hs.hostname}
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_appservice_registration_no_type(self) -> None:
        as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            as_token,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )

        self.hs.get_datastores().main.services_cache.append(appservice)
        request_data = {"username": "as_user_kermit"}

        channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )

        self.assertEqual(channel.code, 400, msg=channel.result)

    def test_POST_appservice_registration_invalid(self) -> None:
        self.appservice = None  # no application service exists
        request_data = {"username": "kermit", "type": APP_SERVICE_REGISTRATION_TYPE}
        channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )

        self.assertEqual(channel.code, 401, msg=channel.result)

    def test_POST_bad_password(self) -> None:
        request_data = {"username": "kermit", "password": 666}
        channel = self.make_request(b"POST", self.url, request_data)

        self.assertEqual(channel.code, 400, msg=channel.result)
        self.assertEqual(channel.json_body["error"], "Invalid password")

    def test_POST_bad_username(self) -> None:
        request_data = {"username": 777, "password": "monkey"}
        channel = self.make_request(b"POST", self.url, request_data)

        self.assertEqual(channel.code, 400, msg=channel.result)
        self.assertEqual(channel.json_body["error"], "Invalid username")

    def test_POST_user_valid(self) -> None:
        user_id = "@kermit:test"
        device_id = "frogfone"
        request_data = {
            "username": "kermit",
            "password": "monkey",
            "device_id": device_id,
            "auth": {"type": LoginType.DUMMY},
        }
        channel = self.make_request(b"POST", self.url, request_data)

        det_data = {
            "user_id": user_id,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertEqual(channel.code, 200, msg=channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    @override_config({"enable_registration": False})
    def test_POST_disabled_registration(self) -> None:
        request_data = {"username": "kermit", "password": "monkey"}
        self.auth_result = (None, {"username": "kermit", "password": "monkey"}, None)

        channel = self.make_request(b"POST", self.url, request_data)

        self.assertEqual(channel.code, 403, msg=channel.result)
        self.assertEqual(channel.json_body["error"], "Registration has been disabled")
        self.assertEqual(channel.json_body["errcode"], "M_FORBIDDEN")

    def test_POST_guest_registration(self) -> None:
        self.hs.config.key.macaroon_secret_key = "test"
        self.hs.config.registration.allow_guest_access = True

        channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        det_data = {"home_server": self.hs.hostname, "device_id": "guest_device"}
        self.assertEqual(channel.code, 200, msg=channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_disabled_guest_registration(self) -> None:
        self.hs.config.registration.allow_guest_access = False

        channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEqual(channel.code, 403, msg=channel.result)
        self.assertEqual(channel.json_body["error"], "Guest access is disabled")

    @override_config({"rc_registration": {"per_second": 0.17, "burst_count": 5}})
    def test_POST_ratelimiting_guest(self) -> None:
        for i in range(0, 6):
            url = self.url + b"?kind=guest"
            channel = self.make_request(b"POST", url, b"{}")

            if i == 5:
                self.assertEqual(channel.code, 429, msg=channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEqual(channel.code, 200, msg=channel.result)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEqual(channel.code, 200, msg=channel.result)

    @override_config({"rc_registration": {"per_second": 0.17, "burst_count": 5}})
    def test_POST_ratelimiting(self) -> None:
        for i in range(0, 6):
            request_data = {
                "username": "kermit" + str(i),
                "password": "monkey",
                "device_id": "frogfone",
                "auth": {"type": LoginType.DUMMY},
            }
            channel = self.make_request(b"POST", self.url, request_data)

            if i == 5:
                self.assertEqual(channel.code, 429, msg=channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEqual(channel.code, 200, msg=channel.result)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEqual(channel.code, 200, msg=channel.result)

    @override_config({"registration_requires_token": True})
    def test_POST_registration_requires_token(self) -> None:
        username = "kermit"
        device_id = "frogfone"
        token = "abcd"
        store = self.hs.get_datastores().main
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": None,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": None,
                },
            )
        )
        params: JsonDict = {
            "username": username,
            "password": "monkey",
            "device_id": device_id,
        }

        # Request without auth to get flows and session
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        flows = channel.json_body["flows"]
        # Synapse adds a dummy stage to differentiate flows where otherwise one
        # flow would be a subset of another flow.
        self.assertCountEqual(
            [[LoginType.REGISTRATION_TOKEN, LoginType.DUMMY]],
            (f["stages"] for f in flows),
        )
        session = channel.json_body["session"]

        # Do the registration token stage and check it has completed
        params["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session,
        }
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        completed = channel.json_body["completed"]
        self.assertCountEqual([LoginType.REGISTRATION_TOKEN], completed)

        # Do the m.login.dummy stage and check registration was successful
        params["auth"] = {
            "type": LoginType.DUMMY,
            "session": session,
        }
        channel = self.make_request(b"POST", self.url, params)
        det_data = {
            "user_id": f"@{username}:{self.hs.hostname}",
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertEqual(channel.code, 200, msg=channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

        # Check the `completed` counter has been incremented and pending is 0
        res = self.get_success(
            store.db_pool.simple_select_one(
                "registration_tokens",
                keyvalues={"token": token},
                retcols=["pending", "completed"],
            )
        )
        self.assertEqual(res["completed"], 1)
        self.assertEqual(res["pending"], 0)

    @override_config({"registration_requires_token": True})
    def test_POST_registration_token_invalid(self) -> None:
        params: JsonDict = {
            "username": "kermit",
            "password": "monkey",
        }
        # Request without auth to get session
        channel = self.make_request(b"POST", self.url, params)
        session = channel.json_body["session"]

        # Test with token param missing (invalid)
        params["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "session": session,
        }
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.MISSING_PARAM)
        self.assertEqual(channel.json_body["completed"], [])

        # Test with non-string (invalid)
        params["auth"]["token"] = 1234
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.INVALID_PARAM)
        self.assertEqual(channel.json_body["completed"], [])

        # Test with unknown token (invalid)
        params["auth"]["token"] = "1234"
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.UNAUTHORIZED)
        self.assertEqual(channel.json_body["completed"], [])

    @override_config({"registration_requires_token": True})
    def test_POST_registration_token_limit_uses(self) -> None:
        token = "abcd"
        store = self.hs.get_datastores().main
        # Create token that can be used once
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": 1,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": None,
                },
            )
        )
        params1: JsonDict = {"username": "bert", "password": "monkey"}
        params2: JsonDict = {"username": "ernie", "password": "monkey"}
        # Do 2 requests without auth to get two session IDs
        channel1 = self.make_request(b"POST", self.url, params1)
        session1 = channel1.json_body["session"]
        channel2 = self.make_request(b"POST", self.url, params2)
        session2 = channel2.json_body["session"]

        # Use token with session1 and check `pending` is 1
        params1["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session1,
        }
        self.make_request(b"POST", self.url, params1)
        # Repeat request to make sure pending isn't increased again
        self.make_request(b"POST", self.url, params1)
        pending = self.get_success(
            store.db_pool.simple_select_one_onecol(
                "registration_tokens",
                keyvalues={"token": token},
                retcol="pending",
            )
        )
        self.assertEqual(pending, 1)

        # Check auth fails when using token with session2
        params2["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session2,
        }
        channel = self.make_request(b"POST", self.url, params2)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.UNAUTHORIZED)
        self.assertEqual(channel.json_body["completed"], [])

        # Complete registration with session1
        params1["auth"]["type"] = LoginType.DUMMY
        self.make_request(b"POST", self.url, params1)
        # Check pending=0 and completed=1
        res = self.get_success(
            store.db_pool.simple_select_one(
                "registration_tokens",
                keyvalues={"token": token},
                retcols=["pending", "completed"],
            )
        )
        self.assertEqual(res["pending"], 0)
        self.assertEqual(res["completed"], 1)

        # Check auth still fails when using token with session2
        channel = self.make_request(b"POST", self.url, params2)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.UNAUTHORIZED)
        self.assertEqual(channel.json_body["completed"], [])

    @override_config({"registration_requires_token": True})
    def test_POST_registration_token_expiry(self) -> None:
        token = "abcd"
        now = self.hs.get_clock().time_msec()
        store = self.hs.get_datastores().main
        # Create token that expired yesterday
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": None,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": now - 24 * 60 * 60 * 1000,
                },
            )
        )
        params: JsonDict = {"username": "kermit", "password": "monkey"}
        # Request without auth to get session
        channel = self.make_request(b"POST", self.url, params)
        session = channel.json_body["session"]

        # Check authentication fails with expired token
        params["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session,
        }
        channel = self.make_request(b"POST", self.url, params)
        self.assertEqual(channel.code, 401, msg=channel.result)
        self.assertEqual(channel.json_body["errcode"], Codes.UNAUTHORIZED)
        self.assertEqual(channel.json_body["completed"], [])

        # Update token so it expires tomorrow
        self.get_success(
            store.db_pool.simple_update_one(
                "registration_tokens",
                keyvalues={"token": token},
                updatevalues={"expiry_time": now + 24 * 60 * 60 * 1000},
            )
        )

        # Check authentication succeeds
        channel = self.make_request(b"POST", self.url, params)
        completed = channel.json_body["completed"]
        self.assertCountEqual([LoginType.REGISTRATION_TOKEN], completed)

    @override_config({"registration_requires_token": True})
    def test_POST_registration_token_session_expiry(self) -> None:
        """Test `pending` is decremented when an uncompleted session expires."""
        token = "abcd"
        store = self.hs.get_datastores().main
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": None,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": None,
                },
            )
        )

        # Do 2 requests without auth to get two session IDs
        params1: JsonDict = {"username": "bert", "password": "monkey"}
        params2: JsonDict = {"username": "ernie", "password": "monkey"}
        channel1 = self.make_request(b"POST", self.url, params1)
        session1 = channel1.json_body["session"]
        channel2 = self.make_request(b"POST", self.url, params2)
        session2 = channel2.json_body["session"]

        # Use token with both sessions
        params1["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session1,
        }
        self.make_request(b"POST", self.url, params1)

        params2["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session2,
        }
        self.make_request(b"POST", self.url, params2)

        # Complete registration with session1
        params1["auth"]["type"] = LoginType.DUMMY
        self.make_request(b"POST", self.url, params1)

        # Check `result` of registration token stage for session1 is `True`
        result1 = self.get_success(
            store.db_pool.simple_select_one_onecol(
                "ui_auth_sessions_credentials",
                keyvalues={
                    "session_id": session1,
                    "stage_type": LoginType.REGISTRATION_TOKEN,
                },
                retcol="result",
            )
        )
        self.assertTrue(db_to_json(result1))

        # Check `result` for session2 is the token used
        result2 = self.get_success(
            store.db_pool.simple_select_one_onecol(
                "ui_auth_sessions_credentials",
                keyvalues={
                    "session_id": session2,
                    "stage_type": LoginType.REGISTRATION_TOKEN,
                },
                retcol="result",
            )
        )
        self.assertEqual(db_to_json(result2), token)

        # Delete both sessions (mimics expiry)
        self.get_success(
            store.delete_old_ui_auth_sessions(self.hs.get_clock().time_msec())
        )

        # Check pending is now 0
        pending = self.get_success(
            store.db_pool.simple_select_one_onecol(
                "registration_tokens",
                keyvalues={"token": token},
                retcol="pending",
            )
        )
        self.assertEqual(pending, 0)

    @override_config({"registration_requires_token": True})
    def test_POST_registration_token_session_expiry_deleted_token(self) -> None:
        """Test session expiry doesn't break when the token is deleted.

        1. Start but don't complete UIA with a registration token
        2. Delete the token from the database
        3. Expire the session
        """
        token = "abcd"
        store = self.hs.get_datastores().main
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": None,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": None,
                },
            )
        )

        # Do request without auth to get a session ID
        params: JsonDict = {"username": "kermit", "password": "monkey"}
        channel = self.make_request(b"POST", self.url, params)
        session = channel.json_body["session"]

        # Use token
        params["auth"] = {
            "type": LoginType.REGISTRATION_TOKEN,
            "token": token,
            "session": session,
        }
        self.make_request(b"POST", self.url, params)

        # Delete token
        self.get_success(
            store.db_pool.simple_delete_one(
                "registration_tokens",
                keyvalues={"token": token},
            )
        )

        # Delete session (mimics expiry)
        self.get_success(
            store.delete_old_ui_auth_sessions(self.hs.get_clock().time_msec())
        )

    def test_advertised_flows(self) -> None:
        channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEqual(channel.code, 401, msg=channel.result)
        flows = channel.json_body["flows"]

        # with the stock config, we only expect the dummy flow
        self.assertCountEqual([["m.login.dummy"]], (f["stages"] for f in flows))

    @unittest.override_config(
        {
            "public_baseurl": "https://test_server",
            "enable_registration_captcha": True,
            "user_consent": {
                "version": "1",
                "template_dir": "/",
                "require_at_registration": True,
            },
            "account_threepid_delegates": {
                "msisdn": "https://id_server",
            },
            "email": {"notif_from": "Synapse <synapse@example.com>"},
        }
    )
    def test_advertised_flows_captcha_and_terms_and_3pids(self) -> None:
        channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEqual(channel.code, 401, msg=channel.result)
        flows = channel.json_body["flows"]

        self.assertCountEqual(
            [
                ["m.login.recaptcha", "m.login.terms", "m.login.dummy"],
                ["m.login.recaptcha", "m.login.terms", "m.login.email.identity"],
                ["m.login.recaptcha", "m.login.terms", "m.login.msisdn"],
                [
                    "m.login.recaptcha",
                    "m.login.terms",
                    "m.login.msisdn",
                    "m.login.email.identity",
                ],
            ],
            (f["stages"] for f in flows),
        )

    @unittest.override_config(
        {
            "public_baseurl": "https://test_server",
            "registrations_require_3pid": ["email"],
            "disable_msisdn_registration": True,
            "email": {
                "smtp_host": "mail_server",
                "smtp_port": 2525,
                "notif_from": "sender@host",
            },
        }
    )
    def test_advertised_flows_no_msisdn_email_required(self) -> None:
        channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEqual(channel.code, 401, msg=channel.result)
        flows = channel.json_body["flows"]

        # with the stock config, we expect all four combinations of 3pid
        self.assertCountEqual(
            [["m.login.email.identity"]], (f["stages"] for f in flows)
        )

    @unittest.override_config(
        {
            "request_token_inhibit_3pid_errors": True,
            "public_baseurl": "https://test_server",
            "email": {
                "smtp_host": "mail_server",
                "smtp_port": 2525,
                "notif_from": "sender@host",
            },
        }
    )
    def test_request_token_existing_email_inhibit_error(self) -> None:
        """Test that requesting a token via this endpoint doesn't leak existing
        associations if configured that way.
        """
        user_id = self.register_user("kermit", "monkey")
        self.login("kermit", "monkey")

        email = "test@example.com"

        # Add a threepid
        self.get_success(
            self.hs.get_datastores().main.user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email,
                validated_at=0,
                added_at=0,
            )
        )

        channel = self.make_request(
            "POST",
            b"register/email/requestToken",
            {"client_secret": "foobar", "email": email, "send_attempt": 1},
        )
        self.assertEqual(200, channel.code, channel.result)

        self.assertIsNotNone(channel.json_body.get("sid"))

    @unittest.override_config(
        {
            "public_baseurl": "https://test_server",
            "email": {
                "smtp_host": "mail_server",
                "smtp_port": 2525,
                "notif_from": "sender@host",
            },
        }
    )
    def test_reject_invalid_email(self) -> None:
        """Check that bad emails are rejected"""

        # Test for email with multiple @
        channel = self.make_request(
            "POST",
            b"register/email/requestToken",
            {"client_secret": "foobar", "email": "email@@email", "send_attempt": 1},
        )
        self.assertEqual(400, channel.code, channel.result)
        # Check error to ensure that we're not erroring due to a bug in the test.
        self.assertEqual(
            channel.json_body,
            {"errcode": "M_UNKNOWN", "error": "Unable to parse email address"},
        )

        # Test for email with no @
        channel = self.make_request(
            "POST",
            b"register/email/requestToken",
            {"client_secret": "foobar", "email": "email", "send_attempt": 1},
        )
        self.assertEqual(400, channel.code, channel.result)
        self.assertEqual(
            channel.json_body,
            {"errcode": "M_UNKNOWN", "error": "Unable to parse email address"},
        )

        # Test for super long email
        email = "a@" + "a" * 1000
        channel = self.make_request(
            "POST",
            b"register/email/requestToken",
            {"client_secret": "foobar", "email": email, "send_attempt": 1},
        )
        self.assertEqual(400, channel.code, channel.result)
        self.assertEqual(
            channel.json_body,
            {"errcode": "M_UNKNOWN", "error": "Unable to parse email address"},
        )

    @override_config(
        {
            "inhibit_user_in_use_error": True,
        }
    )
    def test_inhibit_user_in_use_error(self) -> None:
        """Tests that the 'inhibit_user_in_use_error' configuration flag behaves
        correctly.
        """
        username = "arthur"

        # Manually register the user, so we know the test isn't passing because of a lack
        # of clashing.
        reg_handler = self.hs.get_registration_handler()
        self.get_success(reg_handler.register_user(username))

        # Check that /available correctly ignores the username provided despite the
        # username being already registered.
        channel = self.make_request("GET", "register/available?username=" + username)
        self.assertEqual(200, channel.code, channel.result)

        # Test that when starting a UIA registration flow the request doesn't fail because
        # of a conflicting username
        channel = self.make_request(
            "POST",
            "register",
            {"username": username, "type": "m.login.password", "password": "foo"},
        )
        self.assertEqual(channel.code, 401)
        self.assertIn("session", channel.json_body)

        # Test that finishing the registration fails because of a conflicting username.
        session = channel.json_body["session"]
        channel = self.make_request(
            "POST",
            "register",
            {"auth": {"session": session, "type": LoginType.DUMMY}},
        )
        self.assertEqual(channel.code, 400, channel.json_body)
        self.assertEqual(channel.json_body["errcode"], Codes.USER_IN_USE)

    @override_config(
        {
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            }
        }
    )
    def test_require_approval(self) -> None:
        channel = self.make_request(
            "POST",
            "register",
            {
                "username": "kermit",
                "password": "monkey",
                "auth": {"type": LoginType.DUMMY},
            },
        )
        self.assertEqual(403, channel.code, channel.result)
        self.assertEqual(Codes.USER_AWAITING_APPROVAL, channel.json_body["errcode"])
        self.assertEqual(
            ApprovalNoticeMedium.NONE, channel.json_body["approval_notice_medium"]
        )


class AccountValidityTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        logout.register_servlets,
        account_validity.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        # Test for account expiring after a week.
        config["enable_registration"] = True
        config["account_validity"] = {
            "enabled": True,
            "period": 604800000,  # Time in ms for 1 week
        }
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def test_validity_period(self) -> None:
        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        channel = self.make_request(b"GET", "/sync", access_token=tok)

        self.assertEqual(channel.code, 200, msg=channel.result)

        self.reactor.advance(datetime.timedelta(weeks=1).total_seconds())

        channel = self.make_request(b"GET", "/sync", access_token=tok)

        self.assertEqual(channel.code, 403, msg=channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.EXPIRED_ACCOUNT, channel.result
        )

    def test_manual_renewal(self) -> None:
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.reactor.advance(datetime.timedelta(weeks=1).total_seconds())

        # If we register the admin user at the beginning of the test, it will
        # expire at the same time as the normal user and the renewal request
        # will be denied.
        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_synapse/admin/v1/account_validity/validity"
        request_data = {"user_id": user_id}
        channel = self.make_request(b"POST", url, request_data, access_token=admin_tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

    def test_manual_expire(self) -> None:
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_synapse/admin/v1/account_validity/validity"
        request_data = {
            "user_id": user_id,
            "expiration_ts": 0,
            "enable_renewal_emails": False,
        }
        channel = self.make_request(b"POST", url, request_data, access_token=admin_tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEqual(channel.code, 403, msg=channel.result)
        self.assertEqual(
            channel.json_body["errcode"], Codes.EXPIRED_ACCOUNT, channel.result
        )

    def test_logging_out_expired_user(self) -> None:
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_synapse/admin/v1/account_validity/validity"
        request_data = {
            "user_id": user_id,
            "expiration_ts": 0,
            "enable_renewal_emails": False,
        }
        channel = self.make_request(b"POST", url, request_data, access_token=admin_tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Try to log the user out
        channel = self.make_request(b"POST", "/logout", access_token=tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Log the user in again (allowed for expired accounts)
        tok = self.login("kermit", "monkey")

        # Try to log out all of the user's sessions
        channel = self.make_request(b"POST", "/logout/all", access_token=tok)
        self.assertEqual(channel.code, 200, msg=channel.result)


class AccountValidityRenewalByEmailTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        account_validity.register_servlets,
        account.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        # Test for account expiring after a week and renewal emails being sent 2
        # days before expiry.
        config["enable_registration"] = True
        config["account_validity"] = {
            "enabled": True,
            "period": 604800000,  # Time in ms for 1 week
            "renew_at": 172800000,  # Time in ms for 2 days
            "renew_by_email_enabled": True,
            "renew_email_subject": "Renew your account",
            "account_renewed_html_path": "account_renewed.html",
            "invalid_token_html_path": "invalid_token.html",
        }

        # Email config.

        config["email"] = {
            "enable_notifs": True,
            "template_dir": os.path.abspath(
                pkg_resources.resource_filename("synapse", "res/templates")
            ),
            "expiry_template_html": "notice_expiry.html",
            "expiry_template_text": "notice_expiry.txt",
            "notif_template_html": "notif_mail.html",
            "notif_template_text": "notif_mail.txt",
            "smtp_host": "127.0.0.1",
            "smtp_port": 20,
            "require_transport_security": False,
            "smtp_user": None,
            "smtp_pass": None,
            "notif_from": "test@example.com",
        }

        self.hs = self.setup_test_homeserver(config=config)

        async def sendmail(*args: Any, **kwargs: Any) -> None:
            self.email_attempts.append((args, kwargs))

        self.email_attempts: List[Tuple[Any, Any]] = []
        self.hs.get_send_email_handler()._sendmail = sendmail

        self.store = self.hs.get_datastores().main

        return self.hs

    def test_renewal_email(self) -> None:
        self.email_attempts = []

        (user_id, tok) = self.create_user()

        # Move 5 days forward. This should trigger a renewal email to be sent.
        self.reactor.advance(datetime.timedelta(days=5).total_seconds())
        self.assertEqual(len(self.email_attempts), 1)

        # Retrieving the URL from the email is too much pain for now, so we
        # retrieve the token from the DB.
        renewal_token = self.get_success(self.store.get_renewal_token_for_user(user_id))
        url = "/_matrix/client/unstable/account_validity/renew?token=%s" % renewal_token
        channel = self.make_request(b"GET", url)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Check that we're getting HTML back.
        content_type = channel.headers.getRawHeaders(b"Content-Type")
        self.assertEqual(content_type, [b"text/html; charset=utf-8"], channel.result)

        # Check that the HTML we're getting is the one we expect on a successful renewal.
        expiration_ts = self.get_success(self.store.get_expiration_ts_for_user(user_id))
        expected_html = self.hs.config.account_validity.account_validity_account_renewed_template.render(
            expiration_ts=expiration_ts
        )
        self.assertEqual(
            channel.result["body"], expected_html.encode("utf8"), channel.result
        )

        # Move 1 day forward. Try to renew with the same token again.
        url = "/_matrix/client/unstable/account_validity/renew?token=%s" % renewal_token
        channel = self.make_request(b"GET", url)
        self.assertEqual(channel.code, 200, msg=channel.result)

        # Check that we're getting HTML back.
        content_type = channel.headers.getRawHeaders(b"Content-Type")
        self.assertEqual(content_type, [b"text/html; charset=utf-8"], channel.result)

        # Check that the HTML we're getting is the one we expect when reusing a
        # token. The account expiration date should not have changed.
        expected_html = self.hs.config.account_validity.account_validity_account_previously_renewed_template.render(
            expiration_ts=expiration_ts
        )
        self.assertEqual(
            channel.result["body"], expected_html.encode("utf8"), channel.result
        )

        # Move 3 days forward. If the renewal failed, every authed request with
        # our access token should be denied from now, otherwise they should
        # succeed.
        self.reactor.advance(datetime.timedelta(days=3).total_seconds())
        channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEqual(channel.code, 200, msg=channel.result)

    def test_renewal_invalid_token(self) -> None:
        # Hit the renewal endpoint with an invalid token and check that it behaves as
        # expected, i.e. that it responds with 404 Not Found and the correct HTML.
        url = "/_matrix/client/unstable/account_validity/renew?token=123"
        channel = self.make_request(b"GET", url)
        self.assertEqual(channel.code, 404, msg=channel.result)

        # Check that we're getting HTML back.
        content_type = channel.headers.getRawHeaders(b"Content-Type")
        self.assertEqual(content_type, [b"text/html; charset=utf-8"], channel.result)

        # Check that the HTML we're getting is the one we expect when using an
        # invalid/unknown token.
        expected_html = (
            self.hs.config.account_validity.account_validity_invalid_token_template.render()
        )
        self.assertEqual(
            channel.result["body"], expected_html.encode("utf8"), channel.result
        )

    def test_manual_email_send(self) -> None:
        self.email_attempts = []

        (user_id, tok) = self.create_user()
        channel = self.make_request(
            b"POST",
            "/_matrix/client/unstable/account_validity/send_mail",
            access_token=tok,
        )
        self.assertEqual(channel.code, 200, msg=channel.result)

        self.assertEqual(len(self.email_attempts), 1)

    def test_deactivated_user(self) -> None:
        self.email_attempts = []

        (user_id, tok) = self.create_user()

        request_data = {
            "auth": {
                "type": "m.login.password",
                "user": user_id,
                "password": "monkey",
            },
            "erase": False,
        }
        channel = self.make_request(
            "POST", "account/deactivate", request_data, access_token=tok
        )
        self.assertEqual(channel.code, 200)

        self.reactor.advance(datetime.timedelta(days=8).total_seconds())

        self.assertEqual(len(self.email_attempts), 0)

    def create_user(self) -> Tuple[str, str]:
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")
        # We need to manually add an email address otherwise the handler will do
        # nothing.
        now = self.hs.get_clock().time_msec()
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address="kermit@example.com",
                validated_at=now,
                added_at=now,
            )
        )
        return user_id, tok

    def test_manual_email_send_expired_account(self) -> None:
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        # We need to manually add an email address otherwise the handler will do
        # nothing.
        now = self.hs.get_clock().time_msec()
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address="kermit@example.com",
                validated_at=now,
                added_at=now,
            )
        )

        # Make the account expire.
        self.reactor.advance(datetime.timedelta(days=8).total_seconds())

        # Ignore all emails sent by the automatic background task and only focus on the
        # ones sent manually.
        self.email_attempts = []

        # Test that we're still able to manually trigger a mail to be sent.
        channel = self.make_request(
            b"POST",
            "/_matrix/client/unstable/account_validity/send_mail",
            access_token=tok,
        )
        self.assertEqual(channel.code, 200, msg=channel.result)

        self.assertEqual(len(self.email_attempts), 1)


class AccountValidityBackgroundJobTestCase(unittest.HomeserverTestCase):

    servlets = [synapse.rest.admin.register_servlets_for_client_rest_resource]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.validity_period = 10
        self.max_delta = self.validity_period * 10.0 / 100.0

        config = self.default_config()

        config["enable_registration"] = True
        config["account_validity"] = {"enabled": False}

        self.hs = self.setup_test_homeserver(config=config)

        # We need to set these directly, instead of in the homeserver config dict above.
        # This is due to account validity-related config options not being read by
        # Synapse when account_validity.enabled is False.
        self.hs.get_datastores().main._account_validity_period = self.validity_period
        self.hs.get_datastores().main._account_validity_startup_job_max_delta = (
            self.max_delta
        )

        self.store = self.hs.get_datastores().main

        return self.hs

    def test_background_job(self) -> None:
        """
        Tests the same thing as test_background_job, except that it sets the
        startup_job_max_delta parameter and checks that the expiration date is within the
        allowed range.
        """
        user_id = self.register_user("kermit_delta", "user")

        self.hs.config.account_validity.startup_job_max_delta = self.max_delta

        now_ms = self.hs.get_clock().time_msec()
        self.get_success(self.store._set_expiration_date_when_missing())

        res = self.get_success(self.store.get_expiration_ts_for_user(user_id))

        self.assertGreaterEqual(res, now_ms + self.validity_period - self.max_delta)
        self.assertLessEqual(res, now_ms + self.validity_period)


class RegistrationTokenValidityRestServletTestCase(unittest.HomeserverTestCase):
    servlets = [register.register_servlets]
    url = "/_matrix/client/v1/register/m.login.registration_token/validity"

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["registration_requires_token"] = True
        return config

    def test_GET_token_valid(self) -> None:
        token = "abcd"
        store = self.hs.get_datastores().main
        self.get_success(
            store.db_pool.simple_insert(
                "registration_tokens",
                {
                    "token": token,
                    "uses_allowed": None,
                    "pending": 0,
                    "completed": 0,
                    "expiry_time": None,
                },
            )
        )

        channel = self.make_request(
            b"GET",
            f"{self.url}?token={token}",
        )
        self.assertEqual(channel.code, 200, msg=channel.result)
        self.assertEqual(channel.json_body["valid"], True)

    def test_GET_token_invalid(self) -> None:
        token = "1234"
        channel = self.make_request(
            b"GET",
            f"{self.url}?token={token}",
        )
        self.assertEqual(channel.code, 200, msg=channel.result)
        self.assertEqual(channel.json_body["valid"], False)

    @override_config(
        {"rc_registration_token_validity": {"per_second": 0.1, "burst_count": 5}}
    )
    def test_GET_ratelimiting(self) -> None:
        token = "1234"

        for i in range(0, 6):
            channel = self.make_request(
                b"GET",
                f"{self.url}?token={token}",
            )

            if i == 5:
                self.assertEqual(channel.code, 429, msg=channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEqual(channel.code, 200, msg=channel.result)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        channel = self.make_request(
            b"GET",
            f"{self.url}?token={token}",
        )
        self.assertEqual(channel.code, 200, msg=channel.result)
