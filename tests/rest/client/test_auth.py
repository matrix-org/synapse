# Copyright 2018 New Vector
# Copyright 2020-2021 The Matrix.org Foundation C.I.C
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
from http import HTTPStatus
from typing import Any, Dict, List, Optional, Tuple, Union

from twisted.internet.defer import succeed
from twisted.test.proto_helpers import MemoryReactor
from twisted.web.resource import Resource

import synapse.rest.admin
from synapse.api.constants import ApprovalNoticeMedium, LoginType
from synapse.api.errors import Codes
from synapse.handlers.ui_auth.checkers import UserInteractiveAuthChecker
from synapse.rest.client import account, auth, devices, login, logout, register
from synapse.rest.synapse.client import build_synapse_client_resource_tree
from synapse.server import HomeServer
from synapse.storage.database import LoggingTransaction
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests import unittest
from tests.handlers.test_oidc import HAS_OIDC
from tests.rest.client.utils import TEST_OIDC_CONFIG
from tests.server import FakeChannel
from tests.unittest import override_config, skip_unless


class DummyRecaptchaChecker(UserInteractiveAuthChecker):
    def __init__(self, hs: HomeServer) -> None:
        super().__init__(hs)
        self.recaptcha_attempts: List[Tuple[dict, str]] = []

    def check_auth(self, authdict: dict, clientip: str) -> Any:
        self.recaptcha_attempts.append((authdict, clientip))
        return succeed(True)


class FallbackAuthTests(unittest.HomeserverTestCase):

    servlets = [
        auth.register_servlets,
        register.register_servlets,
    ]
    hijack_auth = False

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:

        config = self.default_config()

        config["enable_registration_captcha"] = True
        config["recaptcha_public_key"] = "brokencake"
        config["registrations_require_3pid"] = []

        hs = self.setup_test_homeserver(config=config)
        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.recaptcha_checker = DummyRecaptchaChecker(hs)
        auth_handler = hs.get_auth_handler()
        auth_handler.checkers[LoginType.RECAPTCHA] = self.recaptcha_checker

    def register(self, expected_response: int, body: JsonDict) -> FakeChannel:
        """Make a register request."""
        channel = self.make_request("POST", "register", body)

        self.assertEqual(channel.code, expected_response)
        return channel

    def recaptcha(
        self,
        session: str,
        expected_post_response: int,
        post_session: Optional[str] = None,
    ) -> None:
        """Get and respond to a fallback recaptcha. Returns the second request."""
        if post_session is None:
            post_session = session

        channel = self.make_request(
            "GET", "auth/m.login.recaptcha/fallback/web?session=" + session
        )
        self.assertEqual(channel.code, HTTPStatus.OK)

        channel = self.make_request(
            "POST",
            "auth/m.login.recaptcha/fallback/web?session="
            + post_session
            + "&g-recaptcha-response=a",
        )
        self.assertEqual(channel.code, expected_post_response)

        # The recaptcha handler is called with the response given
        attempts = self.recaptcha_checker.recaptcha_attempts
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0][0]["response"], "a")

    def test_fallback_captcha(self) -> None:
        """Ensure that fallback auth via a captcha works."""
        # Returns a 401 as per the spec
        channel = self.register(
            HTTPStatus.UNAUTHORIZED,
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )

        # Grab the session
        session = channel.json_body["session"]
        # Assert our configured public key is being given
        self.assertEqual(
            channel.json_body["params"]["m.login.recaptcha"]["public_key"], "brokencake"
        )

        # Complete the recaptcha step.
        self.recaptcha(session, HTTPStatus.OK)

        # also complete the dummy auth
        self.register(
            HTTPStatus.OK, {"auth": {"session": session, "type": "m.login.dummy"}}
        )

        # Now we should have fulfilled a complete auth flow, including
        # the recaptcha fallback step, we can then send a
        # request to the register API with the session in the authdict.
        channel = self.register(HTTPStatus.OK, {"auth": {"session": session}})

        # We're given a registered user.
        self.assertEqual(channel.json_body["user_id"], "@user:test")

    def test_complete_operation_unknown_session(self) -> None:
        """
        Attempting to mark an invalid session as complete should error.
        """
        # Make the initial request to register. (Later on a different password
        # will be used.)
        # Returns a 401 as per the spec
        channel = self.register(
            HTTPStatus.UNAUTHORIZED,
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )

        # Grab the session
        session = channel.json_body["session"]
        # Assert our configured public key is being given
        self.assertEqual(
            channel.json_body["params"]["m.login.recaptcha"]["public_key"], "brokencake"
        )

        # Attempt to complete the recaptcha step with an unknown session.
        # This results in an error.
        self.recaptcha(session, 400, session + "unknown")


class UIAuthTests(unittest.HomeserverTestCase):
    servlets = [
        auth.register_servlets,
        devices.register_servlets,
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        register.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()

        # public_baseurl uses an http:// scheme because FakeChannel.isSecure() returns
        # False, so synapse will see the requested uri as http://..., so using http in
        # the public_baseurl stops Synapse trying to redirect to https.
        config["public_baseurl"] = "http://synapse.test"

        if HAS_OIDC:
            # we enable OIDC as a way of testing SSO flows
            oidc_config = {}
            oidc_config.update(TEST_OIDC_CONFIG)
            oidc_config["allow_existing_users"] = True
            config["oidc_config"] = oidc_config

        return config

    def create_resource_dict(self) -> Dict[str, Resource]:
        resource_dict = super().create_resource_dict()
        resource_dict.update(build_synapse_client_resource_tree(self.hs))
        return resource_dict

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_pass = "pass"
        self.user = self.register_user("test", self.user_pass)
        self.device_id = "dev1"

        # Force-enable password login for just long enough to log in.
        auth_handler = self.hs.get_auth_handler()
        allow_auth_for_login = auth_handler._password_enabled_for_login
        auth_handler._password_enabled_for_login = True

        self.user_tok = self.login("test", self.user_pass, self.device_id)

        # Restore password login to however it was.
        auth_handler._password_enabled_for_login = allow_auth_for_login

    def delete_device(
        self,
        access_token: str,
        device: str,
        expected_response: int,
        body: Union[bytes, JsonDict] = b"",
    ) -> FakeChannel:
        """Delete an individual device."""
        channel = self.make_request(
            "DELETE",
            "devices/" + device,
            body,
            access_token=access_token,
        )

        # Ensure the response is sane.
        self.assertEqual(channel.code, expected_response)

        return channel

    def delete_devices(self, expected_response: int, body: JsonDict) -> FakeChannel:
        """Delete 1 or more devices."""
        # Note that this uses the delete_devices endpoint so that we can modify
        # the payload half-way through some tests.
        channel = self.make_request(
            "POST",
            "delete_devices",
            body,
            access_token=self.user_tok,
        )

        # Ensure the response is sane.
        self.assertEqual(channel.code, expected_response)

        return channel

    def test_ui_auth(self) -> None:
        """
        Test user interactive authentication outside of registration.
        """
        # Attempt to delete this device.
        # Returns a 401 as per the spec
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            self.device_id,
            HTTPStatus.OK,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    @override_config({"password_config": {"enabled": "only_for_reauth"}})
    def test_ui_auth_with_passwords_for_reauth_only(self) -> None:
        """
        Test user interactive authentication outside of registration.
        """

        # Attempt to delete this device.
        # Returns a 401 as per the spec
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            self.device_id,
            HTTPStatus.OK,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    def test_grandfathered_identifier(self) -> None:
        """Check behaviour without "identifier" dict

        Synapse used to require clients to submit a "user" field for m.login.password
        UIA - check that still works.
        """

        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )
        session = channel.json_body["session"]

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            self.device_id,
            HTTPStatus.OK,
            {
                "auth": {
                    "type": "m.login.password",
                    "user": self.user,
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    def test_can_change_body(self) -> None:
        """
        The client dict can be modified during the user interactive authentication session.

        Note that it is not spec compliant to modify the client dict during a
        user interactive authentication session, but many clients currently do.

        When Synapse is updated to be spec compliant, the call to re-use the
        session ID should be rejected.
        """
        # Create a second login.
        self.login("test", self.user_pass, "dev2")

        # Attempt to delete the first device.
        # Returns a 401 as per the spec
        channel = self.delete_devices(
            HTTPStatus.UNAUTHORIZED, {"devices": [self.device_id]}
        )

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow, but try to delete the
        # second device.
        self.delete_devices(
            HTTPStatus.OK,
            {
                "devices": ["dev2"],
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    def test_cannot_change_uri(self) -> None:
        """
        The initial requested URI cannot be modified during the user interactive authentication session.
        """
        # Create a second login.
        self.login("test", self.user_pass, "dev2")

        # Attempt to delete the first device.
        # Returns a 401 as per the spec
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow, but try to delete the
        # second device. This results in an error.
        #
        # This makes use of the fact that the device ID is embedded into the URL.
        self.delete_device(
            self.user_tok,
            "dev2",
            HTTPStatus.FORBIDDEN,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    @unittest.override_config({"ui_auth": {"session_timeout": "5s"}})
    def test_can_reuse_session(self) -> None:
        """
        The session can be reused if configured.

        Compare to test_cannot_change_uri.
        """
        # Create a second and third login.
        self.login("test", self.user_pass, "dev2")
        self.login("test", self.user_pass, "dev3")

        # Attempt to delete a device. This works since the user just logged in.
        self.delete_device(self.user_tok, "dev2", HTTPStatus.OK)

        # Move the clock forward past the validation timeout.
        self.reactor.advance(6)

        # Deleting another devices throws the user into UI auth.
        channel = self.delete_device(self.user_tok, "dev3", HTTPStatus.UNAUTHORIZED)

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            "dev3",
            HTTPStatus.OK,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

        # Make another request, but try to delete the first device. This works
        # due to re-using the previous session.
        #
        # Note that *no auth* information is provided, not even a session iD!
        self.delete_device(self.user_tok, self.device_id, HTTPStatus.OK)

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_ui_auth_via_sso(self) -> None:
        """Test a successful UI Auth flow via SSO

        This includes:
          * hitting the UIA SSO redirect endpoint
          * checking it serves a confirmation page which links to the OIDC provider
          * calling back to the synapse oidc callback
          * checking that the original operation succeeds
        """

        # log the user in
        remote_user_id = UserID.from_string(self.user).localpart
        login_resp = self.helper.login_via_oidc(remote_user_id)
        self.assertEqual(login_resp["user_id"], self.user)

        # initiate a UI Auth process by attempting to delete the device
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        # check that SSO is offered
        flows = channel.json_body["flows"]
        self.assertIn({"stages": ["m.login.sso"]}, flows)

        # run the UIA-via-SSO flow
        session_id = channel.json_body["session"]
        channel = self.helper.auth_via_oidc(
            {"sub": remote_user_id}, ui_auth_session_id=session_id
        )

        # that should serve a confirmation page
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)

        # and now the delete request should succeed.
        self.delete_device(
            self.user_tok,
            self.device_id,
            HTTPStatus.OK,
            body={"auth": {"session": session_id}},
        )

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_does_not_offer_password_for_sso_user(self) -> None:
        login_resp = self.helper.login_via_oidc("username")
        user_tok = login_resp["access_token"]
        device_id = login_resp["device_id"]

        # now call the device deletion API: we should get the option to auth with SSO
        # and not password.
        channel = self.delete_device(user_tok, device_id, HTTPStatus.UNAUTHORIZED)

        flows = channel.json_body["flows"]
        self.assertEqual(flows, [{"stages": ["m.login.sso"]}])

    def test_does_not_offer_sso_for_password_user(self) -> None:
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        flows = channel.json_body["flows"]
        self.assertEqual(flows, [{"stages": ["m.login.password"]}])

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_offers_both_flows_for_upgraded_user(self) -> None:
        """A user that had a password and then logged in with SSO should get both flows"""
        login_resp = self.helper.login_via_oidc(UserID.from_string(self.user).localpart)
        self.assertEqual(login_resp["user_id"], self.user)

        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        flows = channel.json_body["flows"]
        # we have no particular expectations of ordering here
        self.assertIn({"stages": ["m.login.password"]}, flows)
        self.assertIn({"stages": ["m.login.sso"]}, flows)
        self.assertEqual(len(flows), 2)

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_ui_auth_fails_for_incorrect_sso_user(self) -> None:
        """If the user tries to authenticate with the wrong SSO user, they get an error"""
        # log the user in
        login_resp = self.helper.login_via_oidc(UserID.from_string(self.user).localpart)
        self.assertEqual(login_resp["user_id"], self.user)

        # start a UI Auth flow by attempting to delete a device
        channel = self.delete_device(
            self.user_tok, self.device_id, HTTPStatus.UNAUTHORIZED
        )

        flows = channel.json_body["flows"]
        self.assertIn({"stages": ["m.login.sso"]}, flows)
        session_id = channel.json_body["session"]

        # do the OIDC auth, but auth as the wrong user
        channel = self.helper.auth_via_oidc(
            {"sub": "wrong_user"}, ui_auth_session_id=session_id
        )

        # that should return a failure message
        self.assertSubstring("We were unable to validate", channel.text_body)

        # ... and the delete op should now fail with a 403
        self.delete_device(
            self.user_tok,
            self.device_id,
            HTTPStatus.FORBIDDEN,
            body={"auth": {"session": session_id}},
        )

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config(
        {
            "oidc_config": TEST_OIDC_CONFIG,
            "experimental_features": {
                "msc3866": {
                    "enabled": True,
                    "require_approval_for_new_accounts": True,
                }
            },
        }
    )
    def test_sso_not_approved(self) -> None:
        """Tests that if we register a user via SSO while requiring approval for new
        accounts, we still raise the correct error before logging the user in.
        """
        login_resp = self.helper.login_via_oidc("username", expected_status=403)

        self.assertEqual(login_resp["errcode"], Codes.USER_AWAITING_APPROVAL)
        self.assertEqual(
            ApprovalNoticeMedium.NONE, login_resp["approval_notice_medium"]
        )

        # Check that we didn't register a device for the user during the login attempt.
        devices = self.get_success(
            self.hs.get_datastores().main.get_devices_by_user("@username:test")
        )

        self.assertEqual(len(devices), 0)


class RefreshAuthTests(unittest.HomeserverTestCase):
    servlets = [
        auth.register_servlets,
        account.register_servlets,
        login.register_servlets,
        logout.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        register.register_servlets,
    ]
    hijack_auth = False

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.user_pass = "pass"
        self.user = self.register_user("test", self.user_pass)

    def use_refresh_token(self, refresh_token: str) -> FakeChannel:
        """
        Helper that makes a request to use a refresh token.
        """
        return self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": refresh_token},
        )

    def is_access_token_valid(self, access_token: str) -> bool:
        """
        Checks whether an access token is valid, returning whether it is or not.
        """
        code = self.make_request(
            "GET", "/_matrix/client/v3/account/whoami", access_token=access_token
        ).code

        # Either 200 or 401 is what we get back; anything else is a bug.
        assert code in {HTTPStatus.OK, HTTPStatus.UNAUTHORIZED}

        return code == HTTPStatus.OK

    def test_login_issue_refresh_token(self) -> None:
        """
        A login response should include a refresh_token only if asked.
        """
        # Test login
        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
        }

        login_without_refresh = self.make_request(
            "POST", "/_matrix/client/r0/login", body
        )
        self.assertEqual(
            login_without_refresh.code, HTTPStatus.OK, login_without_refresh.result
        )
        self.assertNotIn("refresh_token", login_without_refresh.json_body)

        login_with_refresh = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            {"refresh_token": True, **body},
        )
        self.assertEqual(
            login_with_refresh.code, HTTPStatus.OK, login_with_refresh.result
        )
        self.assertIn("refresh_token", login_with_refresh.json_body)
        self.assertIn("expires_in_ms", login_with_refresh.json_body)

    def test_register_issue_refresh_token(self) -> None:
        """
        A register response should include a refresh_token only if asked.
        """
        register_without_refresh = self.make_request(
            "POST",
            "/_matrix/client/r0/register",
            {
                "username": "test2",
                "password": self.user_pass,
                "auth": {"type": LoginType.DUMMY},
            },
        )
        self.assertEqual(
            register_without_refresh.code,
            HTTPStatus.OK,
            register_without_refresh.result,
        )
        self.assertNotIn("refresh_token", register_without_refresh.json_body)

        register_with_refresh = self.make_request(
            "POST",
            "/_matrix/client/r0/register",
            {
                "username": "test3",
                "password": self.user_pass,
                "auth": {"type": LoginType.DUMMY},
                "refresh_token": True,
            },
        )
        self.assertEqual(
            register_with_refresh.code, HTTPStatus.OK, register_with_refresh.result
        )
        self.assertIn("refresh_token", register_with_refresh.json_body)
        self.assertIn("expires_in_ms", register_with_refresh.json_body)

    def test_token_refresh(self) -> None:
        """
        A refresh token can be used to issue a new access token.
        """
        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)

        refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": login_response.json_body["refresh_token"]},
        )
        self.assertEqual(refresh_response.code, HTTPStatus.OK, refresh_response.result)
        self.assertIn("access_token", refresh_response.json_body)
        self.assertIn("refresh_token", refresh_response.json_body)
        self.assertIn("expires_in_ms", refresh_response.json_body)

        # The access and refresh tokens should be different from the original ones after refresh
        self.assertNotEqual(
            login_response.json_body["access_token"],
            refresh_response.json_body["access_token"],
        )
        self.assertNotEqual(
            login_response.json_body["refresh_token"],
            refresh_response.json_body["refresh_token"],
        )

    @override_config({"refreshable_access_token_lifetime": "1m"})
    def test_refreshable_access_token_expiration(self) -> None:
        """
        The access token should have some time as specified in the config.
        """
        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)
        self.assertApproximates(
            login_response.json_body["expires_in_ms"], 60 * 1000, 100
        )

        refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": login_response.json_body["refresh_token"]},
        )
        self.assertEqual(refresh_response.code, HTTPStatus.OK, refresh_response.result)
        self.assertApproximates(
            refresh_response.json_body["expires_in_ms"], 60 * 1000, 100
        )
        access_token = refresh_response.json_body["access_token"]

        # Advance 59 seconds in the future (just shy of 1 minute, the time of expiry)
        self.reactor.advance(59.0)
        # Check that our token is valid
        self.assertEqual(
            self.make_request(
                "GET", "/_matrix/client/v3/account/whoami", access_token=access_token
            ).code,
            HTTPStatus.OK,
        )

        # Advance 2 more seconds (just past the time of expiry)
        self.reactor.advance(2.0)
        # Check that our token is invalid
        self.assertEqual(
            self.make_request(
                "GET", "/_matrix/client/v3/account/whoami", access_token=access_token
            ).code,
            HTTPStatus.UNAUTHORIZED,
        )

    @override_config(
        {
            "refreshable_access_token_lifetime": "1m",
            "nonrefreshable_access_token_lifetime": "10m",
        }
    )
    def test_different_expiry_for_refreshable_and_nonrefreshable_access_tokens(
        self,
    ) -> None:
        """
        Tests that the expiry times for refreshable and non-refreshable access
        tokens can be different.
        """
        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
        }
        login_response1 = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            {"refresh_token": True, **body},
        )
        self.assertEqual(login_response1.code, HTTPStatus.OK, login_response1.result)
        self.assertApproximates(
            login_response1.json_body["expires_in_ms"], 60 * 1000, 100
        )
        refreshable_access_token = login_response1.json_body["access_token"]

        login_response2 = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response2.code, HTTPStatus.OK, login_response2.result)
        nonrefreshable_access_token = login_response2.json_body["access_token"]

        # Advance 59 seconds in the future (just shy of 1 minute, the time of expiry)
        self.reactor.advance(59.0)

        # Both tokens should still be valid.
        self.assertTrue(self.is_access_token_valid(refreshable_access_token))
        self.assertTrue(self.is_access_token_valid(nonrefreshable_access_token))

        # Advance to 61 s (just past 1 minute, the time of expiry)
        self.reactor.advance(2.0)

        # Only the non-refreshable token is still valid.
        self.assertFalse(self.is_access_token_valid(refreshable_access_token))
        self.assertTrue(self.is_access_token_valid(nonrefreshable_access_token))

        # Advance to 599 s (just shy of 10 minutes, the time of expiry)
        self.reactor.advance(599.0 - 61.0)

        # It's still the case that only the non-refreshable token is still valid.
        self.assertFalse(self.is_access_token_valid(refreshable_access_token))
        self.assertTrue(self.is_access_token_valid(nonrefreshable_access_token))

        # Advance to 601 s (just past 10 minutes, the time of expiry)
        self.reactor.advance(2.0)

        # Now neither token is valid.
        self.assertFalse(self.is_access_token_valid(refreshable_access_token))
        self.assertFalse(self.is_access_token_valid(nonrefreshable_access_token))

    @override_config(
        {"refreshable_access_token_lifetime": "1m", "refresh_token_lifetime": "2m"}
    )
    def test_refresh_token_expiry(self) -> None:
        """
        The refresh token can be configured to have a limited lifetime.
        When that lifetime has ended, the refresh token can no longer be used to
        refresh the session.
        """

        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)
        refresh_token1 = login_response.json_body["refresh_token"]

        # Advance 119 seconds in the future (just shy of 2 minutes)
        self.reactor.advance(119.0)

        # Refresh our session. The refresh token should still JUST be valid right now.
        # By doing so, we get a new access token and a new refresh token.
        refresh_response = self.use_refresh_token(refresh_token1)
        self.assertEqual(refresh_response.code, HTTPStatus.OK, refresh_response.result)
        self.assertIn(
            "refresh_token",
            refresh_response.json_body,
            "No new refresh token returned after refresh.",
        )
        refresh_token2 = refresh_response.json_body["refresh_token"]

        # Advance 121 seconds in the future (just a bit more than 2 minutes)
        self.reactor.advance(121.0)

        # Try to refresh our session, but instead notice that the refresh token is
        # not valid (it just expired).
        refresh_response = self.use_refresh_token(refresh_token2)
        self.assertEqual(
            refresh_response.code, HTTPStatus.FORBIDDEN, refresh_response.result
        )

    @override_config(
        {
            "refreshable_access_token_lifetime": "2m",
            "refresh_token_lifetime": "2m",
            "session_lifetime": "3m",
        }
    )
    def test_ultimate_session_expiry(self) -> None:
        """
        The session can be configured to have an ultimate, limited lifetime.
        """

        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)
        refresh_token = login_response.json_body["refresh_token"]

        # Advance shy of 2 minutes into the future
        self.reactor.advance(119.0)

        # Refresh our session. The refresh token should still be valid right now.
        refresh_response = self.use_refresh_token(refresh_token)
        self.assertEqual(refresh_response.code, HTTPStatus.OK, refresh_response.result)
        self.assertIn(
            "refresh_token",
            refresh_response.json_body,
            "No new refresh token returned after refresh.",
        )
        # Notice that our access token lifetime has been diminished to match the
        # session lifetime.
        # 3 minutes - 119 seconds = 61 seconds.
        self.assertEqual(refresh_response.json_body["expires_in_ms"], 61_000)
        refresh_token = refresh_response.json_body["refresh_token"]

        # Advance 61 seconds into the future. Our session should have expired
        # now, because we've had our 3 minutes.
        self.reactor.advance(61.0)

        # Try to issue a new, refreshed, access token.
        # This should fail because the refresh token's lifetime has also been
        # diminished as our session expired.
        refresh_response = self.use_refresh_token(refresh_token)
        self.assertEqual(
            refresh_response.code, HTTPStatus.FORBIDDEN, refresh_response.result
        )

    def test_refresh_token_invalidation(self) -> None:
        """Refresh tokens are invalidated after first use of the next token.

        A refresh token is considered invalid if:
            - it was already used at least once
            - and either
                - the next access token was used
                - the next refresh token was used

        The chain of tokens goes like this:

            login -|-> first_refresh -> third_refresh (fails)
                   |-> second_refresh -> fifth_refresh
                   |-> fourth_refresh (fails)
        """

        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/r0/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)

        # This first refresh should work properly
        first_refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": login_response.json_body["refresh_token"]},
        )
        self.assertEqual(
            first_refresh_response.code, HTTPStatus.OK, first_refresh_response.result
        )

        # This one as well, since the token in the first one was never used
        second_refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": login_response.json_body["refresh_token"]},
        )
        self.assertEqual(
            second_refresh_response.code, HTTPStatus.OK, second_refresh_response.result
        )

        # This one should not, since the token from the first refresh is not valid anymore
        third_refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": first_refresh_response.json_body["refresh_token"]},
        )
        self.assertEqual(
            third_refresh_response.code,
            HTTPStatus.UNAUTHORIZED,
            third_refresh_response.result,
        )

        # The associated access token should also be invalid
        whoami_response = self.make_request(
            "GET",
            "/_matrix/client/r0/account/whoami",
            access_token=first_refresh_response.json_body["access_token"],
        )
        self.assertEqual(
            whoami_response.code, HTTPStatus.UNAUTHORIZED, whoami_response.result
        )

        # But all other tokens should work (they will expire after some time)
        for access_token in [
            second_refresh_response.json_body["access_token"],
            login_response.json_body["access_token"],
        ]:
            whoami_response = self.make_request(
                "GET", "/_matrix/client/r0/account/whoami", access_token=access_token
            )
            self.assertEqual(
                whoami_response.code, HTTPStatus.OK, whoami_response.result
            )

        # Now that the access token from the last valid refresh was used once, refreshing with the N-1 token should fail
        fourth_refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": login_response.json_body["refresh_token"]},
        )
        self.assertEqual(
            fourth_refresh_response.code,
            HTTPStatus.FORBIDDEN,
            fourth_refresh_response.result,
        )

        # But refreshing from the last valid refresh token still works
        fifth_refresh_response = self.make_request(
            "POST",
            "/_matrix/client/v1/refresh",
            {"refresh_token": second_refresh_response.json_body["refresh_token"]},
        )
        self.assertEqual(
            fifth_refresh_response.code, HTTPStatus.OK, fifth_refresh_response.result
        )

    def test_many_token_refresh(self) -> None:
        """
        If a refresh is performed many times during a session, there shouldn't be
        extra 'cruft' built up over time.

        This test was written specifically to troubleshoot a case where logout
        was very slow if a lot of refreshes had been performed for the session.
        """

        def _refresh(refresh_token: str) -> Tuple[str, str]:
            """
            Performs one refresh, returning the next refresh token and access token.
            """
            refresh_response = self.use_refresh_token(refresh_token)
            self.assertEqual(
                refresh_response.code, HTTPStatus.OK, refresh_response.result
            )
            return (
                refresh_response.json_body["refresh_token"],
                refresh_response.json_body["access_token"],
            )

        def _table_length(table_name: str) -> int:
            """
            Helper to get the size of a table, in rows.
            For testing only; trivially vulnerable to SQL injection.
            """

            def _txn(txn: LoggingTransaction) -> int:
                txn.execute(f"SELECT COUNT(1) FROM {table_name}")
                row = txn.fetchone()
                # Query is infallible
                assert row is not None
                return row[0]

            return self.get_success(
                self.hs.get_datastores().main.db_pool.runInteraction(
                    "_table_length", _txn
                )
            )

        # Before we log in, there are no access tokens.
        self.assertEqual(_table_length("access_tokens"), 0)
        self.assertEqual(_table_length("refresh_tokens"), 0)

        body = {
            "type": "m.login.password",
            "user": "test",
            "password": self.user_pass,
            "refresh_token": True,
        }
        login_response = self.make_request(
            "POST",
            "/_matrix/client/v3/login",
            body,
        )
        self.assertEqual(login_response.code, HTTPStatus.OK, login_response.result)

        access_token = login_response.json_body["access_token"]
        refresh_token = login_response.json_body["refresh_token"]

        # Now that we have logged in, there should be one access token and one
        # refresh token
        self.assertEqual(_table_length("access_tokens"), 1)
        self.assertEqual(_table_length("refresh_tokens"), 1)

        for _ in range(5):
            refresh_token, access_token = _refresh(refresh_token)

        # After 5 sequential refreshes, there should only be the latest two
        # refresh/access token pairs.
        # (The last one is preserved because it's in use!
        # The one before that is preserved because it can still be used to
        # replace the last token pair, in case of e.g. a network interruption.)
        self.assertEqual(_table_length("access_tokens"), 2)
        self.assertEqual(_table_length("refresh_tokens"), 2)

        logout_response = self.make_request(
            "POST", "/_matrix/client/v3/logout", {}, access_token=access_token
        )
        self.assertEqual(logout_response.code, HTTPStatus.OK, logout_response.result)

        # Now that we have logged in, there should be no access token
        # and no refresh token
        self.assertEqual(_table_length("access_tokens"), 0)
        self.assertEqual(_table_length("refresh_tokens"), 0)
