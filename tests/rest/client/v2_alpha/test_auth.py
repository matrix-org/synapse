# -*- coding: utf-8 -*-
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
from typing import Union

from twisted.internet.defer import succeed

import synapse.rest.admin
from synapse.api.constants import LoginType
from synapse.handlers.ui_auth.checkers import UserInteractiveAuthChecker
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import auth, devices, register
from synapse.rest.synapse.client import build_synapse_client_resource_tree
from synapse.types import JsonDict, UserID

from tests import unittest
from tests.handlers.test_oidc import HAS_OIDC
from tests.rest.client.v1.utils import TEST_OIDC_CONFIG
from tests.server import FakeChannel
from tests.unittest import override_config, skip_unless


class DummyRecaptchaChecker(UserInteractiveAuthChecker):
    def __init__(self, hs):
        super().__init__(hs)
        self.recaptcha_attempts = []

    def check_auth(self, authdict, clientip):
        self.recaptcha_attempts.append((authdict, clientip))
        return succeed(True)


class FallbackAuthTests(unittest.HomeserverTestCase):

    servlets = [
        auth.register_servlets,
        register.register_servlets,
    ]
    hijack_auth = False

    def make_homeserver(self, reactor, clock):

        config = self.default_config()

        config["enable_registration_captcha"] = True
        config["recaptcha_public_key"] = "brokencake"
        config["registrations_require_3pid"] = []

        hs = self.setup_test_homeserver(config=config)
        return hs

    def prepare(self, reactor, clock, hs):
        self.recaptcha_checker = DummyRecaptchaChecker(hs)
        auth_handler = hs.get_auth_handler()
        auth_handler.checkers[LoginType.RECAPTCHA] = self.recaptcha_checker

    def register(self, expected_response: int, body: JsonDict) -> FakeChannel:
        """Make a register request."""
        channel = self.make_request("POST", "register", body)

        self.assertEqual(channel.code, expected_response)
        return channel

    def recaptcha(
        self, session: str, expected_post_response: int, post_session: str = None
    ) -> None:
        """Get and respond to a fallback recaptcha. Returns the second request."""
        if post_session is None:
            post_session = session

        channel = self.make_request(
            "GET", "auth/m.login.recaptcha/fallback/web?session=" + session
        )
        self.assertEqual(channel.code, 200)

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

    def test_fallback_captcha(self):
        """Ensure that fallback auth via a captcha works."""
        # Returns a 401 as per the spec
        channel = self.register(
            401,
            {"username": "user", "type": "m.login.password", "password": "bar"},
        )

        # Grab the session
        session = channel.json_body["session"]
        # Assert our configured public key is being given
        self.assertEqual(
            channel.json_body["params"]["m.login.recaptcha"]["public_key"], "brokencake"
        )

        # Complete the recaptcha step.
        self.recaptcha(session, 200)

        # also complete the dummy auth
        self.register(200, {"auth": {"session": session, "type": "m.login.dummy"}})

        # Now we should have fulfilled a complete auth flow, including
        # the recaptcha fallback step, we can then send a
        # request to the register API with the session in the authdict.
        channel = self.register(200, {"auth": {"session": session}})

        # We're given a registered user.
        self.assertEqual(channel.json_body["user_id"], "@user:test")

    def test_complete_operation_unknown_session(self):
        """
        Attempting to mark an invalid session as complete should error.
        """
        # Make the initial request to register. (Later on a different password
        # will be used.)
        # Returns a 401 as per the spec
        channel = self.register(
            401, {"username": "user", "type": "m.login.password", "password": "bar"}
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

    def default_config(self):
        config = super().default_config()
        config["public_baseurl"] = "https://synapse.test"

        if HAS_OIDC:
            # we enable OIDC as a way of testing SSO flows
            oidc_config = {}
            oidc_config.update(TEST_OIDC_CONFIG)
            oidc_config["allow_existing_users"] = True
            config["oidc_config"] = oidc_config

        return config

    def create_resource_dict(self):
        resource_dict = super().create_resource_dict()
        resource_dict.update(build_synapse_client_resource_tree(self.hs))
        return resource_dict

    def prepare(self, reactor, clock, hs):
        self.user_pass = "pass"
        self.user = self.register_user("test", self.user_pass)
        self.device_id = "dev1"
        self.user_tok = self.login("test", self.user_pass, self.device_id)

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

    def test_ui_auth(self):
        """
        Test user interactive authentication outside of registration.
        """
        # Attempt to delete this device.
        # Returns a 401 as per the spec
        channel = self.delete_device(self.user_tok, self.device_id, 401)

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            self.device_id,
            200,
            {
                "auth": {
                    "type": "m.login.password",
                    "identifier": {"type": "m.id.user", "user": self.user},
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    def test_grandfathered_identifier(self):
        """Check behaviour without "identifier" dict

        Synapse used to require clients to submit a "user" field for m.login.password
        UIA - check that still works.
        """

        channel = self.delete_device(self.user_tok, self.device_id, 401)
        session = channel.json_body["session"]

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            self.device_id,
            200,
            {
                "auth": {
                    "type": "m.login.password",
                    "user": self.user,
                    "password": self.user_pass,
                    "session": session,
                },
            },
        )

    def test_can_change_body(self):
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
        channel = self.delete_devices(401, {"devices": [self.device_id]})

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow, but try to delete the
        # second device.
        self.delete_devices(
            200,
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

    def test_cannot_change_uri(self):
        """
        The initial requested URI cannot be modified during the user interactive authentication session.
        """
        # Create a second login.
        self.login("test", self.user_pass, "dev2")

        # Attempt to delete the first device.
        # Returns a 401 as per the spec
        channel = self.delete_device(self.user_tok, self.device_id, 401)

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
            403,
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
    def test_can_reuse_session(self):
        """
        The session can be reused if configured.

        Compare to test_cannot_change_uri.
        """
        # Create a second and third login.
        self.login("test", self.user_pass, "dev2")
        self.login("test", self.user_pass, "dev3")

        # Attempt to delete a device. This works since the user just logged in.
        self.delete_device(self.user_tok, "dev2", 200)

        # Move the clock forward past the validation timeout.
        self.reactor.advance(6)

        # Deleting another devices throws the user into UI auth.
        channel = self.delete_device(self.user_tok, "dev3", 401)

        # Grab the session
        session = channel.json_body["session"]
        # Ensure that flows are what is expected.
        self.assertIn({"stages": ["m.login.password"]}, channel.json_body["flows"])

        # Make another request providing the UI auth flow.
        self.delete_device(
            self.user_tok,
            "dev3",
            200,
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
        self.delete_device(self.user_tok, self.device_id, 200)

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_ui_auth_via_sso(self):
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
        channel = self.delete_device(self.user_tok, self.device_id, 401)

        # check that SSO is offered
        flows = channel.json_body["flows"]
        self.assertIn({"stages": ["m.login.sso"]}, flows)

        # run the UIA-via-SSO flow
        session_id = channel.json_body["session"]
        channel = self.helper.auth_via_oidc(
            {"sub": remote_user_id}, ui_auth_session_id=session_id
        )

        # that should serve a confirmation page
        self.assertEqual(channel.code, 200, channel.result)

        # and now the delete request should succeed.
        self.delete_device(
            self.user_tok,
            self.device_id,
            200,
            body={"auth": {"session": session_id}},
        )

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_does_not_offer_password_for_sso_user(self):
        login_resp = self.helper.login_via_oidc("username")
        user_tok = login_resp["access_token"]
        device_id = login_resp["device_id"]

        # now call the device deletion API: we should get the option to auth with SSO
        # and not password.
        channel = self.delete_device(user_tok, device_id, 401)

        flows = channel.json_body["flows"]
        self.assertEqual(flows, [{"stages": ["m.login.sso"]}])

    def test_does_not_offer_sso_for_password_user(self):
        channel = self.delete_device(self.user_tok, self.device_id, 401)

        flows = channel.json_body["flows"]
        self.assertEqual(flows, [{"stages": ["m.login.password"]}])

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_offers_both_flows_for_upgraded_user(self):
        """A user that had a password and then logged in with SSO should get both flows"""
        login_resp = self.helper.login_via_oidc(UserID.from_string(self.user).localpart)
        self.assertEqual(login_resp["user_id"], self.user)

        channel = self.delete_device(self.user_tok, self.device_id, 401)

        flows = channel.json_body["flows"]
        # we have no particular expectations of ordering here
        self.assertIn({"stages": ["m.login.password"]}, flows)
        self.assertIn({"stages": ["m.login.sso"]}, flows)
        self.assertEqual(len(flows), 2)

    @skip_unless(HAS_OIDC, "requires OIDC")
    @override_config({"oidc_config": TEST_OIDC_CONFIG})
    def test_ui_auth_fails_for_incorrect_sso_user(self):
        """If the user tries to authenticate with the wrong SSO user, they get an error"""
        # log the user in
        login_resp = self.helper.login_via_oidc(UserID.from_string(self.user).localpart)
        self.assertEqual(login_resp["user_id"], self.user)

        # start a UI Auth flow by attempting to delete a device
        channel = self.delete_device(self.user_tok, self.device_id, 401)

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
            self.user_tok, self.device_id, 403, body={"auth": {"session": session_id}}
        )
