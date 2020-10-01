# -*- coding: utf-8 -*-
# Copyright 2015-2016 OpenMarket Ltd
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
import json
import os
import re
from email.parser import Parser
from typing import Optional
from urllib.parse import urlencode

import pkg_resources

import synapse.rest.admin
from synapse.api.constants import LoginType, Membership
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import account, register
from synapse.rest.synapse.client.password_reset import PasswordResetSubmitTokenResource

from tests import unittest
from tests.unittest import override_config


class PasswordResetTestCase(unittest.HomeserverTestCase):

    servlets = [
        account.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        register.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()

        # Email config.
        self.email_attempts = []

        async def sendmail(smtphost, from_addr, to_addrs, msg, **kwargs):
            self.email_attempts.append(msg)
            return

        config["email"] = {
            "enable_notifs": False,
            "template_dir": os.path.abspath(
                pkg_resources.resource_filename("synapse", "res/templates")
            ),
            "smtp_host": "127.0.0.1",
            "smtp_port": 20,
            "require_transport_security": False,
            "smtp_user": None,
            "smtp_pass": None,
            "notif_from": "test@example.com",
        }
        config["public_baseurl"] = "https://example.com"

        hs = self.setup_test_homeserver(config=config, sendmail=sendmail)
        return hs

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.submit_token_resource = PasswordResetSubmitTokenResource(hs)

    def test_basic_password_reset(self):
        """Test basic password reset flow
        """
        old_password = "monkey"
        new_password = "kangeroo"

        user_id = self.register_user("kermit", old_password)
        self.login("kermit", old_password)

        email = "test@example.com"

        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email,
                validated_at=0,
                added_at=0,
            )
        )

        client_secret = "foobar"
        session_id = self._request_token(email, client_secret)

        self.assertEquals(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        self._reset_password(new_password, session_id, client_secret)

        # Assert we can log in with the new password
        self.login("kermit", new_password)

        # Assert we can't log in with the old password
        self.attempt_wrong_password_login("kermit", old_password)

    def test_basic_password_reset_canonicalise_email(self):
        """Test basic password reset flow
        Request password reset with different spelling
        """
        old_password = "monkey"
        new_password = "kangeroo"

        user_id = self.register_user("kermit", old_password)
        self.login("kermit", old_password)

        email_profile = "test@example.com"
        email_passwort_reset = "TEST@EXAMPLE.COM"

        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email_profile,
                validated_at=0,
                added_at=0,
            )
        )

        client_secret = "foobar"
        session_id = self._request_token(email_passwort_reset, client_secret)

        self.assertEquals(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        self._reset_password(new_password, session_id, client_secret)

        # Assert we can log in with the new password
        self.login("kermit", new_password)

        # Assert we can't log in with the old password
        self.attempt_wrong_password_login("kermit", old_password)

    def test_cant_reset_password_without_clicking_link(self):
        """Test that we do actually need to click the link in the email
        """
        old_password = "monkey"
        new_password = "kangeroo"

        user_id = self.register_user("kermit", old_password)
        self.login("kermit", old_password)

        email = "test@example.com"

        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email,
                validated_at=0,
                added_at=0,
            )
        )

        client_secret = "foobar"
        session_id = self._request_token(email, client_secret)

        self.assertEquals(len(self.email_attempts), 1)

        # Attempt to reset password without clicking the link
        self._reset_password(new_password, session_id, client_secret, expected_code=401)

        # Assert we can log in with the old password
        self.login("kermit", old_password)

        # Assert we can't log in with the new password
        self.attempt_wrong_password_login("kermit", new_password)

    def test_no_valid_token(self):
        """Test that we do actually need to request a token and can't just
        make a session up.
        """
        old_password = "monkey"
        new_password = "kangeroo"

        user_id = self.register_user("kermit", old_password)
        self.login("kermit", old_password)

        email = "test@example.com"

        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email,
                validated_at=0,
                added_at=0,
            )
        )

        client_secret = "foobar"
        session_id = "weasle"

        # Attempt to reset password without even requesting an email
        self._reset_password(new_password, session_id, client_secret, expected_code=401)

        # Assert we can log in with the old password
        self.login("kermit", old_password)

        # Assert we can't log in with the new password
        self.attempt_wrong_password_login("kermit", new_password)

    @unittest.override_config({"request_token_inhibit_3pid_errors": True})
    def test_password_reset_bad_email_inhibit_error(self):
        """Test that triggering a password reset with an email address that isn't bound
        to an account doesn't leak the lack of binding for that address if configured
        that way.
        """
        self.register_user("kermit", "monkey")
        self.login("kermit", "monkey")

        email = "test@example.com"

        client_secret = "foobar"
        session_id = self._request_token(email, client_secret)

        self.assertIsNotNone(session_id)

    def _request_token(self, email, client_secret):
        request, channel = self.make_request(
            "POST",
            b"account/password/email/requestToken",
            {"client_secret": client_secret, "email": email, "send_attempt": 1},
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        return channel.json_body["sid"]

    def _validate_token(self, link):
        # Remove the host
        path = link.replace("https://example.com", "")

        # Load the password reset confirmation page
        request, channel = self.make_request("GET", path, shorthand=False)
        request.render(self.submit_token_resource)
        self.pump()
        self.assertEquals(200, channel.code, channel.result)

        # Now POST to the same endpoint, mimicking the same behaviour as clicking the
        # password reset confirm button

        # Send arguments as url-encoded form data, matching the template's behaviour
        form_args = []
        for key, value_list in request.args.items():
            for value in value_list:
                arg = (key, value)
                form_args.append(arg)

        # Confirm the password reset
        request, channel = self.make_request(
            "POST",
            path,
            content=urlencode(form_args).encode("utf8"),
            shorthand=False,
            content_is_form=True,
        )
        request.render(self.submit_token_resource)
        self.pump()
        self.assertEquals(200, channel.code, channel.result)

    def _get_link_from_email(self):
        assert self.email_attempts, "No emails have been sent"

        raw_msg = self.email_attempts[-1].decode("UTF-8")
        mail = Parser().parsestr(raw_msg)

        text = None
        for part in mail.walk():
            if part.get_content_type() == "text/plain":
                text = part.get_payload(decode=True).decode("UTF-8")
                break

        if not text:
            self.fail("Could not find text portion of email to parse")

        match = re.search(r"https://example.com\S+", text)
        assert match, "Could not find link in email"

        return match.group(0)

    def _reset_password(
        self, new_password, session_id, client_secret, expected_code=200
    ):
        request, channel = self.make_request(
            "POST",
            b"account/password",
            {
                "new_password": new_password,
                "auth": {
                    "type": LoginType.EMAIL_IDENTITY,
                    "threepid_creds": {
                        "client_secret": client_secret,
                        "sid": session_id,
                    },
                },
            },
        )
        self.render(request)
        self.assertEquals(expected_code, channel.code, channel.result)


class DeactivateTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        self.hs = self.setup_test_homeserver()
        return self.hs

    def test_deactivate_account(self):
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        self.deactivate(user_id, tok)

        store = self.hs.get_datastore()

        # Check that the user has been marked as deactivated.
        self.assertTrue(self.get_success(store.get_user_deactivated_status(user_id)))

        # Check that this access token has been invalidated.
        request, channel = self.make_request("GET", "account/whoami")
        self.render(request)
        self.assertEqual(request.code, 401)

    @unittest.INFO
    def test_pending_invites(self):
        """Tests that deactivating a user rejects every pending invite for them."""
        store = self.hs.get_datastore()

        inviter_id = self.register_user("inviter", "test")
        inviter_tok = self.login("inviter", "test")

        invitee_id = self.register_user("invitee", "test")
        invitee_tok = self.login("invitee", "test")

        # Make @inviter:test invite @invitee:test in a new room.
        room_id = self.helper.create_room_as(inviter_id, tok=inviter_tok)
        self.helper.invite(
            room=room_id, src=inviter_id, targ=invitee_id, tok=inviter_tok
        )

        # Make sure the invite is here.
        pending_invites = self.get_success(
            store.get_invited_rooms_for_local_user(invitee_id)
        )
        self.assertEqual(len(pending_invites), 1, pending_invites)
        self.assertEqual(pending_invites[0].room_id, room_id, pending_invites)

        # Deactivate @invitee:test.
        self.deactivate(invitee_id, invitee_tok)

        # Check that the invite isn't there anymore.
        pending_invites = self.get_success(
            store.get_invited_rooms_for_local_user(invitee_id)
        )
        self.assertEqual(len(pending_invites), 0, pending_invites)

        # Check that the membership of @invitee:test in the room is now "leave".
        memberships = self.get_success(
            store.get_rooms_for_local_user_where_membership_is(
                invitee_id, [Membership.LEAVE]
            )
        )
        self.assertEqual(len(memberships), 1, memberships)
        self.assertEqual(memberships[0].room_id, room_id, memberships)

    def deactivate(self, user_id, tok):
        request_data = json.dumps(
            {
                "auth": {
                    "type": "m.login.password",
                    "user": user_id,
                    "password": "test",
                },
                "erase": False,
            }
        )
        request, channel = self.make_request(
            "POST", "account/deactivate", request_data, access_token=tok
        )
        self.render(request)
        self.assertEqual(request.code, 200)


class ThreepidEmailRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        account.register_servlets,
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()

        # Email config.
        self.email_attempts = []

        async def sendmail(smtphost, from_addr, to_addrs, msg, **kwargs):
            self.email_attempts.append(msg)

        config["email"] = {
            "enable_notifs": False,
            "template_dir": os.path.abspath(
                pkg_resources.resource_filename("synapse", "res/templates")
            ),
            "smtp_host": "127.0.0.1",
            "smtp_port": 20,
            "require_transport_security": False,
            "smtp_user": None,
            "smtp_pass": None,
            "notif_from": "test@example.com",
        }
        config["public_baseurl"] = "https://example.com"

        self.hs = self.setup_test_homeserver(config=config, sendmail=sendmail)
        return self.hs

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

        self.user_id = self.register_user("kermit", "test")
        self.user_id_tok = self.login("kermit", "test")
        self.email = "test@example.com"
        self.url_3pid = b"account/3pid"

    def test_add_valid_email(self):
        self.get_success(self._add_email(self.email, self.email))

    def test_add_valid_email_second_time(self):
        self.get_success(self._add_email(self.email, self.email))
        self.get_success(
            self._request_token_invalid_email(
                self.email,
                expected_errcode=Codes.THREEPID_IN_USE,
                expected_error="Email is already in use",
            )
        )

    def test_add_valid_email_second_time_canonicalise(self):
        self.get_success(self._add_email(self.email, self.email))
        self.get_success(
            self._request_token_invalid_email(
                "TEST@EXAMPLE.COM",
                expected_errcode=Codes.THREEPID_IN_USE,
                expected_error="Email is already in use",
            )
        )

    def test_add_email_no_at(self):
        self.get_success(
            self._request_token_invalid_email(
                "address-without-at.bar",
                expected_errcode=Codes.UNKNOWN,
                expected_error="Unable to parse email address",
            )
        )

    def test_add_email_two_at(self):
        self.get_success(
            self._request_token_invalid_email(
                "foo@foo@test.bar",
                expected_errcode=Codes.UNKNOWN,
                expected_error="Unable to parse email address",
            )
        )

    def test_add_email_bad_format(self):
        self.get_success(
            self._request_token_invalid_email(
                "user@bad.example.net@good.example.com",
                expected_errcode=Codes.UNKNOWN,
                expected_error="Unable to parse email address",
            )
        )

    def test_add_email_domain_to_lower(self):
        self.get_success(self._add_email("foo@TEST.BAR", "foo@test.bar"))

    def test_add_email_domain_with_umlaut(self):
        self.get_success(self._add_email("foo@Öumlaut.com", "foo@öumlaut.com"))

    def test_add_email_address_casefold(self):
        self.get_success(self._add_email("Strauß@Example.com", "strauss@example.com"))

    def test_address_trim(self):
        self.get_success(self._add_email(" foo@test.bar ", "foo@test.bar"))

    def test_add_email_if_disabled(self):
        """Test adding email to profile when doing so is disallowed
        """
        self.hs.config.enable_3pid_changes = False

        client_secret = "foobar"
        session_id = self._request_token(self.email, client_secret)

        self.assertEquals(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        request, channel = self.make_request(
            "POST",
            b"/_matrix/client/unstable/account/3pid/add",
            {
                "client_secret": client_secret,
                "sid": session_id,
                "auth": {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": "test",
                },
            },
            access_token=self.user_id_tok,
        )
        self.render(request)
        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_delete_email(self):
        """Test deleting an email from profile
        """
        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=self.user_id,
                medium="email",
                address=self.email,
                validated_at=0,
                added_at=0,
            )
        )

        request, channel = self.make_request(
            "POST",
            b"account/3pid/delete",
            {"medium": "email", "address": self.email},
            access_token=self.user_id_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_delete_email_if_disabled(self):
        """Test deleting an email from profile when disallowed
        """
        self.hs.config.enable_3pid_changes = False

        # Add a threepid
        self.get_success(
            self.store.user_add_threepid(
                user_id=self.user_id,
                medium="email",
                address=self.email,
                validated_at=0,
                added_at=0,
            )
        )

        request, channel = self.make_request(
            "POST",
            b"account/3pid/delete",
            {"medium": "email", "address": self.email},
            access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual(self.email, channel.json_body["threepids"][0]["address"])

    def test_cant_add_email_without_clicking_link(self):
        """Test that we do actually need to click the link in the email
        """
        client_secret = "foobar"
        session_id = self._request_token(self.email, client_secret)

        self.assertEquals(len(self.email_attempts), 1)

        # Attempt to add email without clicking the link
        request, channel = self.make_request(
            "POST",
            b"/_matrix/client/unstable/account/3pid/add",
            {
                "client_secret": client_secret,
                "sid": session_id,
                "auth": {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": "test",
                },
            },
            access_token=self.user_id_tok,
        )
        self.render(request)
        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.THREEPID_AUTH_FAILED, channel.json_body["errcode"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_no_valid_token(self):
        """Test that we do actually need to request a token and can't just
        make a session up.
        """
        client_secret = "foobar"
        session_id = "weasle"

        # Attempt to add email without even requesting an email
        request, channel = self.make_request(
            "POST",
            b"/_matrix/client/unstable/account/3pid/add",
            {
                "client_secret": client_secret,
                "sid": session_id,
                "auth": {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": "test",
                },
            },
            access_token=self.user_id_tok,
        )
        self.render(request)
        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.THREEPID_AUTH_FAILED, channel.json_body["errcode"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    @override_config({"next_link_domain_whitelist": None})
    def test_next_link(self):
        """Tests a valid next_link parameter value with no whitelist (good case)"""
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://example.com/a/good/site",
            expect_code=200,
        )

    @override_config({"next_link_domain_whitelist": None})
    def test_next_link_exotic_protocol(self):
        """Tests using a esoteric protocol as a next_link parameter value.
        Someone may be hosting a client on IPFS etc.
        """
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="some-protocol://abcdefghijklmopqrstuvwxyz",
            expect_code=200,
        )

    @override_config({"next_link_domain_whitelist": None})
    def test_next_link_file_uri(self):
        """Tests next_link parameters cannot be file URI"""
        # Attempt to use a next_link value that points to the local disk
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="file:///host/path",
            expect_code=400,
        )

    @override_config({"next_link_domain_whitelist": ["example.com", "example.org"]})
    def test_next_link_domain_whitelist(self):
        """Tests next_link parameters must fit the whitelist if provided"""

        # Ensure not providing a next_link parameter still works
        self._request_token(
            "something@example.com", "some_secret", next_link=None, expect_code=200,
        )

        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://example.com/some/good/page",
            expect_code=200,
        )

        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://example.org/some/also/good/page",
            expect_code=200,
        )

        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://bad.example.org/some/bad/page",
            expect_code=400,
        )

    @override_config({"next_link_domain_whitelist": []})
    def test_empty_next_link_domain_whitelist(self):
        """Tests an empty next_lint_domain_whitelist value, meaning next_link is essentially
        disallowed
        """
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://example.com/a/page",
            expect_code=400,
        )

    def _request_token(
        self,
        email: str,
        client_secret: str,
        next_link: Optional[str] = None,
        expect_code: int = 200,
    ) -> str:
        """Request a validation token to add an email address to a user's account

        Args:
            email: The email address to validate
            client_secret: A secret string
            next_link: A link to redirect the user to after validation
            expect_code: Expected return code of the call

        Returns:
            The ID of the new threepid validation session
        """
        body = {"client_secret": client_secret, "email": email, "send_attempt": 1}
        if next_link:
            body["next_link"] = next_link

        request, channel = self.make_request(
            "POST", b"account/3pid/email/requestToken", body,
        )
        self.render(request)
        self.assertEquals(expect_code, channel.code, channel.result)

        return channel.json_body.get("sid")

    def _request_token_invalid_email(
        self, email, expected_errcode, expected_error, client_secret="foobar",
    ):
        request, channel = self.make_request(
            "POST",
            b"account/3pid/email/requestToken",
            {"client_secret": client_secret, "email": email, "send_attempt": 1},
        )
        self.render(request)
        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(expected_errcode, channel.json_body["errcode"])
        self.assertEqual(expected_error, channel.json_body["error"])

    def _validate_token(self, link):
        # Remove the host
        path = link.replace("https://example.com", "")

        request, channel = self.make_request("GET", path, shorthand=False)
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

    def _get_link_from_email(self):
        assert self.email_attempts, "No emails have been sent"

        raw_msg = self.email_attempts[-1].decode("UTF-8")
        mail = Parser().parsestr(raw_msg)

        text = None
        for part in mail.walk():
            if part.get_content_type() == "text/plain":
                text = part.get_payload(decode=True).decode("UTF-8")
                break

        if not text:
            self.fail("Could not find text portion of email to parse")

        match = re.search(r"https://example.com\S+", text)
        assert match, "Could not find link in email"

        return match.group(0)

    def _add_email(self, request_email, expected_email):
        """Test adding an email to profile
        """
        client_secret = "foobar"
        session_id = self._request_token(request_email, client_secret)

        self.assertEquals(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        request, channel = self.make_request(
            "POST",
            b"/_matrix/client/unstable/account/3pid/add",
            {
                "client_secret": client_secret,
                "sid": session_id,
                "auth": {
                    "type": "m.login.password",
                    "user": self.user_id,
                    "password": "test",
                },
            },
            access_token=self.user_id_tok,
        )

        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])

        # Get user
        request, channel = self.make_request(
            "GET", self.url_3pid, access_token=self.user_id_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual(expected_email, channel.json_body["threepids"][0]["address"])
