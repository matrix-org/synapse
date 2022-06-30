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
import json
import os
import re
from email.parser import Parser
from typing import Any, Dict, List, Optional, Union
from unittest.mock import Mock

import pkg_resources

from twisted.internet.interfaces import IReactorTCP
from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.constants import LoginType, Membership
from synapse.api.errors import Codes, HttpResponseException
from synapse.appservice import ApplicationService
from synapse.rest import admin
from synapse.rest.client import account, login, register, room
from synapse.rest.synapse.client.password_reset import PasswordResetSubmitTokenResource
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock

from tests import unittest
from tests.server import FakeSite, make_request
from tests.unittest import override_config


class PasswordResetTestCase(unittest.HomeserverTestCase):

    servlets = [
        account.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        register.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        # Email config.
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

        hs = self.setup_test_homeserver(config=config)

        async def sendmail(
            reactor: IReactorTCP,
            smtphost: str,
            smtpport: int,
            from_addr: str,
            to_addr: str,
            msg_bytes: bytes,
            *args: Any,
            **kwargs: Any,
        ) -> None:
            self.email_attempts.append(msg_bytes)

        self.email_attempts: List[bytes] = []
        hs.get_send_email_handler()._sendmail = sendmail

        return hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.submit_token_resource = PasswordResetSubmitTokenResource(hs)

    def attempt_wrong_password_login(self, username: str, password: str) -> None:
        """Attempts to login as the user with the given password, asserting
        that the attempt *fails*.
        """
        body = {"type": "m.login.password", "user": username, "password": password}

        channel = self.make_request(
            "POST", "/_matrix/client/r0/login", json.dumps(body).encode("utf8")
        )
        self.assertEqual(channel.code, 403, channel.result)

    def test_basic_password_reset(self) -> None:
        """Test basic password reset flow"""
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

        self.assertEqual(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        self._reset_password(new_password, session_id, client_secret)

        # Assert we can log in with the new password
        self.login("kermit", new_password)

        # Assert we can't log in with the old password
        self.attempt_wrong_password_login("kermit", old_password)

    @override_config({"rc_3pid_validation": {"burst_count": 3}})
    def test_ratelimit_by_email(self) -> None:
        """Test that we ratelimit /requestToken for the same email."""
        old_password = "monkey"
        new_password = "kangeroo"

        user_id = self.register_user("kermit", old_password)
        self.login("kermit", old_password)

        email = "test1@example.com"

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

        def reset(ip: str) -> None:
            client_secret = "foobar"
            session_id = self._request_token(email, client_secret, ip)

            self.assertEqual(len(self.email_attempts), 1)
            link = self._get_link_from_email()

            self._validate_token(link)

            self._reset_password(new_password, session_id, client_secret)

            self.email_attempts.clear()

        # We expect to be able to make three requests before getting rate
        # limited.
        #
        # We change IPs to ensure that we're not being ratelimited due to the
        # same IP
        reset("127.0.0.1")
        reset("127.0.0.2")
        reset("127.0.0.3")

        with self.assertRaises(HttpResponseException) as cm:
            reset("127.0.0.4")

        self.assertEqual(cm.exception.code, 429)

    def test_basic_password_reset_canonicalise_email(self) -> None:
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

        self.assertEqual(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        self._reset_password(new_password, session_id, client_secret)

        # Assert we can log in with the new password
        self.login("kermit", new_password)

        # Assert we can't log in with the old password
        self.attempt_wrong_password_login("kermit", old_password)

    def test_cant_reset_password_without_clicking_link(self) -> None:
        """Test that we do actually need to click the link in the email"""
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

        self.assertEqual(len(self.email_attempts), 1)

        # Attempt to reset password without clicking the link
        self._reset_password(new_password, session_id, client_secret, expected_code=401)

        # Assert we can log in with the old password
        self.login("kermit", old_password)

        # Assert we can't log in with the new password
        self.attempt_wrong_password_login("kermit", new_password)

    def test_no_valid_token(self) -> None:
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
    def test_password_reset_bad_email_inhibit_error(self) -> None:
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

    def _request_token(
        self,
        email: str,
        client_secret: str,
        ip: str = "127.0.0.1",
    ) -> str:
        channel = self.make_request(
            "POST",
            b"account/password/email/requestToken",
            {"client_secret": client_secret, "email": email, "send_attempt": 1},
            client_ip=ip,
        )

        if channel.code != 200:
            raise HttpResponseException(
                channel.code,
                channel.result["reason"],
                channel.result["body"],
            )

        return channel.json_body["sid"]

    def _validate_token(self, link: str) -> None:
        # Remove the host
        path = link.replace("https://example.com", "")

        # Load the password reset confirmation page
        channel = make_request(
            self.reactor,
            FakeSite(self.submit_token_resource, self.reactor),
            "GET",
            path,
            shorthand=False,
        )

        self.assertEqual(200, channel.code, channel.result)

        # Now POST to the same endpoint, mimicking the same behaviour as clicking the
        # password reset confirm button

        # Confirm the password reset
        channel = make_request(
            self.reactor,
            FakeSite(self.submit_token_resource, self.reactor),
            "POST",
            path,
            content=b"",
            shorthand=False,
            content_is_form=True,
        )
        self.assertEqual(200, channel.code, channel.result)

    def _get_link_from_email(self) -> str:
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

        assert text is not None
        match = re.search(r"https://example.com\S+", text)
        assert match, "Could not find link in email"

        return match.group(0)

    def _reset_password(
        self,
        new_password: str,
        session_id: str,
        client_secret: str,
        expected_code: int = 200,
    ) -> None:
        channel = self.make_request(
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
        self.assertEqual(expected_code, channel.code, channel.result)


class DeactivateTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        self.hs = self.setup_test_homeserver()
        return self.hs

    def test_deactivate_account(self) -> None:
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        self.deactivate(user_id, tok)

        store = self.hs.get_datastores().main

        # Check that the user has been marked as deactivated.
        self.assertTrue(self.get_success(store.get_user_deactivated_status(user_id)))

        # Check that this access token has been invalidated.
        channel = self.make_request("GET", "account/whoami", access_token=tok)
        self.assertEqual(channel.code, 401)

    def test_pending_invites(self) -> None:
        """Tests that deactivating a user rejects every pending invite for them."""
        store = self.hs.get_datastores().main

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

    def deactivate(self, user_id: str, tok: str) -> None:
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
        channel = self.make_request(
            "POST", "account/deactivate", request_data, access_token=tok
        )
        self.assertEqual(channel.code, 200)


class WhoamiTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
        register.register_servlets,
    ]

    def default_config(self) -> Dict[str, Any]:
        config = super().default_config()
        config["allow_guest_access"] = True
        return config

    def test_GET_whoami(self) -> None:
        device_id = "wouldgohere"
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test", device_id=device_id)

        whoami = self._whoami(tok)
        self.assertEqual(
            whoami,
            {
                "user_id": user_id,
                "device_id": device_id,
                "is_guest": False,
            },
        )

    def test_GET_whoami_guests(self) -> None:
        channel = self.make_request(
            b"POST", b"/_matrix/client/r0/register?kind=guest", b"{}"
        )
        tok = channel.json_body["access_token"]
        user_id = channel.json_body["user_id"]
        device_id = channel.json_body["device_id"]

        whoami = self._whoami(tok)
        self.assertEqual(
            whoami,
            {
                "user_id": user_id,
                "device_id": device_id,
                "is_guest": True,
            },
        )

    def test_GET_whoami_appservices(self) -> None:
        user_id = "@as:test"
        as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            as_token,
            id="1234",
            namespaces={"users": [{"regex": user_id, "exclusive": True}]},
            sender=user_id,
        )
        self.hs.get_datastores().main.services_cache.append(appservice)

        whoami = self._whoami(as_token)
        self.assertEqual(
            whoami,
            {
                "user_id": user_id,
                "is_guest": False,
            },
        )
        self.assertFalse(hasattr(whoami, "device_id"))

    def _whoami(self, tok: str) -> JsonDict:
        channel = self.make_request("GET", "account/whoami", {}, access_token=tok)
        self.assertEqual(channel.code, 200)
        return channel.json_body


class ThreepidEmailRestTestCase(unittest.HomeserverTestCase):

    servlets = [
        account.register_servlets,
        login.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()

        # Email config.
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

        self.hs = self.setup_test_homeserver(config=config)

        async def sendmail(
            reactor: IReactorTCP,
            smtphost: str,
            smtpport: int,
            from_addr: str,
            to_addr: str,
            msg_bytes: bytes,
            *args: Any,
            **kwargs: Any,
        ) -> None:
            self.email_attempts.append(msg_bytes)

        self.email_attempts: List[bytes] = []
        self.hs.get_send_email_handler()._sendmail = sendmail

        return self.hs

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

        self.user_id = self.register_user("kermit", "test")
        self.user_id_tok = self.login("kermit", "test")
        self.email = "test@example.com"
        self.url_3pid = b"account/3pid"

    def test_add_valid_email(self) -> None:
        self._add_email(self.email, self.email)

    def test_add_valid_email_second_time(self) -> None:
        self._add_email(self.email, self.email)
        self._request_token_invalid_email(
            self.email,
            expected_errcode=Codes.THREEPID_IN_USE,
            expected_error="Email is already in use",
        )

    def test_add_valid_email_second_time_canonicalise(self) -> None:
        self._add_email(self.email, self.email)
        self._request_token_invalid_email(
            "TEST@EXAMPLE.COM",
            expected_errcode=Codes.THREEPID_IN_USE,
            expected_error="Email is already in use",
        )

    def test_add_email_no_at(self) -> None:
        self._request_token_invalid_email(
            "address-without-at.bar",
            expected_errcode=Codes.UNKNOWN,
            expected_error="Unable to parse email address",
        )

    def test_add_email_two_at(self) -> None:
        self._request_token_invalid_email(
            "foo@foo@test.bar",
            expected_errcode=Codes.UNKNOWN,
            expected_error="Unable to parse email address",
        )

    def test_add_email_bad_format(self) -> None:
        self._request_token_invalid_email(
            "user@bad.example.net@good.example.com",
            expected_errcode=Codes.UNKNOWN,
            expected_error="Unable to parse email address",
        )

    def test_add_email_domain_to_lower(self) -> None:
        self._add_email("foo@TEST.BAR", "foo@test.bar")

    def test_add_email_domain_with_umlaut(self) -> None:
        self._add_email("foo@Öumlaut.com", "foo@öumlaut.com")

    def test_add_email_address_casefold(self) -> None:
        self._add_email("Strauß@Example.com", "strauss@example.com")

    def test_address_trim(self) -> None:
        self._add_email(" foo@test.bar ", "foo@test.bar")

    @override_config({"rc_3pid_validation": {"burst_count": 3}})
    def test_ratelimit_by_ip(self) -> None:
        """Tests that adding emails is ratelimited by IP"""

        # We expect to be able to set three emails before getting ratelimited.
        self._add_email("foo1@test.bar", "foo1@test.bar")
        self._add_email("foo2@test.bar", "foo2@test.bar")
        self._add_email("foo3@test.bar", "foo3@test.bar")

        with self.assertRaises(HttpResponseException) as cm:
            self._add_email("foo4@test.bar", "foo4@test.bar")

        self.assertEqual(cm.exception.code, 429)

    def test_add_email_if_disabled(self) -> None:
        """Test adding email to profile when doing so is disallowed"""
        self.hs.config.registration.enable_3pid_changes = False

        client_secret = "foobar"
        session_id = self._request_token(self.email, client_secret)

        self.assertEqual(len(self.email_attempts), 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        channel = self.make_request(
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
        self.assertEqual(400, channel.code, msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_delete_email(self) -> None:
        """Test deleting an email from profile"""
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

        channel = self.make_request(
            "POST",
            b"account/3pid/delete",
            {"medium": "email", "address": self.email},
            access_token=self.user_id_tok,
        )
        self.assertEqual(200, channel.code, msg=channel.result["body"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_delete_email_if_disabled(self) -> None:
        """Test deleting an email from profile when disallowed"""
        self.hs.config.registration.enable_3pid_changes = False

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

        channel = self.make_request(
            "POST",
            b"account/3pid/delete",
            {"medium": "email", "address": self.email},
            access_token=self.user_id_tok,
        )

        self.assertEqual(400, channel.code, msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])
        self.assertEqual(self.email, channel.json_body["threepids"][0]["address"])

    def test_cant_add_email_without_clicking_link(self) -> None:
        """Test that we do actually need to click the link in the email"""
        client_secret = "foobar"
        session_id = self._request_token(self.email, client_secret)

        self.assertEqual(len(self.email_attempts), 1)

        # Attempt to add email without clicking the link
        channel = self.make_request(
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
        self.assertEqual(400, channel.code, msg=channel.result["body"])
        self.assertEqual(Codes.THREEPID_AUTH_FAILED, channel.json_body["errcode"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    def test_no_valid_token(self) -> None:
        """Test that we do actually need to request a token and can't just
        make a session up.
        """
        client_secret = "foobar"
        session_id = "weasle"

        # Attempt to add email without even requesting an email
        channel = self.make_request(
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
        self.assertEqual(400, channel.code, msg=channel.result["body"])
        self.assertEqual(Codes.THREEPID_AUTH_FAILED, channel.json_body["errcode"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertFalse(channel.json_body["threepids"])

    @override_config({"next_link_domain_whitelist": None})
    def test_next_link(self) -> None:
        """Tests a valid next_link parameter value with no whitelist (good case)"""
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="https://example.com/a/good/site",
            expect_code=200,
        )

    @override_config({"next_link_domain_whitelist": None})
    def test_next_link_exotic_protocol(self) -> None:
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
    def test_next_link_file_uri(self) -> None:
        """Tests next_link parameters cannot be file URI"""
        # Attempt to use a next_link value that points to the local disk
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link="file:///host/path",
            expect_code=400,
        )

    @override_config({"next_link_domain_whitelist": ["example.com", "example.org"]})
    def test_next_link_domain_whitelist(self) -> None:
        """Tests next_link parameters must fit the whitelist if provided"""

        # Ensure not providing a next_link parameter still works
        self._request_token(
            "something@example.com",
            "some_secret",
            next_link=None,
            expect_code=200,
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
    def test_empty_next_link_domain_whitelist(self) -> None:
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
    ) -> Optional[str]:
        """Request a validation token to add an email address to a user's account

        Args:
            email: The email address to validate
            client_secret: A secret string
            next_link: A link to redirect the user to after validation
            expect_code: Expected return code of the call

        Returns:
            The ID of the new threepid validation session, or None if the response
            did not contain a session ID.
        """
        body = {"client_secret": client_secret, "email": email, "send_attempt": 1}
        if next_link:
            body["next_link"] = next_link

        channel = self.make_request(
            "POST",
            b"account/3pid/email/requestToken",
            body,
        )

        if channel.code != expect_code:
            raise HttpResponseException(
                channel.code,
                channel.result["reason"],
                channel.result["body"],
            )

        return channel.json_body.get("sid")

    def _request_token_invalid_email(
        self,
        email: str,
        expected_errcode: str,
        expected_error: str,
        client_secret: str = "foobar",
    ) -> None:
        channel = self.make_request(
            "POST",
            b"account/3pid/email/requestToken",
            {"client_secret": client_secret, "email": email, "send_attempt": 1},
        )
        self.assertEqual(400, channel.code, msg=channel.result["body"])
        self.assertEqual(expected_errcode, channel.json_body["errcode"])
        self.assertEqual(expected_error, channel.json_body["error"])

    def _validate_token(self, link: str) -> None:
        # Remove the host
        path = link.replace("https://example.com", "")

        channel = self.make_request("GET", path, shorthand=False)
        self.assertEqual(200, channel.code, channel.result)

    def _get_link_from_email(self) -> str:
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

        assert text is not None
        match = re.search(r"https://example.com\S+", text)
        assert match, "Could not find link in email"

        return match.group(0)

    def _add_email(self, request_email: str, expected_email: str) -> None:
        """Test adding an email to profile"""
        previous_email_attempts = len(self.email_attempts)

        client_secret = "foobar"
        session_id = self._request_token(request_email, client_secret)

        self.assertEqual(len(self.email_attempts) - previous_email_attempts, 1)
        link = self._get_link_from_email()

        self._validate_token(link)

        channel = self.make_request(
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

        self.assertEqual(200, channel.code, msg=channel.result["body"])

        # Get user
        channel = self.make_request(
            "GET",
            self.url_3pid,
            access_token=self.user_id_tok,
        )

        self.assertEqual(200, channel.code, msg=channel.result["body"])
        self.assertEqual("email", channel.json_body["threepids"][0]["medium"])

        threepids = {threepid["address"] for threepid in channel.json_body["threepids"]}
        self.assertIn(expected_email, threepids)


class AccountStatusTestCase(unittest.HomeserverTestCase):
    servlets = [
        account.register_servlets,
        admin.register_servlets,
        login.register_servlets,
    ]

    url = "/_matrix/client/unstable/org.matrix.msc3720/account_status"

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["experimental_features"] = {"msc3720_enabled": True}

        return self.setup_test_homeserver(config=config)

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.requester = self.register_user("requester", "password")
        self.requester_tok = self.login("requester", "password")
        self.server_name = hs.config.server.server_name

    def test_missing_mxid(self) -> None:
        """Tests that not providing any MXID raises an error."""
        self._test_status(
            users=None,
            expected_status_code=400,
            expected_errcode=Codes.MISSING_PARAM,
        )

    def test_invalid_mxid(self) -> None:
        """Tests that providing an invalid MXID raises an error."""
        self._test_status(
            users=["bad:test"],
            expected_status_code=400,
            expected_errcode=Codes.INVALID_PARAM,
        )

    def test_local_user_not_exists(self) -> None:
        """Tests that the account status endpoints correctly reports that a user doesn't
        exist.
        """
        user = "@unknown:" + self.hs.config.server.server_name

        self._test_status(
            users=[user],
            expected_statuses={
                user: {
                    "exists": False,
                },
            },
            expected_failures=[],
        )

    def test_local_user_exists(self) -> None:
        """Tests that the account status endpoint correctly reports that a user doesn't
        exist.
        """
        user = self.register_user("someuser", "password")

        self._test_status(
            users=[user],
            expected_statuses={
                user: {
                    "exists": True,
                    "deactivated": False,
                },
            },
            expected_failures=[],
        )

    def test_local_user_deactivated(self) -> None:
        """Tests that the account status endpoint correctly reports a deactivated user."""
        user = self.register_user("someuser", "password")
        self.get_success(
            self.hs.get_datastores().main.set_user_deactivated_status(
                user, deactivated=True
            )
        )

        self._test_status(
            users=[user],
            expected_statuses={
                user: {
                    "exists": True,
                    "deactivated": True,
                },
            },
            expected_failures=[],
        )

    def test_mixed_local_and_remote_users(self) -> None:
        """Tests that if some users are remote the account status endpoint correctly
        merges the remote responses with the local result.
        """
        # We use 3 users: one doesn't exist but belongs on the local homeserver, one is
        # deactivated and belongs on one remote homeserver, and one belongs to another
        # remote homeserver that didn't return any result (the federation code should
        # mark that user as a failure).
        users = [
            "@unknown:" + self.hs.config.server.server_name,
            "@deactivated:remote",
            "@failed:otherremote",
            "@bad:badremote",
        ]

        async def post_json(
            destination: str,
            path: str,
            data: Optional[JsonDict] = None,
            *a: Any,
            **kwa: Any,
        ) -> Union[JsonDict, list]:
            if destination == "remote":
                return {
                    "account_statuses": {
                        users[1]: {
                            "exists": True,
                            "deactivated": True,
                        },
                    }
                }
            elif destination == "badremote":
                # badremote tries to overwrite the status of a user that doesn't belong
                # to it (i.e. users[1]) with false data, which Synapse is expected to
                # ignore.
                return {
                    "account_statuses": {
                        users[3]: {
                            "exists": False,
                        },
                        users[1]: {
                            "exists": False,
                        },
                    }
                }
            # if destination == "otherremote"
            else:
                return {}

        # Register a mock that will return the expected result depending on the remote.
        self.hs.get_federation_http_client().post_json = Mock(side_effect=post_json)

        # Check that we've got the correct response from the client-side endpoint.
        self._test_status(
            users=users,
            expected_statuses={
                users[0]: {
                    "exists": False,
                },
                users[1]: {
                    "exists": True,
                    "deactivated": True,
                },
                users[3]: {
                    "exists": False,
                },
            },
            expected_failures=[users[2]],
        )

    @unittest.override_config(
        {
            "use_account_validity_in_account_status": True,
        }
    )
    def test_no_account_validity(self) -> None:
        """Tests that if we decide to include account validity in the response but no
        account validity 'is_user_expired' callback is provided, we default to marking all
        users as not expired.
        """
        user = self.register_user("someuser", "password")

        self._test_status(
            users=[user],
            expected_statuses={
                user: {
                    "exists": True,
                    "deactivated": False,
                    "org.matrix.expired": False,
                },
            },
            expected_failures=[],
        )

    @unittest.override_config(
        {
            "use_account_validity_in_account_status": True,
        }
    )
    def test_account_validity_expired(self) -> None:
        """Test that if we decide to include account validity in the response and the user
        is expired, we return the correct info.
        """
        user = self.register_user("someuser", "password")

        async def is_expired(user_id: str) -> bool:
            # We can't blindly say everyone is expired, otherwise the request to get the
            # account status will fail.
            return UserID.from_string(user_id).localpart == "someuser"

        self.hs.get_account_validity_handler()._is_user_expired_callbacks.append(
            is_expired
        )

        self._test_status(
            users=[user],
            expected_statuses={
                user: {
                    "exists": True,
                    "deactivated": False,
                    "org.matrix.expired": True,
                },
            },
            expected_failures=[],
        )

    def _test_status(
        self,
        users: Optional[List[str]],
        expected_status_code: int = 200,
        expected_statuses: Optional[Dict[str, Dict[str, bool]]] = None,
        expected_failures: Optional[List[str]] = None,
        expected_errcode: Optional[str] = None,
    ) -> None:
        """Send a request to the account status endpoint and check that the response
        matches with what's expected.

        Args:
            users: The account(s) to request the status of, if any. If set to None, no
                `user_id` query parameter will be included in the request.
            expected_status_code: The expected HTTP status code.
            expected_statuses: The expected account statuses, if any.
            expected_failures: The expected failures, if any.
            expected_errcode: The expected Matrix error code, if any.
        """
        content = {}
        if users is not None:
            content["user_ids"] = users

        channel = self.make_request(
            method="POST",
            path=self.url,
            content=content,
            access_token=self.requester_tok,
        )

        self.assertEqual(channel.code, expected_status_code)

        if expected_statuses is not None:
            self.assertEqual(channel.json_body["account_statuses"], expected_statuses)

        if expected_failures is not None:
            self.assertEqual(channel.json_body["failures"], expected_failures)

        if expected_errcode is not None:
            self.assertEqual(channel.json_body["errcode"], expected_errcode)
