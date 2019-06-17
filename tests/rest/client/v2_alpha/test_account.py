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

import pkg_resources

import synapse.rest.admin
from synapse.api.constants import LoginType
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import account, register

from tests import unittest


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

        def sendmail(smtphost, from_addr, to_addrs, msg, **kwargs):
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
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def test_deactivate_account(self):
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

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

        store = self.hs.get_datastore()

        # Check that the user has been marked as deactivated.
        self.assertTrue(self.get_success(store.get_user_deactivated_status(user_id)))

        # Check that this access token has been invalidated.
        request, channel = self.make_request("GET", "account/whoami")
        self.render(request)
        self.assertEqual(request.code, 401)
