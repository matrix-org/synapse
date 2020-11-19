# -*- coding: utf-8 -*-
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
import json
import os

import pkg_resources

import synapse.rest.admin
from synapse.api.constants import LoginType
from synapse.api.errors import Codes
from synapse.appservice import ApplicationService
from synapse.rest.client.v1 import login, logout
from synapse.rest.client.v2_alpha import account, account_validity, register, sync

from tests import unittest
from tests.unittest import override_config


class RegisterRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        login.register_servlets,
        register.register_servlets,
        synapse.rest.admin.register_servlets,
    ]
    url = b"/_matrix/client/r0/register"

    def default_config(self):
        config = super().default_config()
        config["allow_guest_access"] = True
        return config

    def test_POST_appservice_registration_valid(self):
        user_id = "@as_user_kermit:test"
        as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            as_token,
            self.hs.config.server_name,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
            sender="@as:test",
        )

        self.hs.get_datastore().services_cache.append(appservice)
        request_data = json.dumps({"username": "as_user_kermit"})

        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )

        self.assertEquals(channel.result["code"], b"200", channel.result)
        det_data = {"user_id": user_id, "home_server": self.hs.hostname}
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_appservice_registration_invalid(self):
        self.appservice = None  # no application service exists
        request_data = json.dumps({"username": "kermit"})
        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )

        self.assertEquals(channel.result["code"], b"401", channel.result)

    def test_POST_bad_password(self):
        request_data = json.dumps({"username": "kermit", "password": 666})
        request, channel = self.make_request(b"POST", self.url, request_data)

        self.assertEquals(channel.result["code"], b"400", channel.result)
        self.assertEquals(channel.json_body["error"], "Invalid password")

    def test_POST_bad_username(self):
        request_data = json.dumps({"username": 777, "password": "monkey"})
        request, channel = self.make_request(b"POST", self.url, request_data)

        self.assertEquals(channel.result["code"], b"400", channel.result)
        self.assertEquals(channel.json_body["error"], "Invalid username")

    def test_POST_user_valid(self):
        user_id = "@kermit:test"
        device_id = "frogfone"
        params = {
            "username": "kermit",
            "password": "monkey",
            "device_id": device_id,
            "auth": {"type": LoginType.DUMMY},
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", self.url, request_data)

        det_data = {
            "user_id": user_id,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertEquals(channel.result["code"], b"200", channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    @override_config({"enable_registration": False})
    def test_POST_disabled_registration(self):
        request_data = json.dumps({"username": "kermit", "password": "monkey"})
        self.auth_result = (None, {"username": "kermit", "password": "monkey"}, None)

        request, channel = self.make_request(b"POST", self.url, request_data)

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(channel.json_body["error"], "Registration has been disabled")

    def test_POST_guest_registration(self):
        self.hs.config.macaroon_secret_key = "test"
        self.hs.config.allow_guest_access = True

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        det_data = {"home_server": self.hs.hostname, "device_id": "guest_device"}
        self.assertEquals(channel.result["code"], b"200", channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_disabled_guest_registration(self):
        self.hs.config.allow_guest_access = False

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(channel.json_body["error"], "Guest access is disabled")

    @override_config({"rc_registration": {"per_second": 0.17, "burst_count": 5}})
    def test_POST_ratelimiting_guest(self):
        for i in range(0, 6):
            url = self.url + b"?kind=guest"
            request, channel = self.make_request(b"POST", url, b"{}")

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEquals(channel.result["code"], b"200", channel.result)

    @override_config({"rc_registration": {"per_second": 0.17, "burst_count": 5}})
    def test_POST_ratelimiting(self):
        for i in range(0, 6):
            params = {
                "username": "kermit" + str(i),
                "password": "monkey",
                "device_id": "frogfone",
                "auth": {"type": LoginType.DUMMY},
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", self.url, request_data)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.0 + 1.0)

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_advertised_flows(self):
        request, channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEquals(channel.result["code"], b"401", channel.result)
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
                "email": "https://id_server",
                "msisdn": "https://id_server",
            },
        }
    )
    def test_advertised_flows_captcha_and_terms_and_3pids(self):
        request, channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEquals(channel.result["code"], b"401", channel.result)
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
    def test_advertised_flows_no_msisdn_email_required(self):
        request, channel = self.make_request(b"POST", self.url, b"{}")
        self.assertEquals(channel.result["code"], b"401", channel.result)
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
    def test_request_token_existing_email_inhibit_error(self):
        """Test that requesting a token via this endpoint doesn't leak existing
        associations if configured that way.
        """
        user_id = self.register_user("kermit", "monkey")
        self.login("kermit", "monkey")

        email = "test@example.com"

        # Add a threepid
        self.get_success(
            self.hs.get_datastore().user_add_threepid(
                user_id=user_id,
                medium="email",
                address=email,
                validated_at=0,
                added_at=0,
            )
        )

        request, channel = self.make_request(
            "POST",
            b"register/email/requestToken",
            {"client_secret": "foobar", "email": email, "send_attempt": 1},
        )
        self.assertEquals(200, channel.code, channel.result)

        self.assertIsNotNone(channel.json_body.get("sid"))


class AccountValidityTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        logout.register_servlets,
        account_validity.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        # Test for account expiring after a week.
        config["enable_registration"] = True
        config["account_validity"] = {
            "enabled": True,
            "period": 604800000,  # Time in ms for 1 week
        }
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def test_validity_period(self):
        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)

        self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(datetime.timedelta(weeks=1).total_seconds())

        request, channel = self.make_request(b"GET", "/sync", access_token=tok)

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(
            channel.json_body["errcode"], Codes.EXPIRED_ACCOUNT, channel.result
        )

    def test_manual_renewal(self):
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.reactor.advance(datetime.timedelta(weeks=1).total_seconds())

        # If we register the admin user at the beginning of the test, it will
        # expire at the same time as the normal user and the renewal request
        # will be denied.
        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_matrix/client/unstable/admin/account_validity/validity"
        params = {"user_id": user_id}
        request_data = json.dumps(params)
        request, channel = self.make_request(
            b"POST", url, request_data, access_token=admin_tok
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_manual_expire(self):
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_matrix/client/unstable/admin/account_validity/validity"
        params = {
            "user_id": user_id,
            "expiration_ts": 0,
            "enable_renewal_emails": False,
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(
            b"POST", url, request_data, access_token=admin_tok
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(
            channel.json_body["errcode"], Codes.EXPIRED_ACCOUNT, channel.result
        )

    def test_logging_out_expired_user(self):
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        self.register_user("admin", "adminpassword", admin=True)
        admin_tok = self.login("admin", "adminpassword")

        url = "/_matrix/client/unstable/admin/account_validity/validity"
        params = {
            "user_id": user_id,
            "expiration_ts": 0,
            "enable_renewal_emails": False,
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(
            b"POST", url, request_data, access_token=admin_tok
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # Try to log the user out
        request, channel = self.make_request(b"POST", "/logout", access_token=tok)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # Log the user in again (allowed for expired accounts)
        tok = self.login("kermit", "monkey")

        # Try to log out all of the user's sessions
        request, channel = self.make_request(b"POST", "/logout/all", access_token=tok)
        self.assertEquals(channel.result["code"], b"200", channel.result)


class AccountValidityRenewalByEmailTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        account_validity.register_servlets,
        account.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
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
        self.email_attempts = []

        async def sendmail(*args, **kwargs):
            self.email_attempts.append((args, kwargs))

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
        config["public_baseurl"] = "aaa"

        self.hs = self.setup_test_homeserver(config=config, sendmail=sendmail)

        self.store = self.hs.get_datastore()

        return self.hs

    def test_renewal_email(self):
        self.email_attempts = []

        (user_id, tok) = self.create_user()

        # Move 6 days forward. This should trigger a renewal email to be sent.
        self.reactor.advance(datetime.timedelta(days=6).total_seconds())
        self.assertEqual(len(self.email_attempts), 1)

        # Retrieving the URL from the email is too much pain for now, so we
        # retrieve the token from the DB.
        renewal_token = self.get_success(self.store.get_renewal_token_for_user(user_id))
        url = "/_matrix/client/unstable/account_validity/renew?token=%s" % renewal_token
        request, channel = self.make_request(b"GET", url)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # Check that we're getting HTML back.
        content_type = None
        for header in channel.result.get("headers", []):
            if header[0] == b"Content-Type":
                content_type = header[1]
        self.assertEqual(content_type, b"text/html; charset=utf-8", channel.result)

        # Check that the HTML we're getting is the one we expect on a successful renewal.
        expected_html = self.hs.config.account_validity.account_renewed_html_content
        self.assertEqual(
            channel.result["body"], expected_html.encode("utf8"), channel.result
        )

        # Move 3 days forward. If the renewal failed, every authed request with
        # our access token should be denied from now, otherwise they should
        # succeed.
        self.reactor.advance(datetime.timedelta(days=3).total_seconds())
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_renewal_invalid_token(self):
        # Hit the renewal endpoint with an invalid token and check that it behaves as
        # expected, i.e. that it responds with 404 Not Found and the correct HTML.
        url = "/_matrix/client/unstable/account_validity/renew?token=123"
        request, channel = self.make_request(b"GET", url)
        self.assertEquals(channel.result["code"], b"404", channel.result)

        # Check that we're getting HTML back.
        content_type = None
        for header in channel.result.get("headers", []):
            if header[0] == b"Content-Type":
                content_type = header[1]
        self.assertEqual(content_type, b"text/html; charset=utf-8", channel.result)

        # Check that the HTML we're getting is the one we expect when using an
        # invalid/unknown token.
        expected_html = self.hs.config.account_validity.invalid_token_html_content
        self.assertEqual(
            channel.result["body"], expected_html.encode("utf8"), channel.result
        )

    def test_manual_email_send(self):
        self.email_attempts = []

        (user_id, tok) = self.create_user()
        request, channel = self.make_request(
            b"POST",
            "/_matrix/client/unstable/account_validity/send_mail",
            access_token=tok,
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        self.assertEqual(len(self.email_attempts), 1)

    def test_deactivated_user(self):
        self.email_attempts = []

        (user_id, tok) = self.create_user()

        request_data = json.dumps(
            {
                "auth": {
                    "type": "m.login.password",
                    "user": user_id,
                    "password": "monkey",
                },
                "erase": False,
            }
        )
        request, channel = self.make_request(
            "POST", "account/deactivate", request_data, access_token=tok
        )
        self.assertEqual(request.code, 200)

        self.reactor.advance(datetime.timedelta(days=8).total_seconds())

        self.assertEqual(len(self.email_attempts), 0)

    def create_user(self):
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")
        # We need to manually add an email address otherwise the handler will do
        # nothing.
        now = self.hs.clock.time_msec()
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

    def test_manual_email_send_expired_account(self):
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        # We need to manually add an email address otherwise the handler will do
        # nothing.
        now = self.hs.clock.time_msec()
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
        request, channel = self.make_request(
            b"POST",
            "/_matrix/client/unstable/account_validity/send_mail",
            access_token=tok,
        )
        self.assertEquals(channel.result["code"], b"200", channel.result)

        self.assertEqual(len(self.email_attempts), 1)


class AccountValidityBackgroundJobTestCase(unittest.HomeserverTestCase):

    servlets = [synapse.rest.admin.register_servlets_for_client_rest_resource]

    def make_homeserver(self, reactor, clock):
        self.validity_period = 10
        self.max_delta = self.validity_period * 10.0 / 100.0

        config = self.default_config()

        config["enable_registration"] = True
        config["account_validity"] = {"enabled": False}

        self.hs = self.setup_test_homeserver(config=config)
        self.hs.config.account_validity.period = self.validity_period

        self.store = self.hs.get_datastore()

        return self.hs

    def test_background_job(self):
        """
        Tests the same thing as test_background_job, except that it sets the
        startup_job_max_delta parameter and checks that the expiration date is within the
        allowed range.
        """
        user_id = self.register_user("kermit_delta", "user")

        self.hs.config.account_validity.startup_job_max_delta = self.max_delta

        now_ms = self.hs.clock.time_msec()
        self.get_success(self.store._set_expiration_date_when_missing())

        res = self.get_success(self.store.get_expiration_ts_for_user(user_id))

        self.assertGreaterEqual(res, now_ms + self.validity_period - self.max_delta)
        self.assertLessEqual(res, now_ms + self.validity_period)
