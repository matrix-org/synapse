import datetime
import json
import os

import pkg_resources

import synapse.rest.admin
from synapse.api.constants import LoginType
from synapse.api.errors import Codes
from synapse.appservice import ApplicationService
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import account_validity, register, sync

from tests import unittest

try:
    from synapse.push.mailer import load_jinja2_templates
except ImportError:
    load_jinja2_templates = None


class RegisterRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [register.register_servlets]

    def make_homeserver(self, reactor, clock):

        self.url = b"/_matrix/client/r0/register"

        self.hs = self.setup_test_homeserver()
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []
        self.hs.config.enable_registration_captcha = False
        self.hs.config.allow_guest_access = True

        return self.hs

    def test_POST_appservice_registration_valid(self):
        user_id = "@as_user_kermit:test"
        as_token = "i_am_an_app_service"

        appservice = ApplicationService(
            as_token,
            self.hs.config.server_name,
            id="1234",
            namespaces={"users": [{"regex": r"@as_user.*", "exclusive": True}]},
        )

        self.hs.get_datastore().services_cache.append(appservice)
        request_data = json.dumps({"username": "as_user_kermit"})

        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)
        det_data = {"user_id": user_id, "home_server": self.hs.hostname}
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_appservice_registration_invalid(self):
        self.appservice = None  # no application service exists
        request_data = json.dumps({"username": "kermit"})
        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )
        self.render(request)

        self.assertEquals(channel.result["code"], b"401", channel.result)

    def test_POST_bad_password(self):
        request_data = json.dumps({"username": "kermit", "password": 666})
        request, channel = self.make_request(b"POST", self.url, request_data)
        self.render(request)

        self.assertEquals(channel.result["code"], b"400", channel.result)
        self.assertEquals(channel.json_body["error"], "Invalid password")

    def test_POST_bad_username(self):
        request_data = json.dumps({"username": 777, "password": "monkey"})
        request, channel = self.make_request(b"POST", self.url, request_data)
        self.render(request)

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
        self.render(request)

        det_data = {
            "user_id": user_id,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertEquals(channel.result["code"], b"200", channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_disabled_registration(self):
        self.hs.config.enable_registration = False
        request_data = json.dumps({"username": "kermit", "password": "monkey"})
        self.auth_result = (None, {"username": "kermit", "password": "monkey"}, None)

        request, channel = self.make_request(b"POST", self.url, request_data)
        self.render(request)

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(channel.json_body["error"], "Registration has been disabled")

    def test_POST_guest_registration(self):
        self.hs.config.macaroon_secret_key = "test"
        self.hs.config.allow_guest_access = True

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        det_data = {"home_server": self.hs.hostname, "device_id": "guest_device"}
        self.assertEquals(channel.result["code"], b"200", channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)

    def test_POST_disabled_guest_registration(self):
        self.hs.config.allow_guest_access = False

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(channel.json_body["error"], "Guest access is disabled")

    def test_POST_ratelimiting_guest(self):
        self.hs.config.rc_registration.burst_count = 5
        self.hs.config.rc_registration.per_second = 0.17

        for i in range(0, 6):
            url = self.url + b"?kind=guest"
            request, channel = self.make_request(b"POST", url, b"{}")
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.0)

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_POST_ratelimiting(self):
        self.hs.config.rc_registration.burst_count = 5
        self.hs.config.rc_registration.per_second = 0.17

        for i in range(0, 6):
            params = {
                "username": "kermit" + str(i),
                "password": "monkey",
                "device_id": "frogfone",
                "auth": {"type": LoginType.DUMMY},
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", self.url, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.0)

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)


class AccountValidityTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        account_validity.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        # Test for account expiring after a week.
        config.enable_registration = True
        config.account_validity.enabled = True
        config.account_validity.period = 604800000  # Time in ms for 1 week
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def test_validity_period(self):
        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(datetime.timedelta(weeks=1).total_seconds())

        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.render(request)

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
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.render(request)
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
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # The specific endpoint doesn't matter, all we need is an authenticated
        # endpoint.
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.render(request)
        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(
            channel.json_body["errcode"], Codes.EXPIRED_ACCOUNT, channel.result
        )


class AccountValidityRenewalByEmailTestCase(unittest.HomeserverTestCase):

    skip = "No Jinja installed" if not load_jinja2_templates else None
    servlets = [
        register.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        sync.register_servlets,
        account_validity.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        config = self.default_config()
        # Test for account expiring after a week and renewal emails being sent 2
        # days before expiry.
        config.enable_registration = True
        config.account_validity.enabled = True
        config.account_validity.renew_by_email_enabled = True
        config.account_validity.period = 604800000  # Time in ms for 1 week
        config.account_validity.renew_at = 172800000  # Time in ms for 2 days
        config.account_validity.renew_email_subject = "Renew your account"

        # Email config.
        self.email_attempts = []

        def sendmail(*args, **kwargs):
            self.email_attempts.append((args, kwargs))
            return

        config.email_template_dir = os.path.abspath(
            pkg_resources.resource_filename('synapse', 'res/templates')
        )
        config.email_expiry_template_html = "notice_expiry.html"
        config.email_expiry_template_text = "notice_expiry.txt"
        config.email_smtp_host = "127.0.0.1"
        config.email_smtp_port = 20
        config.require_transport_security = False
        config.email_smtp_user = None
        config.email_smtp_pass = None
        config.email_notif_from = "test@example.com"

        self.hs = self.setup_test_homeserver(config=config, sendmail=sendmail)

        self.store = self.hs.get_datastore()

        return self.hs

    def test_renewal_email(self):
        self.email_attempts = []

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

        # Move 6 days forward. This should trigger a renewal email to be sent.
        self.reactor.advance(datetime.timedelta(days=6).total_seconds())
        self.assertEqual(len(self.email_attempts), 1)

        # Retrieving the URL from the email is too much pain for now, so we
        # retrieve the token from the DB.
        renewal_token = self.get_success(self.store.get_renewal_token_for_user(user_id))
        url = "/_matrix/client/unstable/account_validity/renew?token=%s" % renewal_token
        request, channel = self.make_request(b"GET", url)
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        # Move 3 days forward. If the renewal failed, every authed request with
        # our access token should be denied from now, otherwise they should
        # succeed.
        self.reactor.advance(datetime.timedelta(days=3).total_seconds())
        request, channel = self.make_request(b"GET", "/sync", access_token=tok)
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_manual_email_send(self):
        self.email_attempts = []

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

        request, channel = self.make_request(
            b"POST",
            "/_matrix/client/unstable/account_validity/send_mail",
            access_token=tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)

        self.assertEqual(len(self.email_attempts), 1)
