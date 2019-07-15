import json

import synapse.rest.admin
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import devices
from synapse.rest.client.v2_alpha.account import WhoamiRestServlet

from tests import unittest
from tests.unittest import override_config

LOGIN_URL = b"/_matrix/client/r0/login"
TEST_URL = b"/_matrix/client/r0/account/whoami"


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        devices.register_servlets,
        lambda hs, http_server: WhoamiRestServlet(hs).register(http_server),
    ]

    def make_homeserver(self, reactor, clock):

        self.hs = self.setup_test_homeserver()
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []
        self.hs.config.enable_registration_captcha = False

        return self.hs

    def test_POST_ratelimiting_per_address(self):
        self.hs.config.rc_login_address.burst_count = 5
        self.hs.config.rc_login_address.per_second = 0.17

        # Create different users so we're sure not to be bothered by the per-user
        # ratelimiter.
        for i in range(0, 6):
            self.register_user("kermit" + str(i), "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
                "password": "monkey",
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", LOGIN_URL, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit" + str(i)},
            "password": "monkey",
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", LOGIN_URL, params)
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_POST_ratelimiting_per_account(self):
        self.hs.config.rc_login_account.burst_count = 5
        self.hs.config.rc_login_account.per_second = 0.17

        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "monkey",
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", LOGIN_URL, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", LOGIN_URL, params)
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_POST_ratelimiting_per_account_failed_attempts(self):
        self.hs.config.rc_login_failed_attempts.burst_count = 5
        self.hs.config.rc_login_failed_attempts.per_second = 0.17

        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {"type": "m.id.user", "user": "kermit"},
                "password": "notamonkey",
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", LOGIN_URL, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"403", channel.result)

        # Since we're ratelimiting at 1 request/min, retry_after_ms should be lower
        # than 1min.
        self.assertTrue(retry_after_ms < 6000)

        self.reactor.advance(retry_after_ms / 1000.0)

        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "notamonkey",
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", LOGIN_URL, params)
        self.render(request)

        self.assertEquals(channel.result["code"], b"403", channel.result)

    @override_config({"session_lifetime": "24h"})
    def test_soft_logout(self):
        self.register_user("kermit", "monkey")

        # we shouldn't be able to make requests without an access token
        request, channel = self.make_request(b"GET", TEST_URL)
        self.render(request)
        self.assertEquals(channel.result["code"], b"401", channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_MISSING_TOKEN")

        # log in as normal
        params = {
            "type": "m.login.password",
            "identifier": {"type": "m.id.user", "user": "kermit"},
            "password": "monkey",
        }
        request, channel = self.make_request(b"POST", LOGIN_URL, params)
        self.render(request)

        self.assertEquals(channel.code, 200, channel.result)
        access_token = channel.json_body["access_token"]
        device_id = channel.json_body["device_id"]

        # we should now be able to make requests with the access token
        request, channel = self.make_request(
            b"GET", TEST_URL, access_token=access_token
        )
        self.render(request)
        self.assertEquals(channel.code, 200, channel.result)

        # time passes
        self.reactor.advance(24 * 3600)

        # ... and we should be soft-logouted
        request, channel = self.make_request(
            b"GET", TEST_URL, access_token=access_token
        )
        self.render(request)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        #
        # test behaviour after deleting the expired device
        #

        # we now log in as a different device
        access_token_2 = self.login("kermit", "monkey")

        # more requests with the expired token should still return a soft-logout
        self.reactor.advance(3600)
        request, channel = self.make_request(
            b"GET", TEST_URL, access_token=access_token
        )
        self.render(request)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], True)

        # ... but if we delete that device, it will be a proper logout
        self._delete_device(access_token_2, "kermit", "monkey", device_id)

        request, channel = self.make_request(
            b"GET", TEST_URL, access_token=access_token
        )
        self.render(request)
        self.assertEquals(channel.code, 401, channel.result)
        self.assertEquals(channel.json_body["errcode"], "M_UNKNOWN_TOKEN")
        self.assertEquals(channel.json_body["soft_logout"], False)

    def _delete_device(self, access_token, user_id, password, device_id):
        """Perform the UI-Auth to delete a device"""
        request, channel = self.make_request(
            b"DELETE", "devices/" + device_id, access_token=access_token
        )
        self.render(request)
        self.assertEquals(channel.code, 401, channel.result)
        # check it's a UI-Auth fail
        self.assertEqual(
            set(channel.json_body.keys()),
            {"flows", "params", "session"},
            channel.result,
        )

        auth = {
            "type": "m.login.password",
            # https://github.com/matrix-org/synapse/issues/5665
            # "identifier": {"type": "m.id.user", "user": user_id},
            "user": user_id,
            "password": password,
            "session": channel.json_body["session"],
        }

        request, channel = self.make_request(
            b"DELETE",
            "devices/" + device_id,
            access_token=access_token,
            content={"auth": auth},
        )
        self.render(request)
        self.assertEquals(channel.code, 200, channel.result)
