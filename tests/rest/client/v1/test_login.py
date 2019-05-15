import json

import synapse.rest.admin
from synapse.rest.client.v1 import login

from tests import unittest

LOGIN_URL = b"/_matrix/client/r0/login"


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
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
