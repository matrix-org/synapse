import json

from synapse.rest.client.v1 import admin, login

from tests import unittest


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        self.url = b"/_matrix/client/r0/login"

        self.hs = self.setup_test_homeserver()
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []
        self.hs.config.enable_registration_captcha = False

        return self.hs

    def test_POST_ratelimiting_per_address(self):
        self.hs.config.rc_login.address.burst_count = 5
        self.hs.config.rc_login.address.per_second = 0.17

        # Create different users so we're sure not to be bothered by the per-user
        # ratelimiter.
        for i in range(0, 6):
            self.register_user("kermit" + str(i), "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "kermit" + str(i),
                },
                "password": "monkey",
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", self.url, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.)

        params = {
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "kermit" + str(i),
            },
            "password": "monkey",
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", self.url, params)
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)

    def test_POST_ratelimiting_per_account(self):
        self.hs.config.rc_login.account.burst_count = 5
        self.hs.config.rc_login.account.per_second = 0.17

        self.register_user("kermit", "monkey")

        for i in range(0, 6):
            params = {
                "type": "m.login.password",
                "identifier": {
                    "type": "m.id.user",
                    "user": "kermit",
                },
                "password": "monkey",
            }
            request_data = json.dumps(params)
            request, channel = self.make_request(b"POST", self.url, request_data)
            self.render(request)

            if i == 5:
                self.assertEquals(channel.result["code"], b"429", channel.result)
                retry_after_ms = int(channel.json_body["retry_after_ms"])
            else:
                self.assertEquals(channel.result["code"], b"200", channel.result)

        self.reactor.advance(retry_after_ms / 1000.)

        params = {
            "type": "m.login.password",
            "identifier": {
                "type": "m.id.user",
                "user": "kermit",
            },
            "password": "monkey",
        }
        request_data = json.dumps(params)
        request, channel = self.make_request(b"POST", self.url, params)
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)
