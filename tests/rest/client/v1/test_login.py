import json

from synapse.api.constants import LoginType
from synapse.api.errors import HttpResponseException
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import register

from tests import unittest


class LoginRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [
        register.register_servlets,
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
        self.hs.config.rc_login_request_per_address_burst_count = 5
        self.hs.config.rc_login_requests_per_address_per_second = 0.17

        # Create different users so we're sure not to be bothered by the per-user
        # ratelimiter.
        for i in range(0, 6):
            self.create_user("kermit" + str(i))

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

    def test_POST_ratelimiting_per_user(self):
        self.hs.config.rc_login_request_per_user_burst_count = 5
        self.hs.config.rc_login_requests_per_user_per_second = 0.17

        self.create_user("kermit")

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

    def create_user(self, localpart):
        request_data = json.dumps(
            {
                "username": localpart,
                "password": "monkey",
                "device_id": "frogfone",
                "auth": {"type": LoginType.DUMMY},
            }
        )
        request_url = b"/_matrix/client/r0/register"
        request, channel = self.make_request(b"POST", request_url, request_data)
        self.render(request)

        if channel.code != 200:
            raise HttpResponseException(
                channel.code, channel.result["reason"], channel.result["body"]
            ).to_synapse_error()
