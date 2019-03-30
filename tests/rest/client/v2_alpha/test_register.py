import json

from synapse.api.constants import LoginType
from synapse.appservice import ApplicationService
from synapse.rest.client.v2_alpha.register import register_servlets

from tests import unittest


class RegisterRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [register_servlets]

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
            as_token, self.hs.config.server_name,
            id="1234",
            namespaces={
                "users": [{"regex": r"@as_user.*", "exclusive": True}],
            },
        )

        self.hs.get_datastore().services_cache.append(appservice)
        request_data = json.dumps({"username": "as_user_kermit"})

        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)
        det_data = {
            "user_id": user_id,
            "home_server": self.hs.hostname,
        }
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

        det_data = {
            "home_server": self.hs.hostname,
            "device_id": "guest_device",
        }
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

        self.reactor.advance(retry_after_ms / 1000.)

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

        self.reactor.advance(retry_after_ms / 1000.)

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)
