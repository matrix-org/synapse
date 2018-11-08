import json

from mock import Mock

from twisted.python import failure

from synapse.api.errors import InteractiveAuthIncompleteError
from synapse.rest.client.v2_alpha.register import register_servlets

from tests import unittest


class RegisterRestServletTestCase(unittest.HomeserverTestCase):

    servlets = [register_servlets]

    def make_homeserver(self, reactor, clock):

        self.url = b"/_matrix/client/r0/register"

        self.appservice = None
        self.auth = Mock(
            get_appservice_by_req=Mock(side_effect=lambda x: self.appservice)
        )

        self.auth_result = failure.Failure(InteractiveAuthIncompleteError(None))
        self.auth_handler = Mock(
            check_auth=Mock(side_effect=lambda x, y, z: self.auth_result),
            get_session_data=Mock(return_value=None),
        )
        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()
        self.device_handler = Mock()
        self.device_handler.check_device_registered = Mock(return_value="FAKE")

        self.datastore = Mock(return_value=Mock())
        self.datastore.get_current_state_deltas = Mock(return_value=[])

        # do the dance to hook it up to the hs global
        self.handlers = Mock(
            registration_handler=self.registration_handler,
            identity_handler=self.identity_handler,
            login_handler=self.login_handler,
        )
        self.hs = self.setup_test_homeserver()
        self.hs.get_auth = Mock(return_value=self.auth)
        self.hs.get_handlers = Mock(return_value=self.handlers)
        self.hs.get_auth_handler = Mock(return_value=self.auth_handler)
        self.hs.get_device_handler = Mock(return_value=self.device_handler)
        self.hs.get_datastore = Mock(return_value=self.datastore)
        self.hs.config.enable_registration = True
        self.hs.config.registrations_require_3pid = []
        self.hs.config.auto_join_rooms = []

        return self.hs

    def test_POST_appservice_registration_valid(self):
        user_id = "@kermit:muppet"
        token = "kermits_access_token"
        self.appservice = {"id": "1234"}
        self.registration_handler.appservice_register = Mock(return_value=user_id)
        self.auth_handler.get_access_token_for_user_id = Mock(return_value=token)
        request_data = json.dumps({"username": "kermit"})

        request, channel = self.make_request(
            b"POST", self.url + b"?access_token=i_am_an_app_service", request_data
        )
        self.render(request)

        self.assertEquals(channel.result["code"], b"200", channel.result)
        det_data = {
            "user_id": user_id,
            "access_token": token,
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
        user_id = "@kermit:muppet"
        token = "kermits_access_token"
        device_id = "frogfone"
        request_data = json.dumps(
            {"username": "kermit", "password": "monkey", "device_id": device_id}
        )
        self.registration_handler.check_username = Mock(return_value=True)
        self.auth_result = (None, {"username": "kermit", "password": "monkey"}, None)
        self.registration_handler.register = Mock(return_value=(user_id, None))
        self.auth_handler.get_access_token_for_user_id = Mock(return_value=token)
        self.device_handler.check_device_registered = Mock(return_value=device_id)

        request, channel = self.make_request(b"POST", self.url, request_data)
        self.render(request)

        det_data = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertEquals(channel.result["code"], b"200", channel.result)
        self.assertDictContainsSubset(det_data, channel.json_body)
        self.auth_handler.get_login_tuple_for_user_id(
            user_id, device_id=device_id, initial_device_display_name=None
        )

    def test_POST_disabled_registration(self):
        self.hs.config.enable_registration = False
        request_data = json.dumps({"username": "kermit", "password": "monkey"})
        self.registration_handler.check_username = Mock(return_value=True)
        self.auth_result = (None, {"username": "kermit", "password": "monkey"}, None)
        self.registration_handler.register = Mock(return_value=("@user:id", "t"))

        request, channel = self.make_request(b"POST", self.url, request_data)
        self.render(request)

        self.assertEquals(channel.result["code"], b"403", channel.result)
        self.assertEquals(channel.json_body["error"], "Registration has been disabled")

    def test_POST_guest_registration(self):
        user_id = "a@b"
        self.hs.config.macaroon_secret_key = "test"
        self.hs.config.allow_guest_access = True
        self.registration_handler.register = Mock(return_value=(user_id, None))

        request, channel = self.make_request(b"POST", self.url + b"?kind=guest", b"{}")
        self.render(request)

        det_data = {
            "user_id": user_id,
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
