from synapse.rest.client.v2_alpha.register import RegisterRestServlet
from synapse.api.errors import SynapseError
from twisted.internet import defer
from mock import Mock
from tests import unittest
from tests.utils import mock_getRawHeaders
import json


class RegisterRestServletTestCase(unittest.TestCase):

    def setUp(self):
        # do the dance to hook up request data to self.request_data
        self.request_data = ""
        self.request = Mock(
            content=Mock(read=Mock(side_effect=lambda: self.request_data)),
            path='/_matrix/api/v2_alpha/register'
        )
        self.request.args = {}
        self.request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        self.appservice = None
        self.auth = Mock(get_appservice_by_req=Mock(
            side_effect=lambda x: self.appservice)
        )

        self.auth_result = (False, None, None, None)
        self.auth_handler = Mock(
            check_auth=Mock(side_effect=lambda x, y, z: self.auth_result),
            get_session_data=Mock(return_value=None)
        )
        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()
        self.device_handler = Mock()

        # do the dance to hook it up to the hs global
        self.handlers = Mock(
            registration_handler=self.registration_handler,
            identity_handler=self.identity_handler,
            login_handler=self.login_handler
        )
        self.hs = Mock()
        self.hs.hostname = "superbig~testing~thing.com"
        self.hs.get_auth = Mock(return_value=self.auth)
        self.hs.get_handlers = Mock(return_value=self.handlers)
        self.hs.get_auth_handler = Mock(return_value=self.auth_handler)
        self.hs.get_device_handler = Mock(return_value=self.device_handler)
        self.hs.config.enable_registration = True

        # init the thing we're testing
        self.servlet = RegisterRestServlet(self.hs)

    @defer.inlineCallbacks
    def test_POST_appservice_registration_valid(self):
        user_id = "@kermit:muppet"
        token = "kermits_access_token"
        self.request.args = {
            "access_token": "i_am_an_app_service"
        }
        self.request_data = json.dumps({
            "username": "kermit"
        })
        self.appservice = {
            "id": "1234"
        }
        self.registration_handler.appservice_register = Mock(
            return_value=user_id
        )
        self.auth_handler.get_access_token_for_user_id = Mock(
            return_value=token
        )

        (code, result) = yield self.servlet.on_POST(self.request)
        self.assertEquals(code, 200)
        det_data = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname
        }
        self.assertDictContainsSubset(det_data, result)

    @defer.inlineCallbacks
    def test_POST_appservice_registration_invalid(self):
        self.request.args = {
            "access_token": "i_am_an_app_service"
        }
        self.request_data = json.dumps({
            "username": "kermit"
        })
        self.appservice = None  # no application service exists
        result = yield self.servlet.on_POST(self.request)
        self.assertEquals(result, (401, None))

    def test_POST_bad_password(self):
        self.request_data = json.dumps({
            "username": "kermit",
            "password": 666
        })
        d = self.servlet.on_POST(self.request)
        return self.assertFailure(d, SynapseError)

    def test_POST_bad_username(self):
        self.request_data = json.dumps({
            "username": 777,
            "password": "monkey"
        })
        d = self.servlet.on_POST(self.request)
        return self.assertFailure(d, SynapseError)

    @defer.inlineCallbacks
    def test_POST_user_valid(self):
        user_id = "@kermit:muppet"
        token = "kermits_access_token"
        device_id = "frogfone"
        self.request_data = json.dumps({
            "username": "kermit",
            "password": "monkey",
            "device_id": device_id,
        })
        self.registration_handler.check_username = Mock(return_value=True)
        self.auth_result = (True, None, {
            "username": "kermit",
            "password": "monkey"
        }, None)
        self.registration_handler.register = Mock(return_value=(user_id, None))
        self.auth_handler.get_access_token_for_user_id = Mock(
            return_value=token
        )
        self.device_handler.check_device_registered = \
            Mock(return_value=device_id)

        (code, result) = yield self.servlet.on_POST(self.request)
        self.assertEquals(code, 200)
        det_data = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }
        self.assertDictContainsSubset(det_data, result)
        self.auth_handler.get_login_tuple_for_user_id(
            user_id, device_id=device_id, initial_device_display_name=None)

    def test_POST_disabled_registration(self):
        self.hs.config.enable_registration = False
        self.request_data = json.dumps({
            "username": "kermit",
            "password": "monkey"
        })
        self.registration_handler.check_username = Mock(return_value=True)
        self.auth_result = (True, None, {
            "username": "kermit",
            "password": "monkey"
        }, None)
        self.registration_handler.register = Mock(return_value=("@user:id", "t"))
        d = self.servlet.on_POST(self.request)
        return self.assertFailure(d, SynapseError)
