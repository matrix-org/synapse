# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from synapse.rest.client.v1.register import CreateUserRestServlet
from twisted.internet import defer
from mock import Mock
from tests import unittest
import json


class CreateUserServletTestCase(unittest.TestCase):

    def setUp(self):
        # do the dance to hook up request data to self.request_data
        self.request_data = ""
        self.request = Mock(
            content=Mock(read=Mock(side_effect=lambda: self.request_data)),
            path='/_matrix/client/api/v1/createUser'
        )
        self.request.args = {}

        self.appservice = None
        self.auth = Mock(get_appservice_by_req=Mock(
            side_effect=lambda x: defer.succeed(self.appservice))
        )

        self.auth_result = (False, None, None, None)
        self.auth_handler = Mock(
            check_auth=Mock(side_effect=lambda x, y, z: self.auth_result),
            get_session_data=Mock(return_value=None)
        )
        self.registration_handler = Mock()
        self.identity_handler = Mock()
        self.login_handler = Mock()

        # do the dance to hook it up to the hs global
        self.handlers = Mock(
            auth_handler=self.auth_handler,
            registration_handler=self.registration_handler,
            identity_handler=self.identity_handler,
            login_handler=self.login_handler
        )
        self.hs = Mock()
        self.hs.hostname = "supergbig~testing~thing.com"
        self.hs.get_auth = Mock(return_value=self.auth)
        self.hs.get_handlers = Mock(return_value=self.handlers)
        self.hs.config.enable_registration = True
        # init the thing we're testing
        self.servlet = CreateUserRestServlet(self.hs)

    @defer.inlineCallbacks
    def test_POST_createuser_with_valid_user(self):
        user_id = "@someone:interesting"
        token = "my token"
        self.request.args = {
            "access_token": "i_am_an_app_service"
        }
        self.request_data = json.dumps({
            "localpart": "someone",
            "displayname": "someone interesting",
            "duration_seconds": 200
        })

        self.registration_handler.get_or_create_user = Mock(
            return_value=(user_id, token)
        )

        (code, result) = yield self.servlet.on_POST(self.request)
        self.assertEquals(code, 200)

        det_data = {
            "user_id": user_id,
            "access_token": token,
            "home_server": self.hs.hostname
        }
        self.assertDictContainsSubset(det_data, result)
