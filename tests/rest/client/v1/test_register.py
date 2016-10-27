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
from tests.utils import mock_getRawHeaders
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
        self.request.requestHeaders.getRawHeaders = mock_getRawHeaders()

        self.registration_handler = Mock()

        self.appservice = Mock(sender="@as:test")
        self.datastore = Mock(
            get_app_service_by_token=Mock(return_value=self.appservice)
        )

        # do the dance to hook things up to the hs global
        handlers = Mock(
            registration_handler=self.registration_handler,
        )
        self.hs = Mock()
        self.hs.hostname = "superbig~testing~thing.com"
        self.hs.get_datastore = Mock(return_value=self.datastore)
        self.hs.get_handlers = Mock(return_value=handlers)
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
