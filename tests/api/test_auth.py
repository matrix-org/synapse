# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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
from tests import unittest
from twisted.internet import defer

from mock import Mock

from synapse.api.auth import Auth
from synapse.api.errors import AuthError


class AuthTestCase(unittest.TestCase):

    def setUp(self):
        self.state_handler = Mock()
        self.store = Mock()

        self.hs = Mock()
        self.hs.get_datastore = Mock(return_value=self.store)
        self.hs.get_state_handler = Mock(return_value=self.state_handler)
        self.auth = Auth(self.hs)

        self.test_user = "@foo:bar"
        self.test_token = "_test_token_"

    @defer.inlineCallbacks
    def test_get_user_by_req_user_valid_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        user_info = {
            "name": self.test_user,
            "device_id": "nothing",
            "token_id": "ditto",
            "admin": False
        }
        self.store.get_user_by_token = Mock(return_value=user_info)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        (user, info) = yield self.auth.get_user_by_req(request)
        self.assertEquals(user.to_string(), self.test_user)

    def test_get_user_by_req_user_bad_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    def test_get_user_by_req_user_missing_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        user_info = {
            "name": self.test_user,
            "device_id": "nothing",
            "token_id": "ditto",
            "admin": False
        }
        self.store.get_user_by_token = Mock(return_value=user_info)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    @defer.inlineCallbacks
    def test_get_user_by_req_appservice_valid_token(self):
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        (user, info) = yield self.auth.get_user_by_req(request)
        self.assertEquals(user.to_string(), self.test_user)

    def test_get_user_by_req_appservice_bad_token(self):
        self.store.get_app_service_by_token = Mock(return_value=None)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    def test_get_user_by_req_appservice_missing_token(self):
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)

    @defer.inlineCallbacks
    def test_get_user_by_req_appservice_valid_token_valid_user_id(self):
        masquerading_user_id = "@doppelganger:matrix.org"
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        app_service.is_interested_in_user = Mock(return_value=True)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.args["user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        (user, info) = yield self.auth.get_user_by_req(request)
        self.assertEquals(user.to_string(), masquerading_user_id)

    def test_get_user_by_req_appservice_valid_token_bad_user_id(self):
        masquerading_user_id = "@doppelganger:matrix.org"
        app_service = Mock(token="foobar", url="a_url", sender=self.test_user)
        app_service.is_interested_in_user = Mock(return_value=False)
        self.store.get_app_service_by_token = Mock(return_value=app_service)
        self.store.get_user_by_token = Mock(return_value=None)

        request = Mock(args={})
        request.args["access_token"] = [self.test_token]
        request.args["user_id"] = [masquerading_user_id]
        request.requestHeaders.getRawHeaders = Mock(return_value=[""])
        d = self.auth.get_user_by_req(request)
        self.failureResultOf(d, AuthError)
