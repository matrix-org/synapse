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

from twisted.internet import defer

from tests import unittest

from synapse.rest.client.v2_alpha import filter

from synapse.api.errors import Codes

import synapse.types

from synapse.types import UserID

from ....utils import MockHttpResource, setup_test_homeserver

PATH_PREFIX = "/_matrix/client/v2_alpha"


class FilterTestCase(unittest.TestCase):

    USER_ID = "@apple:test"
    EXAMPLE_FILTER = {"type": ["m.*"]}
    EXAMPLE_FILTER_JSON = '{"type": ["m.*"]}'
    TO_REGISTER = [filter]

    @defer.inlineCallbacks
    def setUp(self):
        self.mock_resource = MockHttpResource(prefix=PATH_PREFIX)

        self.hs = yield setup_test_homeserver(
            http_client=None,
            resource_for_client=self.mock_resource,
            resource_for_federation=self.mock_resource,
        )

        self.auth = self.hs.get_auth()

        def get_user_by_access_token(token=None, allow_guest=False):
            return {
                "user": UserID.from_string(self.USER_ID),
                "token_id": 1,
                "is_guest": False,
            }

        def get_user_by_req(request, allow_guest=False, rights="access"):
            return synapse.types.create_requester(
                UserID.from_string(self.USER_ID), 1, False, None)

        self.auth.get_user_by_access_token = get_user_by_access_token
        self.auth.get_user_by_req = get_user_by_req

        self.store = self.hs.get_datastore()
        self.filtering = self.hs.get_filtering()

        for r in self.TO_REGISTER:
            r.register_servlets(self.hs, self.mock_resource)

    @defer.inlineCallbacks
    def test_add_filter(self):
        (code, response) = yield self.mock_resource.trigger(
            "POST", "/user/%s/filter" % (self.USER_ID), self.EXAMPLE_FILTER_JSON
        )
        self.assertEquals(200, code)
        self.assertEquals({"filter_id": "0"}, response)
        filter = yield self.store.get_user_filter(
            user_localpart='apple',
            filter_id=0,
        )
        self.assertEquals(filter, self.EXAMPLE_FILTER)

    @defer.inlineCallbacks
    def test_add_filter_for_other_user(self):
        (code, response) = yield self.mock_resource.trigger(
            "POST", "/user/%s/filter" % ('@watermelon:test'), self.EXAMPLE_FILTER_JSON
        )
        self.assertEquals(403, code)
        self.assertEquals(response['errcode'], Codes.FORBIDDEN)

    @defer.inlineCallbacks
    def test_add_filter_non_local_user(self):
        _is_mine = self.hs.is_mine
        self.hs.is_mine = lambda target_user: False
        (code, response) = yield self.mock_resource.trigger(
            "POST", "/user/%s/filter" % (self.USER_ID), self.EXAMPLE_FILTER_JSON
        )
        self.hs.is_mine = _is_mine
        self.assertEquals(403, code)
        self.assertEquals(response['errcode'], Codes.FORBIDDEN)

    @defer.inlineCallbacks
    def test_get_filter(self):
        filter_id = yield self.filtering.add_user_filter(
            user_localpart='apple',
            user_filter=self.EXAMPLE_FILTER
        )
        (code, response) = yield self.mock_resource.trigger_get(
            "/user/%s/filter/%s" % (self.USER_ID, filter_id)
        )
        self.assertEquals(200, code)
        self.assertEquals(self.EXAMPLE_FILTER, response)

    @defer.inlineCallbacks
    def test_get_filter_non_existant(self):
        (code, response) = yield self.mock_resource.trigger_get(
            "/user/%s/filter/12382148321" % (self.USER_ID)
        )
        self.assertEquals(400, code)
        self.assertEquals(response['errcode'], Codes.NOT_FOUND)

    # Currently invalid params do not have an appropriate errcode
    # in errors.py
    @defer.inlineCallbacks
    def test_get_filter_invalid_id(self):
        (code, response) = yield self.mock_resource.trigger_get(
            "/user/%s/filter/foobar" % (self.USER_ID)
        )
        self.assertEquals(400, code)

    # No ID also returns an invalid_id error
    @defer.inlineCallbacks
    def test_get_filter_no_id(self):
        (code, response) = yield self.mock_resource.trigger_get(
            "/user/%s/filter/" % (self.USER_ID)
        )
        self.assertEquals(400, code)
