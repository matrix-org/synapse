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

import synapse.types
from synapse.api.errors import Codes
from synapse.http.server import JsonResource
from synapse.rest.client.v2_alpha import filter
from synapse.types import UserID
from synapse.util import Clock

from tests import unittest
from tests.server import (
    ThreadedMemoryReactorClock as MemoryReactorClock,
    make_request,
    render,
    setup_test_homeserver,
)

PATH_PREFIX = "/_matrix/client/v2_alpha"


class FilterTestCase(unittest.TestCase):

    USER_ID = "@apple:test"
    EXAMPLE_FILTER = {"room": {"timeline": {"types": ["m.room.message"]}}}
    EXAMPLE_FILTER_JSON = b'{"room": {"timeline": {"types": ["m.room.message"]}}}'
    TO_REGISTER = [filter]

    def setUp(self):
        self.clock = MemoryReactorClock()
        self.hs_clock = Clock(self.clock)

        self.hs = setup_test_homeserver(
            self.addCleanup, http_client=None, clock=self.hs_clock, reactor=self.clock
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
                UserID.from_string(self.USER_ID), 1, False, None
            )

        self.auth.get_user_by_access_token = get_user_by_access_token
        self.auth.get_user_by_req = get_user_by_req

        self.store = self.hs.get_datastore()
        self.filtering = self.hs.get_filtering()
        self.resource = JsonResource(self.hs)

        for r in self.TO_REGISTER:
            r.register_servlets(self.hs, self.resource)

    def test_add_filter(self):
        request, channel = make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % (self.USER_ID),
            self.EXAMPLE_FILTER_JSON,
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.json_body, {"filter_id": "0"})
        filter = self.store.get_user_filter(user_localpart="apple", filter_id=0)
        self.clock.advance(0)
        self.assertEquals(filter.result, self.EXAMPLE_FILTER)

    def test_add_filter_for_other_user(self):
        request, channel = make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % ("@watermelon:test"),
            self.EXAMPLE_FILTER_JSON,
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"403")
        self.assertEquals(channel.json_body["errcode"], Codes.FORBIDDEN)

    def test_add_filter_non_local_user(self):
        _is_mine = self.hs.is_mine
        self.hs.is_mine = lambda target_user: False
        request, channel = make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % (self.USER_ID),
            self.EXAMPLE_FILTER_JSON,
        )
        render(request, self.resource, self.clock)

        self.hs.is_mine = _is_mine
        self.assertEqual(channel.result["code"], b"403")
        self.assertEquals(channel.json_body["errcode"], Codes.FORBIDDEN)

    def test_get_filter(self):
        filter_id = self.filtering.add_user_filter(
            user_localpart="apple", user_filter=self.EXAMPLE_FILTER
        )
        self.clock.advance(1)
        filter_id = filter_id.result
        request, channel = make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/%s" % (self.USER_ID, filter_id)
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"200")
        self.assertEquals(channel.json_body, self.EXAMPLE_FILTER)

    def test_get_filter_non_existant(self):
        request, channel = make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/12382148321" % (self.USER_ID)
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"400")
        self.assertEquals(channel.json_body["errcode"], Codes.NOT_FOUND)

    # Currently invalid params do not have an appropriate errcode
    # in errors.py
    def test_get_filter_invalid_id(self):
        request, channel = make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/foobar" % (self.USER_ID)
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"400")

    # No ID also returns an invalid_id error
    def test_get_filter_no_id(self):
        request, channel = make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/" % (self.USER_ID)
        )
        render(request, self.resource, self.clock)

        self.assertEqual(channel.result["code"], b"400")
