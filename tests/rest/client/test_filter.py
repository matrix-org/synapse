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

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.errors import Codes
from synapse.rest.client import filter
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest

PATH_PREFIX = "/_matrix/client/v2_alpha"


class FilterTestCase(unittest.HomeserverTestCase):

    user_id = "@apple:test"
    hijack_auth = True
    EXAMPLE_FILTER = {"room": {"timeline": {"types": ["m.room.message"]}}}
    EXAMPLE_FILTER_JSON = b'{"room": {"timeline": {"types": ["m.room.message"]}}}'
    servlets = [filter.register_servlets]

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.filtering = hs.get_filtering()
        self.store = hs.get_datastores().main

    def test_add_filter(self) -> None:
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % (self.user_id),
            self.EXAMPLE_FILTER_JSON,
        )

        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.json_body, {"filter_id": "0"})
        filter = self.get_success(
            self.store.get_user_filter(user_localpart="apple", filter_id=0)
        )
        self.pump()
        self.assertEqual(filter, self.EXAMPLE_FILTER)

    def test_add_filter_for_other_user(self) -> None:
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % ("@watermelon:test"),
            self.EXAMPLE_FILTER_JSON,
        )

        self.assertEqual(channel.result["code"], b"403")
        self.assertEqual(channel.json_body["errcode"], Codes.FORBIDDEN)

    def test_add_filter_non_local_user(self) -> None:
        _is_mine = self.hs.is_mine
        self.hs.is_mine = lambda target_user: False
        channel = self.make_request(
            "POST",
            "/_matrix/client/r0/user/%s/filter" % (self.user_id),
            self.EXAMPLE_FILTER_JSON,
        )

        self.hs.is_mine = _is_mine
        self.assertEqual(channel.result["code"], b"403")
        self.assertEqual(channel.json_body["errcode"], Codes.FORBIDDEN)

    def test_get_filter(self) -> None:
        filter_id = self.get_success(
            self.filtering.add_user_filter(
                user_localpart="apple", user_filter=self.EXAMPLE_FILTER
            )
        )
        self.reactor.advance(1)
        channel = self.make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/%s" % (self.user_id, filter_id)
        )

        self.assertEqual(channel.result["code"], b"200")
        self.assertEqual(channel.json_body, self.EXAMPLE_FILTER)

    def test_get_filter_non_existant(self) -> None:
        channel = self.make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/12382148321" % (self.user_id)
        )

        self.assertEqual(channel.result["code"], b"404")
        self.assertEqual(channel.json_body["errcode"], Codes.NOT_FOUND)

    # Currently invalid params do not have an appropriate errcode
    # in errors.py
    def test_get_filter_invalid_id(self) -> None:
        channel = self.make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/foobar" % (self.user_id)
        )

        self.assertEqual(channel.result["code"], b"400")

    # No ID also returns an invalid_id error
    def test_get_filter_no_id(self) -> None:
        channel = self.make_request(
            "GET", "/_matrix/client/r0/user/%s/filter/" % (self.user_id)
        )

        self.assertEqual(channel.result["code"], b"400")
