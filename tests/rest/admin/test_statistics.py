# -*- coding: utf-8 -*-
# Copyright 2020 Dirk Klimpel
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

import json
from binascii import unhexlify
from typing import Any, Dict, List, Optional

import synapse.rest.admin
from synapse.api.errors import Codes
from synapse.rest.client.v1 import login, profile

from tests import unittest


class UserMediaStatisticsTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
        profile.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.media_repo = hs.get_media_repository_resource()

        self.admin_user = self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        self.other_user = self.register_user("user", "pass")
        self.other_user_tok = self.login("user", "pass")

        self.url = "/_synapse/admin/v1/statistics/users/media"

    def test_no_auth(self):
        """
        Try to list users without authentication.
        """
        request, channel = self.make_request("GET", self.url, b"{}")
        self.render(request)

        self.assertEqual(401, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.MISSING_TOKEN, channel.json_body["errcode"])

    def test_requester_is_no_admin(self):
        """
        If the user is not a server admin, an error 403 is returned.
        """
        request, channel = self.make_request(
            "GET", self.url, json.dumps({}), access_token=self.other_user_tok,
        )
        self.render(request)

        self.assertEqual(403, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.FORBIDDEN, channel.json_body["errcode"])

    def test_invalid_parameter(self):
        """
        If parameters are invalid, an error is returned.
        """
        # unkown order_by
        request, channel = self.make_request(
            "GET", self.url + "?order_by=bar", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual("Unknown value for order_by: bar", channel.json_body["error"])

        # negative from
        request, channel = self.make_request(
            "GET", self.url + "?from=-5", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter from must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # negative limit
        request, channel = self.make_request(
            "GET", self.url + "?limit=-5", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter limit must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # negative from_ts
        request, channel = self.make_request(
            "GET", self.url + "?from_ts=-1234", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter from_ts must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # negative until_ts
        request, channel = self.make_request(
            "GET", self.url + "?until_ts=-1234", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter until_ts must be a string representing a positive integer.",
            channel.json_body["error"],
        )

        # until_ts smaller from_ts
        request, channel = self.make_request(
            "GET",
            self.url + "?from_ts=10&until_ts=5",
            access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter until_ts must be greater than from_ts.",
            channel.json_body["error"],
        )

        # empty search term
        request, channel = self.make_request(
            "GET", self.url + "?search_term=", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual(
            "Query parameter search_term cannot be an empty string.",
            channel.json_body["error"],
        )

        # invalid search order
        request, channel = self.make_request(
            "GET", self.url + "?dir=bar", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(400, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(Codes.INVALID_PARAM, channel.json_body["errcode"])
        self.assertEqual("Unknown direction: bar", channel.json_body["error"])

    def test_limit(self):
        """
        Testing list of media with limit
        """
        self._create_users_with_media(10, 2)

        request, channel = self.make_request(
            "GET", self.url + "?limit=5", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 10)
        self.assertEqual(len(channel.json_body["users_media"]), 5)
        self.assertEqual(channel.json_body["next_token"], 5)
        self._check_fields(channel.json_body["users_media"])

    def test_from(self):
        """
        Testing list of media with a defined starting point (from)
        """
        self._create_users_with_media(20, 2)

        request, channel = self.make_request(
            "GET", self.url + "?from=5", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(len(channel.json_body["users_media"]), 15)
        self.assertNotIn("next_token", channel.json_body)
        self._check_fields(channel.json_body["users_media"])

    def test_limit_and_from(self):
        """
        Testing list of media with a defined starting point and limit
        """
        self._create_users_with_media(20, 2)

        request, channel = self.make_request(
            "GET", self.url + "?from=5&limit=10", access_token=self.admin_user_tok,
        )
        self.render(request)

        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)
        self.assertEqual(channel.json_body["next_token"], 15)
        self.assertEqual(len(channel.json_body["users_media"]), 10)
        self._check_fields(channel.json_body["users_media"])

    def test_order_by(self):
        """
        Testing order list with parameter `order_by`
        """

        # create users
        userA = self.register_user("user_a", "pass")
        userA_tok = self.login("user_a", "pass")
        self._set_displayname(userA, userA_tok, "UserZ")
        self._create_media(userA_tok, 1)

        userB = self.register_user("user_b", "pass")
        userB_tok = self.login("user_b", "pass")
        self._set_displayname(userB, userB_tok, "UserY")
        self._create_media(userB_tok, 3)

        userC = self.register_user("user_c", "pass")
        userC_tok = self.login("user_c", "pass")
        self._set_displayname(userC, userC_tok, "UserX")
        self._create_media(userC_tok, 2)

        # order by user_id
        self._order_test("user_id", ["@user_a:test", "@user_b:test", "@user_c:test"])
        self._order_test(
            "user_id", ["@user_a:test", "@user_b:test", "@user_c:test"], "f",
        )
        self._order_test(
            "user_id", ["@user_c:test", "@user_b:test", "@user_a:test"], "b",
        )

        # order by displayname
        self._order_test(
            "displayname", ["@user_c:test", "@user_b:test", "@user_a:test"]
        )
        self._order_test(
            "displayname", ["@user_c:test", "@user_b:test", "@user_a:test"], "f",
        )
        self._order_test(
            "displayname", ["@user_a:test", "@user_b:test", "@user_c:test"], "b",
        )

        # order by media_length
        self._order_test(
            "media_length", ["@user_a:test", "@user_c:test", "@user_b:test"],
        )
        self._order_test(
            "media_length", ["@user_a:test", "@user_c:test", "@user_b:test"], "f",
        )
        self._order_test(
            "media_length", ["@user_b:test", "@user_c:test", "@user_a:test"], "b",
        )

        # order by media_count
        self._order_test(
            "media_count", ["@user_a:test", "@user_c:test", "@user_b:test"],
        )
        self._order_test(
            "media_count", ["@user_a:test", "@user_c:test", "@user_b:test"], "f",
        )
        self._order_test(
            "media_count", ["@user_b:test", "@user_c:test", "@user_a:test"], "b",
        )

    def test_from_until_ts(self):
        """
        Testing filter by time with parameters `from_ts` and `until_ts`
        """
        # create media earlier than `ts1` to ensure that `from_ts` is working
        self._create_media(self.other_user_tok, 3)
        self.pump(1)
        ts1 = self.clock.time_msec()

        # list all media when filter is not set
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["users_media"][0]["media_count"], 3)

        # filter media starting at `ts1` after creating first media
        # result is 0
        request, channel = self.make_request(
            "GET", self.url + "?from_ts=%s" % (ts1,), access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 0)

        self._create_media(self.other_user_tok, 3)
        self.pump(1)
        ts2 = self.clock.time_msec()
        # create media after `ts2` to ensure that `until_ts` is working
        self._create_media(self.other_user_tok, 3)

        # filter media between `ts1` and `ts2`
        request, channel = self.make_request(
            "GET",
            self.url + "?from_ts=%s&until_ts=%s" % (ts1, ts2),
            access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["users_media"][0]["media_count"], 3)

        # filter media until `ts2` and earlier than creating last media
        request, channel = self.make_request(
            "GET", self.url + "?until_ts=%s" % (ts2,), access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["users_media"][0]["media_count"], 6)

    def test_search_term(self):
        self._create_users_with_media(20, 1)

        # check without filter get all users
        request, channel = self.make_request(
            "GET", self.url, access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 20)

        # filter user 1 and 10-19 by `user_id`
        request, channel = self.make_request(
            "GET",
            self.url + "?search_term=foo_user_1",
            access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 11)

        # set a displayname for one user
        self._create_media(self.other_user_tok, 1)
        self._set_displayname(self.other_user, self.other_user_tok, "UserZ")

        # filter on this user in `displayname`
        request, channel = self.make_request(
            "GET", self.url + "?search_term=Z", access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["users_media"][0]["displayname"], "UserZ")
        self.assertEqual(channel.json_body["total"], 1)

        # filter and get empty result
        request, channel = self.make_request(
            "GET", self.url + "?search_term=foobar", access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, int(channel.result["code"]), msg=channel.result["body"])
        self.assertEqual(channel.json_body["total"], 0)

    def _create_users_with_media(self, number_users: int, media_per_user: int):
        """
        Create a number of users with a number of media
        Args:
            number_users: Number of users to be created
            media_per_user: Number of media to be created for each user
        """
        for i in range(number_users):
            self.register_user("foo_user_%s" % i, "pass")
            user_tok = self.login("foo_user_%s" % i, "pass")
            self._create_media(user_tok, media_per_user)

    def _create_media(self, user_token: str, number_media: int):
        """
        Create a number of media for a specific user
        Args:
            user_token: Access token of the user
            number_media: Number of media to be created for the user
        """
        upload_resource = self.media_repo.children[b"upload"]
        for i in range(number_media):
            # file size is 67 Byte
            image_data = unhexlify(
                b"89504e470d0a1a0a0000000d4948445200000001000000010806"
                b"0000001f15c4890000000a49444154789c63000100000500010d"
                b"0a2db40000000049454e44ae426082"
            )

            # Upload some media into the room
            self.helper.upload_media(
                upload_resource, image_data, tok=user_token, expect_code=200
            )

    def _check_fields(self, content: List[Dict[str, Any]]):
        """Checks that all attributes are present in content
        Args:
            content: List that is checked for content
        """
        for c in content:
            self.assertIn("user_id", c)
            self.assertIn("displayname", c)
            self.assertIn("media_count", c)
            self.assertIn("media_length", c)

    def _order_test(
        self, order_type: str, expected_user_list: List[str], dir: Optional[str] = None
    ):
        """Request the list of users in a certain order. Assert that order is what
        we expect
        Args:
            order_type: The type of ordering to give the server
            expected_user_list: The list of user_ids in the order we expect to get
                back from the server
            dir: The direction of ordering to give the server
        """

        url = self.url + "?order_by=%s" % (order_type,)
        if dir is not None:
            if dir in ("b", "f"):
                url += "&dir=%s" % (dir,)
        request, channel = self.make_request(
            "GET", url.encode("ascii"), access_token=self.admin_user_tok,
        )
        self.render(request)
        self.assertEqual(200, channel.code, msg=channel.json_body)
        self.assertEqual(channel.json_body["total"], len(expected_user_list))

        returned_order = [row["user_id"] for row in channel.json_body["users_media"]]
        self.assertListEqual(expected_user_list, returned_order)
        self._check_fields(channel.json_body["users_media"])

    def _set_displayname(self, user_id: str, accesss_token: str, displayname: str):
        """Set a displayname of a specific user
        Args:
            user_id: user ID of the user whose displayname should be set
            access_token: Access token of the user whose displayname should be set
            displayname: new displayname to be set
        """
        request, channel = self.make_request(
            "PUT",
            "/profile/%s/displayname" % (user_id,),
            content=json.dumps({"displayname": displayname}),
            access_token=accesss_token,
        )
        self.render(request)
        self.assertEqual(200, channel.code, msg=channel.json_body)
