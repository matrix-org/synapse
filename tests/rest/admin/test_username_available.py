# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from http import HTTPStatus

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.api.errors import Codes, SynapseError
from synapse.rest.client import login
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class UsernameAvailableTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets,
        login.register_servlets,
    ]
    url = "/_synapse/admin/v1/username_available"

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.register_user("admin", "pass", admin=True)
        self.admin_user_tok = self.login("admin", "pass")

        async def check_username(username: str) -> bool:
            if username == "allowed":
                return True
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User ID already taken.",
                errcode=Codes.USER_IN_USE,
            )

        handler = self.hs.get_registration_handler()
        handler.check_username = check_username

    def test_username_available(self) -> None:
        """
        The endpoint should return a HTTPStatus.OK response if the username does not exist
        """

        url = "%s?username=%s" % (self.url, "allowed")
        channel = self.make_request("GET", url, access_token=self.admin_user_tok)

        self.assertEqual(HTTPStatus.OK, channel.code, msg=channel.json_body)
        self.assertTrue(channel.json_body["available"])

    def test_username_unavailable(self) -> None:
        """
        The endpoint should return a HTTPStatus.OK response if the username does not exist
        """

        url = "%s?username=%s" % (self.url, "disallowed")
        channel = self.make_request("GET", url, access_token=self.admin_user_tok)

        self.assertEqual(
            HTTPStatus.BAD_REQUEST,
            channel.code,
            msg=channel.json_body,
        )
        self.assertEqual(channel.json_body["errcode"], "M_USER_IN_USE")
        self.assertEqual(channel.json_body["error"], "User ID already taken.")
