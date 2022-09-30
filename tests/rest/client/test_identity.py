# Copyright 2019 New Vector Ltd
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
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class IdentityTestCase(unittest.HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        config = self.default_config()
        config["enable_3pid_lookup"] = False
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def test_3pid_lookup_disabled(self) -> None:
        self.hs.config.registration.enable_3pid_lookup = False

        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        channel = self.make_request(b"POST", "/createRoom", b"{}", access_token=tok)
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        room_id = channel.json_body["room_id"]

        request_data = {
            "id_server": "testis",
            "medium": "email",
            "address": "test@example.com",
            "id_access_token": tok,
        }
        request_url = ("/rooms/%s/invite" % (room_id)).encode("ascii")
        channel = self.make_request(
            b"POST", request_url, request_data, access_token=tok
        )
        self.assertEqual(channel.code, HTTPStatus.FORBIDDEN, channel.result)
