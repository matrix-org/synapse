# -*- coding: utf-8 -*-
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

import json

from synapse.rest.client.v1 import admin, login, room
from synapse.rest.client.v2_alpha import account

from tests import unittest


class IdentityTestCase(unittest.HomeserverTestCase):

    servlets = [
        account.register_servlets,
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config.enable_3pid_lookup = False
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    def prepare(self, reactor, clock, hs):
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

    def test_3pid_invite_disabled(self):
        request, channel = self.make_request(
            b"POST", "/createRoom", b"{}", access_token=self.tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"200", channel.result)
        room_id = channel.json_body["room_id"]

        params = {
            "id_server": "testis",
            "medium": "email",
            "address": "test@example.com",
        }
        request_data = json.dumps(params)
        request_url = (
            "/rooms/%s/invite" % (room_id)
        ).encode('ascii')
        request, channel = self.make_request(
            b"POST", request_url, request_data, access_token=self.tok,
        )
        self.render(request)
        self.assertEquals(channel.result["code"], b"403", channel.result)

    def test_3pid_lookup_disabled(self):
        url = "/_matrix/client/unstable/account/3pid/lookup?id_server=testis&medium=email&address=foo@bar.baz"
        request, channel = self.make_request("GET", url, access_token=self.tok)
        self.render(request)
        self.assertEqual(channel.result["code"], b"403", channel.result)

    def test_3pid_bulk_lookup_disabled(self):
        url = "/_matrix/client/unstable/account/3pid/bulk_lookup"
        data = {
            "id_server": "testis",
            "threepids": [
                [
                    "email",
                    "foo@bar.baz"
                ],
                [
                    "email",
                    "john.doe@matrix.org"
                ]
            ]
        }
        request_data = json.dumps(data)
        request, channel = self.make_request(
            "POST", url, request_data, access_token=self.tok,
        )
        self.render(request)
        self.assertEqual(channel.result["code"], b"403", channel.result)
