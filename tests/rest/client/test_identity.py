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

from mock import Mock

from twisted.internet import defer

import synapse.rest.admin
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import account

from tests import unittest


class IdentityDisabledTestCase(unittest.HomeserverTestCase):
    """Tests that 3PID lookup attempts fail when the HS's config disallows them."""

    servlets = [
        account.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config["trusted_third_party_id_servers"] = [
            "testis",
        ]
        config["enable_3pid_lookup"] = False
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
        url = ("/_matrix/client/unstable/account/3pid/lookup"
               "?id_server=testis&medium=email&address=foo@bar.baz")
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


class IdentityEnabledTestCase(unittest.HomeserverTestCase):
    """Tests that 3PID lookup attempts succeed when the HS's config allows them."""

    servlets = [
        account.register_servlets,
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):

        config = self.default_config()
        config["enable_3pid_lookup"] = True
        config["trusted_third_party_id_servers"] = [
            "testis",
        ]

        mock_http_client = Mock(spec=[
            "get_json",
            "post_json_get_json",
        ])
        mock_http_client.get_json.return_value = defer.succeed((200, "{}"))
        mock_http_client.post_json_get_json.return_value = defer.succeed((200, "{}"))

        self.hs = self.setup_test_homeserver(
            config=config,
            simple_http_client=mock_http_client,
        )

        return self.hs

    def prepare(self, reactor, clock, hs):
        self.user_id = self.register_user("kermit", "monkey")
        self.tok = self.login("kermit", "monkey")

    def test_3pid_invite_enabled(self):
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
        request_url = ("/rooms/%s/invite" % (room_id)).encode('ascii')
        request, channel = self.make_request(
            b"POST", request_url, request_data, access_token=self.tok,
        )
        self.render(request)

        get_json = self.hs.get_simple_http_client().get_json
        get_json.assert_called_once_with(
            "https://testis/_matrix/identity/api/v1/lookup",
            {
                "address": "test@example.com",
                "medium": "email",
            },
        )

    def test_3pid_lookup_enabled(self):
        url = ("/_matrix/client/unstable/account/3pid/lookup"
               "?id_server=testis&medium=email&address=foo@bar.baz")
        request, channel = self.make_request("GET", url, access_token=self.tok)
        self.render(request)

        get_json = self.hs.get_simple_http_client().get_json
        get_json.assert_called_once_with(
            "https://testis/_matrix/identity/api/v1/lookup",
            {
                "address": "foo@bar.baz",
                "medium": "email",
            },
        )

    def test_3pid_bulk_lookup_enabled(self):
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

        post_json = self.hs.get_simple_http_client().post_json_get_json
        post_json.assert_called_once_with(
            "https://testis/_matrix/identity/api/v1/bulk_lookup",
            {
                "threepids": [
                    [
                        "email",
                        "foo@bar.baz"
                    ],
                    [
                        "email",
                        "john.doe@matrix.org"
                    ]
                ],
            },
        )
