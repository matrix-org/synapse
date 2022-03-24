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
from unittest.mock import Mock

from twisted.test.proto_helpers import MemoryReactor

import synapse.rest.admin
from synapse.http.client import SimpleHttpClient
from synapse.rest.client import login, register, room
from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest
from tests.test_utils import make_awaitable


class IdentityTestCase(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        register.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:

        config = self.default_config()
        self.hs = self.setup_test_homeserver(config=config)

        return self.hs

    @unittest.override_config({"enable_3pid_lookup": False})
    def test_3pid_lookup_disabled(self) -> None:
        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        channel = self.make_request(b"POST", "/createRoom", b"{}", access_token=tok)
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        room_id = channel.json_body["room_id"]

        self._send_threepid_invite(
            id_server="vip.example.com",
            address="test@example.com",
            room_id=room_id,
            tok=tok,
            expected_status=HTTPStatus.FORBIDDEN,
        )

    @unittest.override_config(
        {
            "rewrite_identity_server_base_urls": {
                "vip.example.com": "http://vip-int.example.com",
            }
        }
    )
    def test_rewrite_is_base_url(self) -> None:
        """Tests that base URLs for identity services are correctly rewritten."""
        mock_client = Mock(spec=SimpleHttpClient)
        mock_client.post_json_get_json = Mock(
            return_value=make_awaitable(
                {
                    "token": "sometoken",
                    "public_key": "somekey",
                    "public_keys": [],
                    "display_name": "foo",
                }
            )
        )
        mock_client.get_json = Mock(return_value=make_awaitable({}))

        self.hs.get_identity_handler().blacklisting_http_client = mock_client

        self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")

        channel = self.make_request(b"POST", "/createRoom", b"{}", access_token=tok)
        self.assertEqual(channel.code, HTTPStatus.OK, channel.result)
        room_id = channel.json_body["room_id"]

        # Send a 3PID invite, and check that the base URL for the identity server has been
        # correctly rewritten.
        self._send_threepid_invite(
            id_server="vip.example.com",
            address="test@example.com",
            room_id=room_id,
            tok=tok,
            expected_status=HTTPStatus.OK,
        )

        mock_client.post_json_get_json.assert_called_once()
        args = mock_client.post_json_get_json.call_args[0]

        self.assertTrue(args[0].startswith("http://vip-int.example.com"))

        # Send another 3PID invite, this time to an identity server that doesn't need
        # rewriting, and check that the base URL hasn't been rewritten (apart from adding
        # an HTTPS protocol scheme).
        self._send_threepid_invite(
            id_server="testis",
            address="test@example.com",
            room_id=room_id,
            tok=tok,
            expected_status=HTTPStatus.OK,
        )

        self.assertEqual(mock_client.post_json_get_json.call_count, 2)
        args = mock_client.post_json_get_json.call_args[0]

        self.assertTrue(args[0].startswith("https://testis"))

    def _send_threepid_invite(
        self, id_server: str, address: str, room_id: str, tok: str, expected_status: int
    ) -> None:
        """Try to send a 3PID invite into a room.

        Args:
            id_server: the identity server to use to store the invite.
            address: the email address to send the invite to.
            room_id: the room the invite is for.
            tok: the access token to authenticate the request with.
            expected_status: the expected HTTP status in the response to /invite.
        """
        params = {
            "id_server": id_server,
            "medium": "email",
            "address": address,
        }
        channel = self.make_request(
            b"POST", "/rooms/%s/invite" % (room_id,), params, access_token=tok
        )
        self.assertEqual(channel.code, expected_status, channel.result)
