# -*- coding: utf-8 -*-
# Copyright 2018 New Vector
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

from mock import Mock

import synapse.rest.admin
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import sync

from tests import unittest
from tests.server import TimedOutException


class FilterTestCase(unittest.HomeserverTestCase):

    user_id = "@apple:test"
    servlets = [sync.register_servlets]

    def make_homeserver(self, reactor, clock):

        hs = self.setup_test_homeserver(
            "red", http_client=None, federation_client=Mock()
        )
        return hs

    def test_sync_argless(self):
        request, channel = self.make_request("GET", "/sync")
        self.render(request)

        self.assertEqual(channel.code, 200)
        self.assertTrue(
            set(
                [
                    "next_batch",
                    "rooms",
                    "presence",
                    "account_data",
                    "to_device",
                    "device_lists",
                ]
            ).issubset(set(channel.json_body.keys()))
        )

    def test_sync_presence_disabled(self):
        """
        When presence is disabled, the key does not appear in /sync.
        """
        self.hs.config.use_presence = False

        request, channel = self.make_request("GET", "/sync")
        self.render(request)

        self.assertEqual(channel.code, 200)
        self.assertTrue(
            set(
                ["next_batch", "rooms", "account_data", "to_device", "device_lists"]
            ).issubset(set(channel.json_body.keys()))
        )


class SyncTypingTests(unittest.HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        sync.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def test_sync_backwards_typing(self):
        """
        If the typing serial goes backwards and the typing handler is then reset
        (such as when the master restarts and sets the typing serial to 0), we
        do not incorrectly return typing information that had a serial greater
        than the now-reset serial.
        """
        typing_url = "/rooms/%s/typing/%s?access_token=%s"
        sync_url = "/sync?timeout=3000000&access_token=%s&since=%s"

        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # Invite the other person
        self.helper.invite(room=room, src=user_id, tok=access_token, targ=other_user_id)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # The other user sends some messages
        self.helper.send(room, body="Hi!", tok=other_access_token)
        self.helper.send(room, body="There!", tok=other_access_token)

        # Start typing.
        request, channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": true, "timeout": 30000}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        request, channel = self.make_request(
            "GET", "/sync?access_token=%s" % (access_token,)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Stop typing.
        request, channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": false}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        # Start typing.
        request, channel = self.make_request(
            "PUT",
            typing_url % (room, other_user_id, other_access_token),
            b'{"typing": true, "timeout": 30000}',
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        # Should return immediately
        request, channel = self.make_request(
            "GET", sync_url % (access_token, next_batch)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Reset typing serial back to 0, as if the master had.
        typing = self.hs.get_typing_handler()
        typing._latest_room_serial = 0

        # Since it checks the state token, we need some state to update to
        # invalidate the stream token.
        self.helper.send(room, body="There!", tok=other_access_token)

        request, channel = self.make_request(
            "GET", sync_url % (access_token, next_batch)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # This should time out! But it does not, because our stream token is
        # ahead, and therefore it's saying the typing (that we've actually
        # already seen) is new, since it's got a token above our new, now-reset
        # stream token.
        request, channel = self.make_request(
            "GET", sync_url % (access_token, next_batch)
        )
        self.render(request)
        self.assertEquals(200, channel.code)
        next_batch = channel.json_body["next_batch"]

        # Clear the typing information, so that it doesn't think everything is
        # in the future.
        typing._reset()

        # Now it SHOULD fail as it never completes!
        request, channel = self.make_request(
            "GET", sync_url % (access_token, next_batch)
        )
        self.assertRaises(TimedOutException, self.render, request)
