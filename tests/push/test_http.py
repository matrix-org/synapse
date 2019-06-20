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

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.rest.client.v1 import login, room
from synapse.util.logcontext import make_deferred_yieldable

from tests.unittest import HomeserverTestCase


class HTTPPusherTests(HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def make_homeserver(self, reactor, clock):

        self.push_attempts = []

        m = Mock()

        def post_json_get_json(url, body):
            d = Deferred()
            self.push_attempts.append((d, url, body))
            return make_deferred_yieldable(d)

        m.post_json_get_json = post_json_get_json

        config = self.default_config()
        config["start_pushers"] = True

        hs = self.setup_test_homeserver(config=config, simple_http_client=m)

        return hs

    def test_sends_http(self):
        """
        The HTTP pusher will send pushes for each message to a HTTP endpoint
        when configured to do so.
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple["token_id"]

        self.get_success(
            self.hs.get_pusherpool().add_pusher(
                user_id=user_id,
                access_token=token_id,
                kind="http",
                app_id="m.http",
                app_display_name="HTTP Push Notifications",
                device_display_name="pushy push",
                pushkey="a@example.com",
                lang=None,
                data={"url": "example.com"},
            )
        )

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # Invite the other person
        self.helper.invite(room=room, src=user_id, tok=access_token, targ=other_user_id)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # The other user sends some messages
        self.helper.send(room, body="Hi!", tok=other_access_token)
        self.helper.send(room, body="There!", tok=other_access_token)

        # Get the stream ordering before it gets sent
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        last_stream_ordering = pushers[0]["last_stream_ordering"]

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # It hasn't succeeded yet, so the stream ordering shouldn't have moved
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        self.assertEqual(last_stream_ordering, pushers[0]["last_stream_ordering"])

        # One push was attempted to be sent -- it'll be the first message
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(self.push_attempts[0][1], "example.com")
        self.assertEqual(
            self.push_attempts[0][2]["notification"]["content"]["body"], "Hi!"
        )

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # The stream ordering has increased
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0]["last_stream_ordering"] > last_stream_ordering)
        last_stream_ordering = pushers[0]["last_stream_ordering"]

        # Now it'll try and send the second push message, which will be the second one
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(self.push_attempts[1][1], "example.com")
        self.assertEqual(
            self.push_attempts[1][2]["notification"]["content"]["body"], "There!"
        )

        # Make the second push succeed
        self.push_attempts[1][0].callback({})
        self.pump()

        # The stream ordering has increased, again
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0]["last_stream_ordering"] > last_stream_ordering)
