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
from unittest.mock import Mock

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.logging.context import make_deferred_yieldable
from synapse.push import PusherConfigException
from synapse.rest.client.v1 import login, room
from synapse.rest.client.v2_alpha import receipts

from tests.unittest import HomeserverTestCase, override_config


class HTTPPusherTests(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        receipts.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def default_config(self):
        config = super().default_config()
        config["start_pushers"] = True
        return config

    def make_homeserver(self, reactor, clock):
        self.push_attempts = []

        m = Mock()

        def post_json_get_json(url, body):
            d = Deferred()
            self.push_attempts.append((d, url, body))
            return make_deferred_yieldable(d)

        m.post_json_get_json = post_json_get_json

        hs = self.setup_test_homeserver(proxied_blacklisted_http_client=m)

        return hs

    def test_invalid_configuration(self):
        """Invalid push configurations should be rejected."""
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

        def test_data(data):
            self.get_failure(
                self.hs.get_pusherpool().add_pusher(
                    user_id=user_id,
                    access_token=token_id,
                    kind="http",
                    app_id="m.http",
                    app_display_name="HTTP Push Notifications",
                    device_display_name="pushy push",
                    pushkey="a@example.com",
                    lang=None,
                    data=data,
                ),
                PusherConfigException,
            )

        # Data must be provided with a URL.
        test_data(None)
        test_data({})
        test_data({"url": 1})
        # A bare domain name isn't accepted.
        test_data({"url": "example.com"})
        # A URL without a path isn't accepted.
        test_data({"url": "http://example.com"})
        # A url with an incorrect path isn't accepted.
        test_data({"url": "http://example.com/foo"})

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
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # The other user sends some messages
        self.helper.send(room, body="Hi!", tok=other_access_token)
        self.helper.send(room, body="There!", tok=other_access_token)

        # Get the stream ordering before it gets sent
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        last_stream_ordering = pushers[0].last_stream_ordering

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # It hasn't succeeded yet, so the stream ordering shouldn't have moved
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertEqual(last_stream_ordering, pushers[0].last_stream_ordering)

        # One push was attempted to be sent -- it'll be the first message
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(
            self.push_attempts[0][2]["notification"]["content"]["body"], "Hi!"
        )

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # The stream ordering has increased
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0].last_stream_ordering > last_stream_ordering)
        last_stream_ordering = pushers[0].last_stream_ordering

        # Now it'll try and send the second push message, which will be the second one
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(
            self.push_attempts[1][2]["notification"]["content"]["body"], "There!"
        )

        # Make the second push succeed
        self.push_attempts[1][0].callback({})
        self.pump()

        # The stream ordering has increased, again
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0].last_stream_ordering > last_stream_ordering)

    def test_sends_high_priority_for_encrypted(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to an encrypted message.
        This will happen both in 1:1 rooms and larger rooms.
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Register a third user
        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Send an encrypted event
        # I know there'd normally be set-up of an encrypted room first
        # but this will do for our purposes
        self.helper.send_event(
            room,
            "m.room.encrypted",
            content={
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "6lImKbzK51MzWLwHh8tUM3UBBSBrLlgup/OOCGTvumM",
                "ciphertext": "AwgAErABoRxwpMipdgiwXgu46rHiWQ0DmRj0qUlPrMraBUDk"
                "leTnJRljpuc7IOhsYbLY3uo2WI0ab/ob41sV+3JEIhODJPqH"
                "TK7cEZaIL+/up9e+dT9VGF5kRTWinzjkeqO8FU5kfdRjm+3w"
                "0sy3o1OCpXXCfO+faPhbV/0HuK4ndx1G+myNfK1Nk/CxfMcT"
                "BT+zDS/Df/QePAHVbrr9uuGB7fW8ogW/ulnydgZPRluusFGv"
                "J3+cg9LoPpZPAmv5Me3ec7NtdlfN0oDZ0gk3TiNkkhsxDG9Y"
                "YcNzl78USI0q8+kOV26Bu5dOBpU4WOuojXZHJlP5lMgdzLLl"
                "EQ0",
                "session_id": "IigqfNWLL+ez/Is+Duwp2s4HuCZhFG9b9CZKTYHtQ4A",
                "device_id": "AHQDUSTAAA",
            },
            tok=other_access_token,
        )

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # Check our push made it with high priority
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        # Add yet another person — we want to make this room not a 1:1
        # (as encrypted messages in a 1:1 currently have tweaks applied
        #  so it doesn't properly exercise the condition of all encrypted
        #  messages need to be high).
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        # Check no push notifications are sent regarding the membership changes
        # (that would confuse the test)
        self.pump()
        self.assertEqual(len(self.push_attempts), 1)

        # Send another encrypted event
        self.helper.send_event(
            room,
            "m.room.encrypted",
            content={
                "ciphertext": "AwgAEoABtEuic/2DF6oIpNH+q/PonzlhXOVho8dTv0tzFr5m"
                "9vTo50yabx3nxsRlP2WxSqa8I07YftP+EKWCWJvTkg6o7zXq"
                "6CK+GVvLQOVgK50SfvjHqJXN+z1VEqj+5mkZVN/cAgJzoxcH"
                "zFHkwDPJC8kQs47IHd8EO9KBUK4v6+NQ1uE/BIak4qAf9aS/"
                "kI+f0gjn9IY9K6LXlah82A/iRyrIrxkCkE/n0VfvLhaWFecC"
                "sAWTcMLoF6fh1Jpke95mljbmFSpsSd/eEQw",
                "device_id": "SRCFTWTHXO",
                "session_id": "eMA+bhGczuTz1C5cJR1YbmrnnC6Goni4lbvS5vJ1nG4",
                "algorithm": "m.megolm.v1.aes-sha2",
                "sender_key": "rC/XSIAiYrVGSuaHMop8/pTZbku4sQKBZwRwukgnN1c",
            },
            tok=other_access_token,
        )

        # Advance time a bit, so the pusher will register something has happened
        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "high")

    def test_sends_high_priority_for_one_to_one_only(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message in a one-to-one room.
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Register a third user
        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Send a message
        self.helper.send(room, body="Hi!", tok=other_access_token)

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # Check our push made it with high priority — this is a one-to-one room
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        # Yet another user joins
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        # Check no push notifications are sent regarding the membership changes
        # (that would confuse the test)
        self.pump()
        self.assertEqual(len(self.push_attempts), 1)

        # Send another event
        self.helper.send(room, body="Welcome!", tok=other_access_token)

        # Advance time a bit, so the pusher will register something has happened
        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][1], "http://example.com/_matrix/push/v1/notify"
        )

        # check that this is low-priority
        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_sends_high_priority_for_mention(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message containing the user's display name.
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Register a third user
        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # The other users join
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Send a message
        self.helper.send(room, body="Oh, user, hello!", tok=other_access_token)

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # Check our push made it with high priority
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        # Send another event, this time with no mention
        self.helper.send(room, body="Are you there?", tok=other_access_token)

        # Advance time a bit, so the pusher will register something has happened
        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][1], "http://example.com/_matrix/push/v1/notify"
        )

        # check that this is low-priority
        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_sends_high_priority_for_atroom(self):
        """
        The HTTP pusher will send pushes at high priority if they correspond
        to a message that contains @room.
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("otheruser", "pass")
        other_access_token = self.login("otheruser", "pass")

        # Register a third user
        yet_another_user_id = self.register_user("yetanotheruser", "pass")
        yet_another_access_token = self.login("yetanotheruser", "pass")

        # Create a room (as other_user so the power levels are compatible with
        # other_user sending @room).
        room = self.helper.create_room_as(other_user_id, tok=other_access_token)

        # The other users join
        self.helper.join(room=room, user=user_id, tok=access_token)
        self.helper.join(
            room=room, user=yet_another_user_id, tok=yet_another_access_token
        )

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Send a message
        self.helper.send(
            room,
            body="@room eeek! There's a spider on the table!",
            tok=other_access_token,
        )

        # Advance time a bit, so the pusher will register something has happened
        self.pump()

        # Make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # Check our push made it with high priority
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )
        self.assertEqual(self.push_attempts[0][2]["notification"]["prio"], "high")

        # Send another event, this time as someone without the power of @room
        self.helper.send(
            room, body="@room the spider is gone", tok=yet_another_access_token
        )

        # Advance time a bit, so the pusher will register something has happened
        self.pump()
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][1], "http://example.com/_matrix/push/v1/notify"
        )

        # check that this is low-priority
        self.assertEqual(self.push_attempts[1][2]["notification"]["prio"], "low")

    def test_push_unread_count_group_by_room(self):
        """
        The HTTP pusher will group unread count by number of unread rooms.
        """
        # Carry out common push count tests and setup
        self._test_push_unread_count()

        # Carry out our option-value specific test
        #
        # This push should still only contain an unread count of 1 (for 1 unread room)
        self.assertEqual(
            self.push_attempts[5][2]["notification"]["counts"]["unread"], 1
        )

    @override_config({"push": {"group_unread_count_by_room": False}})
    def test_push_unread_count_message_count(self):
        """
        The HTTP pusher will send the total unread message count.
        """
        # Carry out common push count tests and setup
        self._test_push_unread_count()

        # Carry out our option-value specific test
        #
        # We're counting every unread message, so there should now be 4 since the
        # last read receipt
        self.assertEqual(
            self.push_attempts[5][2]["notification"]["counts"]["unread"], 4
        )

    def _test_push_unread_count(self):
        """
        Tests that the correct unread count appears in sent push notifications

        Note that:
        * Sending messages will cause push notifications to go out to relevant users
        * Sending a read receipt will cause a "badge update" notification to go out to
          the user that sent the receipt
        """
        # Register the user who gets notified
        user_id = self.register_user("user", "pass")
        access_token = self.login("user", "pass")

        # Register the user who sends the message
        other_user_id = self.register_user("other_user", "pass")
        other_access_token = self.login("other_user", "pass")

        # Create a room (as other_user)
        room_id = self.helper.create_room_as(other_user_id, tok=other_access_token)

        # The user to get notified joins
        self.helper.join(room=room_id, user=user_id, tok=access_token)

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(access_token)
        )
        token_id = user_tuple.token_id

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
                data={"url": "http://example.com/_matrix/push/v1/notify"},
            )
        )

        # Send a message
        response = self.helper.send(
            room_id, body="Hello there!", tok=other_access_token
        )
        # To get an unread count, the user who is getting notified has to have a read
        # position in the room. We'll set the read position to this event in a moment
        first_message_event_id = response["event_id"]

        # Advance time a bit (so the pusher will register something has happened) and
        # make the push succeed
        self.push_attempts[0][0].callback({})
        self.pump()

        # Check our push made it
        self.assertEqual(len(self.push_attempts), 1)
        self.assertEqual(
            self.push_attempts[0][1], "http://example.com/_matrix/push/v1/notify"
        )

        # Check that the unread count for the room is 0
        #
        # The unread count is zero as the user has no read receipt in the room yet
        self.assertEqual(
            self.push_attempts[0][2]["notification"]["counts"]["unread"], 0
        )

        # Now set the user's read receipt position to the first event
        #
        # This will actually trigger a new notification to be sent out so that
        # even if the user does not receive another message, their unread
        # count goes down
        channel = self.make_request(
            "POST",
            "/rooms/%s/receipt/m.read/%s" % (room_id, first_message_event_id),
            {},
            access_token=access_token,
        )
        self.assertEqual(channel.code, 200, channel.json_body)

        # Advance time and make the push succeed
        self.push_attempts[1][0].callback({})
        self.pump()

        # Unread count is still zero as we've read the only message in the room
        self.assertEqual(len(self.push_attempts), 2)
        self.assertEqual(
            self.push_attempts[1][2]["notification"]["counts"]["unread"], 0
        )

        # Send another message
        self.helper.send(
            room_id, body="How's the weather today?", tok=other_access_token
        )

        # Advance time and make the push succeed
        self.push_attempts[2][0].callback({})
        self.pump()

        # This push should contain an unread count of 1 as there's now been one
        # message since our last read receipt
        self.assertEqual(len(self.push_attempts), 3)
        self.assertEqual(
            self.push_attempts[2][2]["notification"]["counts"]["unread"], 1
        )

        # Since we're grouping by room, sending more messages shouldn't increase the
        # unread count, as they're all being sent in the same room
        self.helper.send(room_id, body="Hello?", tok=other_access_token)

        # Advance time and make the push succeed
        self.pump()
        self.push_attempts[3][0].callback({})

        self.helper.send(room_id, body="Hello??", tok=other_access_token)

        # Advance time and make the push succeed
        self.pump()
        self.push_attempts[4][0].callback({})

        self.helper.send(room_id, body="HELLO???", tok=other_access_token)

        # Advance time and make the push succeed
        self.pump()
        self.push_attempts[5][0].callback({})

        self.assertEqual(len(self.push_attempts), 6)
