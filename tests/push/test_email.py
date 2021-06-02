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

import os

import attr
import pkg_resources

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.api.errors import Codes, SynapseError
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase


@attr.s
class _User:
    "Helper wrapper for user ID and access token"
    id = attr.ib()
    token = attr.ib()


class EmailPusherTests(HomeserverTestCase):

    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def make_homeserver(self, reactor, clock):

        # List[Tuple[Deferred, args, kwargs]]
        self.email_attempts = []

        def sendmail(*args, **kwargs):
            d = Deferred()
            self.email_attempts.append((d, args, kwargs))
            return d

        config = self.default_config()
        config["email"] = {
            "enable_notifs": True,
            "template_dir": os.path.abspath(
                pkg_resources.resource_filename("synapse", "res/templates")
            ),
            "expiry_template_html": "notice_expiry.html",
            "expiry_template_text": "notice_expiry.txt",
            "notif_template_html": "notif_mail.html",
            "notif_template_text": "notif_mail.txt",
            "smtp_host": "127.0.0.1",
            "smtp_port": 20,
            "require_transport_security": False,
            "smtp_user": None,
            "smtp_pass": None,
            "app_name": "Matrix",
            "notif_from": "test@example.com",
            "riot_base_url": None,
        }
        config["public_baseurl"] = "aaa"
        config["start_pushers"] = True

        hs = self.setup_test_homeserver(config=config, sendmail=sendmail)

        return hs

    def prepare(self, reactor, clock, hs):
        # Register the user who gets notified
        self.user_id = self.register_user("user", "pass")
        self.access_token = self.login("user", "pass")

        # Register other users
        self.others = [
            _User(
                id=self.register_user("otheruser1", "pass"),
                token=self.login("otheruser1", "pass"),
            ),
            _User(
                id=self.register_user("otheruser2", "pass"),
                token=self.login("otheruser2", "pass"),
            ),
        ]

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastore().get_user_by_access_token(self.access_token)
        )
        self.token_id = user_tuple.token_id

        # We need to add email to account before we can create a pusher.
        self.get_success(
            hs.get_datastore().user_add_threepid(
                self.user_id, "email", "a@example.com", 0, 0
            )
        )

        self.pusher = self.get_success(
            self.hs.get_pusherpool().add_pusher(
                user_id=self.user_id,
                access_token=self.token_id,
                kind="email",
                app_id="m.email",
                app_display_name="Email Notifications",
                device_display_name="a@example.com",
                pushkey="a@example.com",
                lang=None,
                data={},
            )
        )

    def test_need_validated_email(self):
        """Test that we can only add an email pusher if the user has validated
        their email.
        """
        with self.assertRaises(SynapseError) as cm:
            self.get_success_or_raise(
                self.hs.get_pusherpool().add_pusher(
                    user_id=self.user_id,
                    access_token=self.token_id,
                    kind="email",
                    app_id="m.email",
                    app_display_name="Email Notifications",
                    device_display_name="b@example.com",
                    pushkey="b@example.com",
                    lang=None,
                    data={},
                )
            )

        self.assertEqual(400, cm.exception.code)
        self.assertEqual(Codes.THREEPID_NOT_FOUND, cm.exception.errcode)

    def test_simple_sends_email(self):
        # Create a simple room with two users
        room = self.helper.create_room_as(self.user_id, tok=self.access_token)
        self.helper.invite(
            room=room, src=self.user_id, tok=self.access_token, targ=self.others[0].id
        )
        self.helper.join(room=room, user=self.others[0].id, tok=self.others[0].token)

        # The other user sends a single message.
        self.helper.send(room, body="Hi!", tok=self.others[0].token)

        # We should get emailed about that message
        self._check_for_mail()

        # The other user sends multiple messages.
        self.helper.send(room, body="Hi!", tok=self.others[0].token)
        self.helper.send(room, body="There!", tok=self.others[0].token)

        self._check_for_mail()

    def test_invite_sends_email(self):
        # Create a room and invite the user to it
        room = self.helper.create_room_as(self.others[0].id, tok=self.others[0].token)
        self.helper.invite(
            room=room,
            src=self.others[0].id,
            tok=self.others[0].token,
            targ=self.user_id,
        )

        # We should get emailed about the invite
        self._check_for_mail()

    def test_invite_to_empty_room_sends_email(self):
        # Create a room and invite the user to it
        room = self.helper.create_room_as(self.others[0].id, tok=self.others[0].token)
        self.helper.invite(
            room=room,
            src=self.others[0].id,
            tok=self.others[0].token,
            targ=self.user_id,
        )

        # Then have the original user leave
        self.helper.leave(room, self.others[0].id, tok=self.others[0].token)

        # We should get emailed about the invite
        self._check_for_mail()

    def test_multiple_members_email(self):
        # We want to test multiple notifications, so we pause processing of push
        # while we send messages.
        self.pusher._pause_processing()

        # Create a simple room with multiple other users
        room = self.helper.create_room_as(self.user_id, tok=self.access_token)

        for other in self.others:
            self.helper.invite(
                room=room, src=self.user_id, tok=self.access_token, targ=other.id
            )
            self.helper.join(room=room, user=other.id, tok=other.token)

        # The other users send some messages
        self.helper.send(room, body="Hi!", tok=self.others[0].token)
        self.helper.send(room, body="There!", tok=self.others[1].token)
        self.helper.send(room, body="There!", tok=self.others[1].token)

        # Nothing should have happened yet, as we're paused.
        assert not self.email_attempts

        self.pusher._resume_processing()

        # We should get emailed about those messages
        self._check_for_mail()

    def test_multiple_rooms(self):
        # We want to test multiple notifications from multiple rooms, so we pause
        # processing of push while we send messages.
        self.pusher._pause_processing()

        # Create a simple room with multiple other users
        rooms = [
            self.helper.create_room_as(self.user_id, tok=self.access_token),
            self.helper.create_room_as(self.user_id, tok=self.access_token),
        ]

        for r, other in zip(rooms, self.others):
            self.helper.invite(
                room=r, src=self.user_id, tok=self.access_token, targ=other.id
            )
            self.helper.join(room=r, user=other.id, tok=other.token)

        # The other users send some messages
        self.helper.send(rooms[0], body="Hi!", tok=self.others[0].token)
        self.helper.send(rooms[1], body="There!", tok=self.others[1].token)
        self.helper.send(rooms[1], body="There!", tok=self.others[1].token)

        # Nothing should have happened yet, as we're paused.
        assert not self.email_attempts

        self.pusher._resume_processing()

        # We should get emailed about those messages
        self._check_for_mail()

    def test_empty_room(self):
        """All users leaving a room shouldn't cause the pusher to break."""
        # Create a simple room with two users
        room = self.helper.create_room_as(self.user_id, tok=self.access_token)
        self.helper.invite(
            room=room, src=self.user_id, tok=self.access_token, targ=self.others[0].id
        )
        self.helper.join(room=room, user=self.others[0].id, tok=self.others[0].token)

        # The other user sends a single message.
        self.helper.send(room, body="Hi!", tok=self.others[0].token)

        # Leave the room before the message is processed.
        self.helper.leave(room, self.user_id, tok=self.access_token)
        self.helper.leave(room, self.others[0].id, tok=self.others[0].token)

        # We should get emailed about that message
        self._check_for_mail()

    def test_empty_room_multiple_messages(self):
        """All users leaving a room shouldn't cause the pusher to break."""
        # Create a simple room with two users
        room = self.helper.create_room_as(self.user_id, tok=self.access_token)
        self.helper.invite(
            room=room, src=self.user_id, tok=self.access_token, targ=self.others[0].id
        )
        self.helper.join(room=room, user=self.others[0].id, tok=self.others[0].token)

        # The other user sends a single message.
        self.helper.send(room, body="Hi!", tok=self.others[0].token)
        self.helper.send(room, body="There!", tok=self.others[0].token)

        # Leave the room before the message is processed.
        self.helper.leave(room, self.user_id, tok=self.access_token)
        self.helper.leave(room, self.others[0].id, tok=self.others[0].token)

        # We should get emailed about that message
        self._check_for_mail()

    def test_encrypted_message(self):
        room = self.helper.create_room_as(self.user_id, tok=self.access_token)
        self.helper.invite(
            room=room, src=self.user_id, tok=self.access_token, targ=self.others[0].id
        )
        self.helper.join(room=room, user=self.others[0].id, tok=self.others[0].token)

        # The other user sends some messages
        self.helper.send_event(room, "m.room.encrypted", {}, tok=self.others[0].token)

        # We should get emailed about that message
        self._check_for_mail()

    def _check_for_mail(self):
        """Check that the user receives an email notification"""

        # Get the stream ordering before it gets sent
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": self.user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        last_stream_ordering = pushers[0].last_stream_ordering

        # Advance time a bit, so the pusher will register something has happened
        self.pump(10)

        # It hasn't succeeded yet, so the stream ordering shouldn't have moved
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": self.user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertEqual(last_stream_ordering, pushers[0].last_stream_ordering)

        # One email was attempted to be sent
        self.assertEqual(len(self.email_attempts), 1)

        # Make the email succeed
        self.email_attempts[0][0].callback(True)
        self.pump()

        # One email was attempted to be sent
        self.assertEqual(len(self.email_attempts), 1)

        # The stream ordering has increased
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by({"user_name": self.user_id})
        )
        pushers = list(pushers)
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0].last_stream_ordering > last_stream_ordering)

        # Reset the attempts.
        self.email_attempts = []
