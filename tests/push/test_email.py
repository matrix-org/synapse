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

import os

import pkg_resources

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.rest.client.v1 import login, room

from tests.unittest import HomeserverTestCase

try:
    from synapse.push.mailer import load_jinja2_templates
except Exception:
    load_jinja2_templates = None


class EmailPusherTests(HomeserverTestCase):

    skip = "No Jinja installed" if not load_jinja2_templates else None
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
        config.email_enable_notifs = True
        config.start_pushers = True

        config.email_template_dir = os.path.abspath(
            pkg_resources.resource_filename('synapse', 'res/templates')
        )
        config.email_notif_template_html = "notif_mail.html"
        config.email_notif_template_text = "notif_mail.txt"
        config.email_smtp_host = "127.0.0.1"
        config.email_smtp_port = 20
        config.require_transport_security = False
        config.email_smtp_user = None
        config.email_smtp_pass = None
        config.email_app_name = "Matrix"
        config.email_notif_from = "test@example.com"
        config.email_riot_base_url = None

        hs = self.setup_test_homeserver(config=config, sendmail=sendmail)

        return hs

    def test_sends_email(self):

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
                kind="email",
                app_id="m.email",
                app_display_name="Email Notifications",
                device_display_name="a@example.com",
                pushkey="a@example.com",
                lang=None,
                data={},
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
        self.pump(100)

        # It hasn't succeeded yet, so the stream ordering shouldn't have moved
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        self.assertEqual(last_stream_ordering, pushers[0]["last_stream_ordering"])

        # One email was attempted to be sent
        self.assertEqual(len(self.email_attempts), 1)

        # Make the email succeed
        self.email_attempts[0][0].callback(True)
        self.pump()

        # One email was attempted to be sent
        self.assertEqual(len(self.email_attempts), 1)

        # The stream ordering has increased
        pushers = self.get_success(
            self.hs.get_datastore().get_pushers_by(dict(user_name=user_id))
        )
        self.assertEqual(len(pushers), 1)
        self.assertTrue(pushers[0]["last_stream_ordering"] > last_stream_ordering)
