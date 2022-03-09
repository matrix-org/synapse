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
from typing import List
from unittest.mock import Mock

from twisted.internet.defer import Deferred

import synapse.rest.admin
from synapse.logging.context import make_deferred_yieldable
from synapse.rest.client import login, push_rule, receipts, room

from tests.unittest import HomeserverTestCase


class HTTPPusherTests(HomeserverTestCase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
        receipts.register_servlets,
        push_rule.register_servlets,
    ]
    user_id = True
    hijack_auth = False

    def default_config(self):
        config = super().default_config()
        config["start_pushers"] = True
        return config

    def make_homeserver(self, reactor, clock):
        self.push_attempts: List[tuple[Deferred, str, dict]] = []

        m = Mock()

        def post_json_get_json(url, body):
            d: Deferred = Deferred()
            self.push_attempts.append((d, url, body))
            return make_deferred_yieldable(d)

        m.post_json_get_json = post_json_get_json

        hs = self.setup_test_homeserver(proxied_blacklisted_http_client=m)

        return hs

    def _make_user_with_pusher(self, username):
        user_id = self.register_user(username, "pass")
        access_token = self.login(username, "pass")

        # Register the pusher
        user_tuple = self.get_success(
            self.hs.get_datastores().main.get_user_by_access_token(access_token)
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

        return user_id, access_token

    def test_dont_notify_rule_overrides_message(self):
        """
        The override push rule will suppress notification
        """

        user_id, access_token = self._make_user_with_pusher("user")
        other_user_id, other_access_token = self._make_user_with_pusher("otheruser")

        # Create a room
        room = self.helper.create_room_as(user_id, tok=access_token)

        # Disable user notifications for this room -> user
        body = {
            "conditions": [{"kind": "event_match", "key": "room_id", "pattern": room}],
            "actions": ["dont_notify"],
        }
        channel = self.make_request(
            "PUT",
            "/pushrules/global/override/best.friend",
            body,
            access_token=access_token,
        )
        self.assertEqual(channel.code, 200)

        # The other user joins
        self.helper.join(room=room, user=other_user_id, tok=other_access_token)

        # The other user sends a message (ignored by dont_notify push rule set above)
        self.helper.send(room, body="Hi!", tok=other_access_token)

        # The user sends a message back (sends a notification)
        self.helper.send(room, body="Hello", tok=access_token)

        self.assertEqual(len(self.push_attempts), 1)
