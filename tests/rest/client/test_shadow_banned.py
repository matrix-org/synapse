#  Copyright 2020 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from mock import Mock, patch

import synapse.rest.admin
from synapse.api.constants import EventTypes
from synapse.rest.client.v1 import directory, login, profile, room
from synapse.rest.client.v2_alpha import room_upgrade_rest_servlet

from tests import unittest


class _ShadowBannedBase(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, homeserver):
        # Create two users, one of which is shadow-banned.
        self.banned_user_id = self.register_user("banned", "test")
        self.banned_access_token = self.login("banned", "test")

        self.store = self.hs.get_datastore()

        self.get_success(
            self.store.db_pool.simple_update(
                table="users",
                keyvalues={"name": self.banned_user_id},
                updatevalues={"shadow_banned": True},
                desc="shadow_ban",
            )
        )

        self.other_user_id = self.register_user("otheruser", "pass")
        self.other_access_token = self.login("otheruser", "pass")


# To avoid the tests timing out don't add a delay to "annoy the requester".
@patch("random.randint", new=lambda a, b: 0)
class RoomTestCase(_ShadowBannedBase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        directory.register_servlets,
        login.register_servlets,
        room.register_servlets,
        room_upgrade_rest_servlet.register_servlets,
    ]

    def test_invite(self):
        """Invites from shadow-banned users don't actually get sent."""

        # The create works fine.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        # Inviting the user completes successfully.
        self.helper.invite(
            room=room_id,
            src=self.banned_user_id,
            tok=self.banned_access_token,
            targ=self.other_user_id,
        )

        # But the user wasn't actually invited.
        invited_rooms = self.get_success(
            self.store.get_invited_rooms_for_local_user(self.other_user_id)
        )
        self.assertEqual(invited_rooms, [])

    def test_invite_3pid(self):
        """Ensure that a 3PID invite does not attempt to contact the identity server."""
        identity_handler = self.hs.get_handlers().identity_handler
        identity_handler.lookup_3pid = Mock(
            side_effect=AssertionError("This should not get called")
        )

        # The create works fine.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        # Inviting the user completes successfully.
        request, channel = self.make_request(
            "POST",
            "/rooms/%s/invite" % (room_id,),
            {"id_server": "test", "medium": "email", "address": "test@test.test"},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)

        # This should have raised an error earlier, but double check this wasn't called.
        identity_handler.lookup_3pid.assert_not_called()

    def test_create_room(self):
        """Invitations during a room creation should be discarded, but the room still gets created."""
        # The room creation is successful.
        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/createRoom",
            {"visibility": "public", "invite": [self.other_user_id]},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        room_id = channel.json_body["room_id"]

        # But the user wasn't actually invited.
        invited_rooms = self.get_success(
            self.store.get_invited_rooms_for_local_user(self.other_user_id)
        )
        self.assertEqual(invited_rooms, [])

        # Since a real room was created, the other user should be able to join it.
        self.helper.join(room_id, self.other_user_id, tok=self.other_access_token)

        # Both users should be in the room.
        users = self.get_success(self.store.get_users_in_room(room_id))
        self.assertCountEqual(users, ["@banned:test", "@otheruser:test"])

    def test_message(self):
        """Messages from shadow-banned users don't actually get sent."""

        room_id = self.helper.create_room_as(
            self.other_user_id, tok=self.other_access_token
        )

        # The user should be in the room.
        self.helper.join(room_id, self.banned_user_id, tok=self.banned_access_token)

        # Sending a message should complete successfully.
        result = self.helper.send_event(
            room_id=room_id,
            type=EventTypes.Message,
            content={"msgtype": "m.text", "body": "with right label"},
            tok=self.banned_access_token,
        )
        self.assertIn("event_id", result)
        event_id = result["event_id"]

        latest_events = self.get_success(
            self.store.get_latest_event_ids_in_room(room_id)
        )
        self.assertNotIn(event_id, latest_events)

    def test_upgrade(self):
        """A room upgrade should fail, but look like it succeeded."""

        # The create works fine.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        request, channel = self.make_request(
            "POST",
            "/_matrix/client/r0/rooms/%s/upgrade" % (room_id,),
            {"new_version": "6"},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        # A new room_id should be returned.
        self.assertIn("replacement_room", channel.json_body)

        new_room_id = channel.json_body["replacement_room"]

        # It doesn't really matter what API we use here, we just want to assert
        # that the room doesn't exist.
        summary = self.get_success(self.store.get_room_summary(new_room_id))
        # The summary should be empty since the room doesn't exist.
        self.assertEqual(summary, {})

    def test_typing(self):
        """Typing notifications should not be propagated into the room."""
        # The create works fine.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (room_id, self.banned_user_id),
            {"typing": True, "timeout": 30000},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        # There should be no typing events.
        event_source = self.hs.get_event_sources().sources["typing"]
        self.assertEquals(event_source.get_current_key(), 0)

        # The other user can join and send typing events.
        self.helper.join(room_id, self.other_user_id, tok=self.other_access_token)

        request, channel = self.make_request(
            "PUT",
            "/rooms/%s/typing/%s" % (room_id, self.other_user_id),
            {"typing": True, "timeout": 30000},
            access_token=self.other_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code)

        # These appear in the room.
        self.assertEquals(event_source.get_current_key(), 1)
        events = self.get_success(
            event_source.get_new_events(from_key=0, room_ids=[room_id])
        )
        self.assertEquals(
            events[0],
            [
                {
                    "type": "m.typing",
                    "room_id": room_id,
                    "content": {"user_ids": [self.other_user_id]},
                }
            ],
        )


# To avoid the tests timing out don't add a delay to "annoy the requester".
@patch("random.randint", new=lambda a, b: 0)
class ProfileTestCase(_ShadowBannedBase):
    servlets = [
        synapse.rest.admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        profile.register_servlets,
        room.register_servlets,
    ]

    def test_displayname(self):
        """Profile changes should succeed, but don't end up in a room."""
        original_display_name = "banned"
        new_display_name = "new name"

        # Join a room.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        # The update should succeed.
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/profile/%s/displayname" % (self.banned_user_id,),
            {"displayname": new_display_name},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertEqual(channel.json_body, {})

        # The user's display name should be updated.
        request, channel = self.make_request(
            "GET", "/profile/%s/displayname" % (self.banned_user_id,)
        )
        self.render(request)
        self.assertEqual(channel.code, 200, channel.result)
        self.assertEqual(channel.json_body["displayname"], new_display_name)

        # But the display name in the room should not be.
        message_handler = self.hs.get_message_handler()
        event = self.get_success(
            message_handler.get_room_data(
                self.banned_user_id, room_id, "m.room.member", self.banned_user_id,
            )
        )
        self.assertEqual(
            event.content, {"membership": "join", "displayname": original_display_name}
        )

    def test_room_displayname(self):
        """Changes to state events for a room should be processed, but not end up in the room."""
        original_display_name = "banned"
        new_display_name = "new name"

        # Join a room.
        room_id = self.helper.create_room_as(
            self.banned_user_id, tok=self.banned_access_token
        )

        # The update should succeed.
        request, channel = self.make_request(
            "PUT",
            "/_matrix/client/r0/rooms/%s/state/m.room.member/%s"
            % (room_id, self.banned_user_id),
            {"membership": "join", "displayname": new_display_name},
            access_token=self.banned_access_token,
        )
        self.render(request)
        self.assertEquals(200, channel.code, channel.result)
        self.assertIn("event_id", channel.json_body)

        # The display name in the room should not be changed.
        message_handler = self.hs.get_message_handler()
        event = self.get_success(
            message_handler.get_room_data(
                self.banned_user_id, room_id, "m.room.member", self.banned_user_id,
            )
        )
        self.assertEqual(
            event.content, {"membership": "join", "displayname": original_display_name}
        )
