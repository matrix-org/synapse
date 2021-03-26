# -*- coding: utf-8 -*-
# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from synapse.api.constants import EduTypes
from synapse.events import EventBase
from synapse.federation.units import Transaction
from synapse.handlers.presence import UserPresenceState
from synapse.rest import admin
from synapse.rest.client.v1 import login, presence, room
from synapse.types import create_requester

from tests.events.test_presence_router import (
    PresenceRouterTestModule,
    send_presence_update,
    sync_presence,
)
from tests.unittest import FederatingHomeserverTestCase, override_config


class ModuleApiTestCase(FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        presence.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastore()
        self.module_api = homeserver.get_module_api()
        self.event_creation_handler = homeserver.get_event_creation_handler()

    def make_homeserver(self, reactor, clock):
        return self.setup_test_homeserver(
            federation_transport_client=Mock(spec=["send_transaction"]),
        )

    def test_can_register_user(self):
        """Tests that an external module can register a user"""
        # Register a new user
        user_id, access_token = self.get_success(
            self.module_api.register(
                "bob", displayname="Bobberino", emails=["bob@bobinator.bob"]
            )
        )

        # Check that the new user exists with all provided attributes
        self.assertEqual(user_id, "@bob:test")
        self.assertTrue(access_token)
        self.assertTrue(self.get_success(self.store.get_user_by_id(user_id)))

        # Check that the email was assigned
        emails = self.get_success(self.store.user_get_threepids(user_id))
        self.assertEqual(len(emails), 1)

        email = emails[0]
        self.assertEqual(email["medium"], "email")
        self.assertEqual(email["address"], "bob@bobinator.bob")

        # Should these be 0?
        self.assertEqual(email["validated_at"], 0)
        self.assertEqual(email["added_at"], 0)

        # Check that the displayname was assigned
        displayname = self.get_success(self.store.get_profile_displayname("bob"))
        self.assertEqual(displayname, "Bobberino")

    def test_sending_events_into_room(self):
        """Tests that a module can send events into a room"""
        # Mock out create_and_send_nonmember_event to check whether events are being sent
        self.event_creation_handler.create_and_send_nonmember_event = Mock(
            spec=[],
            side_effect=self.event_creation_handler.create_and_send_nonmember_event,
        )

        # Create a user and room to play with
        user_id = self.register_user("summer", "monkey")
        tok = self.login("summer", "monkey")
        room_id = self.helper.create_room_as(user_id, tok=tok)

        # Create and send a non-state event
        content = {"body": "I am a puppet", "msgtype": "m.text"}
        event_dict = {
            "room_id": room_id,
            "type": "m.room.message",
            "content": content,
            "sender": user_id,
        }
        event = self.get_success(
            self.module_api.create_and_send_event_into_room(event_dict)
        )  # type: EventBase
        self.assertEqual(event.sender, user_id)
        self.assertEqual(event.type, "m.room.message")
        self.assertEqual(event.room_id, room_id)
        self.assertFalse(hasattr(event, "state_key"))
        self.assertDictEqual(event.content, content)

        expected_requester = create_requester(
            user_id, authenticated_entity=self.hs.hostname
        )

        # Check that the event was sent
        self.event_creation_handler.create_and_send_nonmember_event.assert_called_with(
            expected_requester,
            event_dict,
            ratelimit=False,
            ignore_shadow_ban=True,
        )

        # Create and send a state event
        content = {
            "events_default": 0,
            "users": {user_id: 100},
            "state_default": 50,
            "users_default": 0,
            "events": {"test.event.type": 25},
        }
        event_dict = {
            "room_id": room_id,
            "type": "m.room.power_levels",
            "content": content,
            "sender": user_id,
            "state_key": "",
        }
        event = self.get_success(
            self.module_api.create_and_send_event_into_room(event_dict)
        )  # type: EventBase
        self.assertEqual(event.sender, user_id)
        self.assertEqual(event.type, "m.room.power_levels")
        self.assertEqual(event.room_id, room_id)
        self.assertEqual(event.state_key, "")
        self.assertDictEqual(event.content, content)

        # Check that the event was sent
        self.event_creation_handler.create_and_send_nonmember_event.assert_called_with(
            expected_requester,
            {
                "type": "m.room.power_levels",
                "content": content,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "",
            },
            ratelimit=False,
            ignore_shadow_ban=True,
        )

        # Check that we can't send membership events
        content = {
            "membership": "leave",
        }
        event_dict = {
            "room_id": room_id,
            "type": "m.room.member",
            "content": content,
            "sender": user_id,
            "state_key": user_id,
        }
        self.get_failure(
            self.module_api.create_and_send_event_into_room(event_dict), Exception
        )

    def test_public_rooms(self):
        """Tests that a room can be added and removed from the public rooms list,
        as well as have its public rooms directory state queried.
        """
        # Create a user and room to play with
        user_id = self.register_user("kermit", "monkey")
        tok = self.login("kermit", "monkey")
        room_id = self.helper.create_room_as(user_id, tok=tok)

        # The room should not currently be in the public rooms directory
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertFalse(is_in_public_rooms)

        # Let's try adding it to the public rooms directory
        self.get_success(
            self.module_api.public_room_list_manager.add_room_to_public_room_list(
                room_id
            )
        )

        # And checking whether it's in there...
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertTrue(is_in_public_rooms)

        # Let's remove it again
        self.get_success(
            self.module_api.public_room_list_manager.remove_room_from_public_room_list(
                room_id
            )
        )

        # Should be gone
        is_in_public_rooms = self.get_success(
            self.module_api.public_room_list_manager.room_is_in_public_room_list(
                room_id
            )
        )
        self.assertFalse(is_in_public_rooms)

    @override_config(
        {
            "presence": {
                "presence_router": {
                    "module": "%s.%s"
                    % (
                        PresenceRouterTestModule.__module__,
                        PresenceRouterTestModule.__name__,
                    ),
                    "config": {
                        "users_who_should_receive_all_presence": [
                            "@presence_gobbler1:test",
                            "@presence_gobbler2:test",
                            "@far_away_person:island",
                        ]
                    },
                }
            },
            "send_federation": True,
        }
    )
    def test_send_local_online_presence_to(self):
        """Tests that send_local_presence_to_users sends local online presence to a set
        of specified local and remote users.
        """
        self.sync_handler = self.hs.get_sync_handler()

        # Create a user who will send presence updates
        self.other_user_id = self.register_user("other_user", "monkey")
        self.other_user_tok = self.login("other_user", "monkey")

        # And another two users that will also send out presence updates, as well as receive
        # theirs and everyone else's
        self.presence_receiving_user_one_id = self.register_user(
            "presence_gobbler1", "monkey"
        )
        self.presence_receiving_user_one_tok = self.login("presence_gobbler1", "monkey")
        self.presence_receiving_user_two_id = self.register_user(
            "presence_gobbler2", "monkey"
        )
        self.presence_receiving_user_two_tok = self.login("presence_gobbler2", "monkey")

        # Have all three users send some presence updates
        send_presence_update(
            self,
            self.other_user_id,
            self.other_user_tok,
            "online",
            "I'm online!",
        )
        send_presence_update(
            self,
            self.presence_receiving_user_one_id,
            self.presence_receiving_user_one_tok,
            "online",
            "I'm also online!",
        )
        send_presence_update(
            self,
            self.presence_receiving_user_two_id,
            self.presence_receiving_user_two_tok,
            "unavailable",
            "I'm in a meeting!",
        )

        # Mark each presence-receiving user for receiving all user presence
        self.get_success(
            self.module_api.send_local_online_presence_to(
                [
                    self.presence_receiving_user_one_id,
                    self.presence_receiving_user_two_id,
                ]
            )
        )

        # Perform a sync for each user

        # The other user should only receive their own presence
        presence_updates = sync_presence(self, self.other_user_id)
        self.assertEqual(len(presence_updates), 1)

        presence_update = presence_updates[0]  # type: UserPresenceState
        self.assertEqual(presence_update.user_id, self.other_user_id)
        self.assertEqual(presence_update.state, "online")
        self.assertEqual(presence_update.status_msg, "I'm online!")

        # Whereas both presence receiving users should receive everyone's presence updates
        presence_updates = sync_presence(self, self.presence_receiving_user_one_id)
        self.assertEqual(len(presence_updates), 3)
        presence_updates = sync_presence(self, self.presence_receiving_user_two_id)
        self.assertEqual(len(presence_updates), 3)

        # Test that sending to a remote user works
        remote_user_id = "@far_away_person:island"

        # Note that due to the remote user being in our module's
        # users_who_should_receive_all_presence config, they would have
        # received user presence updates already.
        #
        # Thus we reset the mock, and try sending all online local user
        # presence again
        self.hs.get_federation_transport_client().send_transaction.reset_mock()

        # Track the outgoing presence on the federation client
        self.get_success(
            self.module_api.send_local_online_presence_to([remote_user_id])
        )

        # Check that the expected presence updates were sent
        expected_users = [
            self.other_user_id,
            self.presence_receiving_user_one_id,
            self.presence_receiving_user_two_id,
        ]

        calls = (
            self.hs.get_federation_transport_client().send_transaction.call_args_list
        )
        for call in calls:
            federation_transaction = call.args[0]  # type: Transaction

            # Get the sent EDUs in this transaction
            edus = federation_transaction.get_dict()["edus"]

            for edu in edus:
                # Make sure we're only checking presence-type EDUs
                if edu["edu_type"] != EduTypes.Presence:
                    continue

                # EDUs can contain multiple presence updates
                for presence_update in edu["content"]["push"]:
                    # Check for presence updates that contain the user IDs we're after
                    expected_users.remove(presence_update["user_id"])

                    # Ensure that no offline states are being sent out
                    self.assertNotEqual(presence_update["presence"], "offline")

        self.assertEqual(len(expected_users), 0)
