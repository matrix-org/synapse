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
from unittest.mock import Mock

from twisted.internet import defer

from synapse.api.constants import EduTypes
from synapse.events import EventBase
from synapse.federation.units import Transaction
from synapse.handlers.presence import UserPresenceState
from synapse.rest import admin
from synapse.rest.client.v1 import login, presence, room
from synapse.types import create_requester

from tests.events.test_presence_router import send_presence_update, sync_presence
from tests.replication._base import BaseMultiWorkerStreamTestCase
from tests.test_utils.event_injection import inject_member_event
from tests.unittest import HomeserverTestCase, override_config
from tests.utils import USE_POSTGRES_FOR_TESTS


class ModuleApiTestCase(HomeserverTestCase):
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
        self.sync_handler = homeserver.get_sync_handler()

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

    def test_send_local_online_presence_to(self):
        # Test sending local online presence to users from the main process
        _test_sending_local_online_presence_to_local_user(self, test_with_workers=False)

    @override_config({"send_federation": True})
    def test_send_local_online_presence_to_federation(self):
        """Tests that send_local_presence_to_users sends local online presence to remote users."""
        # Create a user who will send presence updates
        self.presence_sender_id = self.register_user("presence_sender1", "monkey")
        self.presence_sender_tok = self.login("presence_sender1", "monkey")

        # And a room they're a part of
        room_id = self.helper.create_room_as(
            self.presence_sender_id,
            tok=self.presence_sender_tok,
        )

        # Mark them as online
        send_presence_update(
            self,
            self.presence_sender_id,
            self.presence_sender_tok,
            "online",
            "I'm online!",
        )

        # Make up a remote user to send presence to
        remote_user_id = "@far_away_person:island"

        # Create a join membership event for the remote user into the room.
        # This allows presence information to flow from one user to the other.
        self.get_success(
            inject_member_event(
                self.hs,
                room_id,
                sender=remote_user_id,
                target=remote_user_id,
                membership="join",
            )
        )

        # The remote user would have received the existing room members' presence
        # when they joined the room.
        #
        # Thus we reset the mock, and try sending online local user
        # presence again
        self.hs.get_federation_transport_client().send_transaction.reset_mock()

        # Broadcast local user online presence
        self.get_success(
            self.module_api.send_local_online_presence_to([remote_user_id])
        )

        # Check that a presence update was sent as part of a federation transaction
        found_update = False
        calls = (
            self.hs.get_federation_transport_client().send_transaction.call_args_list
        )
        for call in calls:
            call_args = call[0]
            federation_transaction = call_args[0]  # type: Transaction

            # Get the sent EDUs in this transaction
            edus = federation_transaction.get_dict()["edus"]

            for edu in edus:
                # Make sure we're only checking presence-type EDUs
                if edu["edu_type"] != EduTypes.Presence:
                    continue

                # EDUs can contain multiple presence updates
                for presence_update in edu["content"]["push"]:
                    if presence_update["user_id"] == self.presence_sender_id:
                        found_update = True

        self.assertTrue(found_update)


class ModuleApiWorkerTestCase(BaseMultiWorkerStreamTestCase):
    """For testing ModuleApi functionality in a multi-worker setup"""

    # Testing stream ID replication from the main to worker processes requires postgres
    # (due to needing `MultiWriterIdGenerator`).
    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
        presence.register_servlets,
    ]

    def default_config(self):
        conf = super().default_config()
        conf["redis"] = {"enabled": "true"}
        conf["stream_writers"] = {"presence": ["presence_writer"]}
        conf["instance_map"] = {
            "presence_writer": {"host": "testserv", "port": 1001},
        }
        return conf

    def prepare(self, reactor, clock, homeserver):
        self.module_api = homeserver.get_module_api()
        self.sync_handler = homeserver.get_sync_handler()

    def test_send_local_online_presence_to_workers(self):
        # Test sending local online presence to users from a worker process
        _test_sending_local_online_presence_to_local_user(self, test_with_workers=True)


def _test_sending_local_online_presence_to_local_user(
    test_case: HomeserverTestCase, test_with_workers: bool = False
):
    """Tests that send_local_presence_to_users sends local online presence to local users.

    This simultaneously tests two different usecases:
        * Testing that this method works when either called from a worker or the main process.
            - We test this by calling this method from both a TestCase that runs in monolith mode, and one that
              runs with a main and generic_worker.
        * Testing that multiple devices syncing simultaneously will all receive a snapshot of local,
            online presence - but only once per device.

    Args:
        test_with_workers: If True, this method will call ModuleApi.send_local_online_presence_to on a
            worker process. The test users will still sync with the main process. The purpose of testing
            with a worker is to check whether a Synapse module running on a worker can inform other workers/
            the main process that they should include additional presence when a user next syncs.
    """
    if test_with_workers:
        # Create a worker process to make module_api calls against
        worker_hs = test_case.make_worker_hs(
            "synapse.app.generic_worker", {"worker_name": "presence_writer"}
        )

    # Create a user who will send presence updates
    test_case.presence_receiver_id = test_case.register_user(
        "presence_receiver1", "monkey"
    )
    test_case.presence_receiver_tok = test_case.login("presence_receiver1", "monkey")

    # And another user that will send presence updates out
    test_case.presence_sender_id = test_case.register_user("presence_sender2", "monkey")
    test_case.presence_sender_tok = test_case.login("presence_sender2", "monkey")

    # Put them in a room together so they will receive each other's presence updates
    room_id = test_case.helper.create_room_as(
        test_case.presence_receiver_id,
        tok=test_case.presence_receiver_tok,
    )
    test_case.helper.join(
        room_id, test_case.presence_sender_id, tok=test_case.presence_sender_tok
    )

    # Presence sender comes online
    send_presence_update(
        test_case,
        test_case.presence_sender_id,
        test_case.presence_sender_tok,
        "online",
        "I'm online!",
    )

    # Presence receiver should have received it
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id
    )
    test_case.assertEqual(len(presence_updates), 1)

    presence_update = presence_updates[0]  # type: UserPresenceState
    test_case.assertEqual(presence_update.user_id, test_case.presence_sender_id)
    test_case.assertEqual(presence_update.state, "online")

    if test_with_workers:
        # Replicate the current sync presence token from the main process to the worker process.
        # We need to do this so that the worker process knows the current presence stream ID to
        # insert into the database when we call ModuleApi.send_local_online_presence_to.
        test_case.replicate()

    # Syncing again should result in no presence updates
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token
    )
    test_case.assertEqual(len(presence_updates), 0)

    # We do an (initial) sync with a second "device" now, getting a new sync token.
    # We'll use this in a moment.
    _, sync_token_second_device = sync_presence(
        test_case, test_case.presence_receiver_id
    )

    # Determine on which process (main or worker) to call ModuleApi.send_local_online_presence_to on
    if test_with_workers:
        module_api_to_use = worker_hs.get_module_api()
    else:
        module_api_to_use = test_case.module_api

    # Trigger sending local online presence. We expect this information
    # to be saved to the database where all processes can access it.
    # Note that we're syncing via the master.
    d = module_api_to_use.send_local_online_presence_to(
        [
            test_case.presence_receiver_id,
        ]
    )
    d = defer.ensureDeferred(d)

    if test_with_workers:
        # In order for the required presence_set_state replication request to occur between the
        # worker and main process, we need to pump the reactor. Otherwise, the coordinator that
        # reads the request on the main process won't do so, and the request will time out.
        while not d.called:
            test_case.reactor.advance(0.1)

    test_case.get_success(d)

    # The presence receiver should have received online presence again.
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token
    )
    test_case.assertEqual(len(presence_updates), 1)

    presence_update = presence_updates[0]  # type: UserPresenceState
    test_case.assertEqual(presence_update.user_id, test_case.presence_sender_id)
    test_case.assertEqual(presence_update.state, "online")

    # We attempt to sync with the second sync token we received above - just to check that
    # multiple syncing devices will each receive the necessary online presence.
    presence_updates, sync_token_second_device = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token_second_device
    )
    test_case.assertEqual(len(presence_updates), 1)

    presence_update = presence_updates[0]  # type: UserPresenceState
    test_case.assertEqual(presence_update.user_id, test_case.presence_sender_id)
    test_case.assertEqual(presence_update.state, "online")

    # However, if we now sync with either "device", we won't receive another burst of online presence
    # until the API is called again sometime in the future
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token
    )

    # Now we check that we don't receive *offline* updates using ModuleApi.send_local_online_presence_to.

    # Presence sender goes offline
    send_presence_update(
        test_case,
        test_case.presence_sender_id,
        test_case.presence_sender_tok,
        "offline",
        "I slink back into the darkness.",
    )

    # Presence receiver should have received the updated, offline state
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token
    )
    test_case.assertEqual(len(presence_updates), 1)

    # Now trigger sending local online presence.
    d = module_api_to_use.send_local_online_presence_to(
        [
            test_case.presence_receiver_id,
        ]
    )
    d = defer.ensureDeferred(d)

    if test_with_workers:
        # In order for the required presence_set_state replication request to occur between the
        # worker and main process, we need to pump the reactor. Otherwise, the coordinator that
        # reads the request on the main process won't do so, and the request will time out.
        while not d.called:
            test_case.reactor.advance(0.1)

    test_case.get_success(d)

    # Presence receiver should *not* have received offline state
    presence_updates, sync_token = sync_presence(
        test_case, test_case.presence_receiver_id, sync_token
    )
    test_case.assertEqual(len(presence_updates), 0)
