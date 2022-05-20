# Copyright 2020 Matrix.org Federation C.I.C
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
from collections import OrderedDict
from typing import Dict, List

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events import builder
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import RoomAlias

from tests.test_utils import event_injection
from tests.unittest import FederatingHomeserverTestCase, TestCase


class KnockingStrippedStateEventHelperMixin(TestCase):
    def send_example_state_events_to_room(
        self,
        hs: "HomeServer",
        room_id: str,
        sender: str,
    ) -> OrderedDict:
        """Adds some state to a room. State events are those that should be sent to a knocking
        user after they knock on the room, as well as some state that *shouldn't* be sent
        to the knocking user.

        Args:
            hs: The homeserver of the sender.
            room_id: The ID of the room to send state into.
            sender: The ID of the user to send state as. Must be in the room.

        Returns:
            The OrderedDict of event types and content that a user is expected to see
            after knocking on a room.
        """
        # To set a canonical alias, we'll need to point an alias at the room first.
        canonical_alias = "#fancy_alias:test"
        self.get_success(
            self.store.create_room_alias_association(
                RoomAlias.from_string(canonical_alias), room_id, ["test"]
            )
        )

        # Send some state that we *don't* expect to be given to knocking users
        self.get_success(
            event_injection.inject_event(
                hs,
                room_version=RoomVersions.V7.identifier,
                room_id=room_id,
                sender=sender,
                type="com.example.secret",
                state_key="",
                content={"secret": "password"},
            )
        )

        # We use an OrderedDict here to ensure that the knock membership appears last.
        # Note that order only matters when sending stripped state to clients, not federated
        # homeservers.
        room_state = OrderedDict(
            [
                # We need to set the room's join rules to allow knocking
                (
                    EventTypes.JoinRules,
                    {"content": {"join_rule": JoinRules.KNOCK}, "state_key": ""},
                ),
                # Below are state events that are to be stripped and sent to clients
                (
                    EventTypes.Name,
                    {"content": {"name": "A cool room"}, "state_key": ""},
                ),
                (
                    EventTypes.RoomAvatar,
                    {
                        "content": {
                            "info": {
                                "h": 398,
                                "mimetype": "image/jpeg",
                                "size": 31037,
                                "w": 394,
                            },
                            "url": "mxc://example.org/JWEIFJgwEIhweiWJE",
                        },
                        "state_key": "",
                    },
                ),
                (
                    EventTypes.RoomEncryption,
                    {"content": {"algorithm": "m.megolm.v1.aes-sha2"}, "state_key": ""},
                ),
                (
                    EventTypes.CanonicalAlias,
                    {
                        "content": {"alias": canonical_alias, "alt_aliases": []},
                        "state_key": "",
                    },
                ),
                (
                    EventTypes.Topic,
                    {
                        "content": {
                            "topic": "A really cool room",
                        },
                        "state_key": "",
                    },
                ),
            ]
        )

        for event_type, event_dict in room_state.items():
            event_content = event_dict["content"]
            state_key = event_dict["state_key"]

            self.get_success(
                event_injection.inject_event(
                    hs,
                    room_version=RoomVersions.V7.identifier,
                    room_id=room_id,
                    sender=sender,
                    type=event_type,
                    state_key=state_key,
                    content=event_content,
                )
            )

        # Finally, we expect to see the m.room.create event of the room as part of the
        # stripped state. We don't need to inject this event though.
        room_state[EventTypes.Create] = {
            "content": {
                "creator": sender,
                "room_version": RoomVersions.V7.identifier,
            },
            "state_key": "",
        }

        return room_state

    def check_knock_room_state_against_room_state(
        self,
        knock_room_state: List[Dict],
        expected_room_state: Dict,
    ) -> None:
        """Test a list of stripped room state events received over federation against a
        dict of expected state events.

        Args:
            knock_room_state: The list of room state that was received over federation.
            expected_room_state: A dict containing the room state we expect to see in
                `knock_room_state`.
        """
        for event in knock_room_state:
            event_type = event["type"]

            # Check that this event type is one of those that we expected.
            # Note: This will also check that no excess state was included
            self.assertIn(event_type, expected_room_state)

            # Check the state content matches
            self.assertEqual(
                expected_room_state[event_type]["content"], event["content"]
            )

            # Check the state key is correct
            self.assertEqual(
                expected_room_state[event_type]["state_key"], event["state_key"]
            )

            # Ensure the event has been stripped
            self.assertNotIn("signatures", event)

            # Pop once we've found and processed a state event
            expected_room_state.pop(event_type)

        # Check that all expected state events were accounted for
        self.assertEqual(len(expected_room_state), 0)


class FederationKnockingTestCase(
    FederatingHomeserverTestCase, KnockingStrippedStateEventHelperMixin
):
    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, homeserver):
        self.store = homeserver.get_datastores().main

        # We're not going to be properly signing events as our remote homeserver is fake,
        # therefore disable event signature checks.
        # Note that these checks are not relevant to this test case.

        # Have this homeserver auto-approve all event signature checking.
        async def approve_all_signature_checking(_, pdu):
            return pdu

        homeserver.get_federation_server()._check_sigs_and_hash = (
            approve_all_signature_checking
        )

        # Have this homeserver skip event auth checks. This is necessary due to
        # event auth checks ensuring that events were signed by the sender's homeserver.
        async def _check_event_auth(origin, event, context, *args, **kwargs):
            return context

        homeserver.get_federation_event_handler()._check_event_auth = _check_event_auth

        return super().prepare(reactor, clock, homeserver)

    def test_room_state_returned_when_knocking(self):
        """
        Tests that specific, stripped state events from a room are returned after
        a remote homeserver successfully knocks on a local room.
        """
        user_id = self.register_user("u1", "you the one")
        user_token = self.login("u1", "you the one")

        fake_knocking_user_id = "@user:other.example.com"

        # Create a room with a room version that includes knocking
        room_id = self.helper.create_room_as(
            "u1",
            is_public=False,
            room_version=RoomVersions.V7.identifier,
            tok=user_token,
        )

        # Update the join rules and add additional state to the room to check for later
        expected_room_state = self.send_example_state_events_to_room(
            self.hs, room_id, user_id
        )

        channel = self.make_signed_federation_request(
            "GET",
            "/_matrix/federation/v1/make_knock/%s/%s?ver=%s"
            % (
                room_id,
                fake_knocking_user_id,
                # Inform the remote that we support the room version of the room we're
                # knocking on
                RoomVersions.V7.identifier,
            ),
        )
        self.assertEqual(200, channel.code, channel.result)

        # Note: We don't expect the knock membership event to be sent over federation as
        # part of the stripped room state, as the knocking homeserver already has that
        # event. It is only done for clients during /sync

        # Extract the generated knock event json
        knock_event = channel.json_body["event"]

        # Check that the event has things we expect in it
        self.assertEqual(knock_event["room_id"], room_id)
        self.assertEqual(knock_event["sender"], fake_knocking_user_id)
        self.assertEqual(knock_event["state_key"], fake_knocking_user_id)
        self.assertEqual(knock_event["type"], EventTypes.Member)
        self.assertEqual(knock_event["content"]["membership"], Membership.KNOCK)

        # Turn the event json dict into a proper event.
        # We won't sign it properly, but that's OK as we stub out event auth in `prepare`
        signed_knock_event = builder.create_local_event_from_event_dict(
            self.clock,
            self.hs.hostname,
            self.hs.signing_key,
            room_version=RoomVersions.V7,
            event_dict=knock_event,
        )

        # Convert our proper event back to json dict format
        signed_knock_event_json = signed_knock_event.get_pdu_json(
            self.clock.time_msec()
        )

        # Send the signed knock event into the room
        channel = self.make_signed_federation_request(
            "PUT",
            "/_matrix/federation/v1/send_knock/%s/%s"
            % (room_id, signed_knock_event.event_id),
            signed_knock_event_json,
        )
        self.assertEqual(200, channel.code, channel.result)

        # Check that we got the stripped room state in return
        room_state_events = channel.json_body["knock_state_events"]

        # Validate the stripped room state events
        self.check_knock_room_state_against_room_state(
            room_state_events, expected_room_state
        )
