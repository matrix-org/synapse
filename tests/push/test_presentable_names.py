#  Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Iterable, Optional, Tuple

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events import FrozenEvent
from synapse.push.presentable_names import calculate_room_name
from synapse.types import StateKey, StateMap

from tests import unittest


class MockDataStore:
    """
    A fake data store which stores a mapping of state key to event content.
    (I.e. the state key is used as the event ID.)
    """

    def __init__(self, events: Iterable[Tuple[StateKey, dict]]):
        """
        Args:
            events: A state map to event contents.
        """
        self._events = {}

        for i, (event_id, content) in enumerate(events):
            self._events[event_id] = FrozenEvent(
                {
                    "event_id": "$event_id",
                    "type": event_id[0],
                    "sender": "@user:test",
                    "state_key": event_id[1],
                    "room_id": "#room:test",
                    "content": content,
                    "origin_server_ts": i,
                },
                RoomVersions.V1,
            )

    async def get_event(
        self, event_id: StateKey, allow_none: bool = False
    ) -> Optional[FrozenEvent]:
        assert allow_none, "Mock not configured for allow_none = False"

        return self._events.get(event_id)

    async def get_events(self, event_ids: Iterable[StateKey]):
        # This is cheating since it just returns all events.
        return self._events


class PresentableNamesTestCase(unittest.HomeserverTestCase):
    USER_ID = "@test:test"
    OTHER_USER_ID = "@user:test"

    def _calculate_room_name(
        self,
        events: StateMap[dict],
        user_id: str = "",
        fallback_to_members: bool = True,
        fallback_to_single_member: bool = True,
    ):
        # This isn't 100% accurate, but works with MockDataStore.
        room_state_ids = {k[0]: k[0] for k in events}

        return self.get_success(
            calculate_room_name(
                MockDataStore(events),
                room_state_ids,
                user_id or self.USER_ID,
                fallback_to_members,
                fallback_to_single_member,
            )
        )

    def test_name(self):
        """A room name event should be used."""
        events = [
            ((EventTypes.Name, ""), {"name": "test-name"}),
        ]
        self.assertEqual("test-name", self._calculate_room_name(events))

        # Check if the event content has garbage.
        events = [((EventTypes.Name, ""), {"foo": 1})]
        self.assertEqual("Empty Room", self._calculate_room_name(events))

        events = [((EventTypes.Name, ""), {"name": 1})]
        self.assertEqual(1, self._calculate_room_name(events))

    def test_canonical_alias(self):
        """An canonical alias should be used."""
        events = [
            ((EventTypes.CanonicalAlias, ""), {"alias": "#test-name:test"}),
        ]
        self.assertEqual("#test-name:test", self._calculate_room_name(events))

        # Check if the event content has garbage.
        events = [((EventTypes.CanonicalAlias, ""), {"foo": 1})]
        self.assertEqual("Empty Room", self._calculate_room_name(events))

        events = [((EventTypes.CanonicalAlias, ""), {"alias": "test-name"})]
        self.assertEqual("Empty Room", self._calculate_room_name(events))

    def test_invite(self):
        """An invite has special behaviour."""
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.INVITE}),
            ((EventTypes.Member, self.OTHER_USER_ID), {"displayname": "Other User"}),
        ]
        self.assertEqual("Invite from Other User", self._calculate_room_name(events))
        self.assertIsNone(
            self._calculate_room_name(events, fallback_to_single_member=False)
        )
        # Ensure this logic is skipped if we don't fallback to members.
        self.assertIsNone(self._calculate_room_name(events, fallback_to_members=False))

        # Check if the event content has garbage.
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.INVITE}),
            ((EventTypes.Member, self.OTHER_USER_ID), {"foo": 1}),
        ]
        self.assertEqual("Invite from @user:test", self._calculate_room_name(events))

        # No member event for sender.
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.INVITE}),
        ]
        self.assertEqual("Room Invite", self._calculate_room_name(events))

    def test_no_members(self):
        """Behaviour of an empty room."""
        events = []
        self.assertEqual("Empty Room", self._calculate_room_name(events))

        # Note that events with invalid (or missing) membership are ignored.
        events = [
            ((EventTypes.Member, self.OTHER_USER_ID), {"foo": 1}),
            ((EventTypes.Member, "@foo:test"), {"membership": "foo"}),
        ]
        self.assertEqual("Empty Room", self._calculate_room_name(events))

    def test_no_other_members(self):
        """Behaviour of a room with no other members in it."""
        events = [
            (
                (EventTypes.Member, self.USER_ID),
                {"membership": Membership.JOIN, "displayname": "Me"},
            ),
        ]
        self.assertEqual("Me", self._calculate_room_name(events))

        # Check if the event content has no displayname.
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.JOIN}),
        ]
        self.assertEqual("@test:test", self._calculate_room_name(events))

        # 3pid invite, use the other user (who is set as the sender).
        events = [
            ((EventTypes.Member, self.OTHER_USER_ID), {"membership": Membership.JOIN}),
        ]
        self.assertEqual(
            "nobody", self._calculate_room_name(events, user_id=self.OTHER_USER_ID)
        )

        events = [
            ((EventTypes.Member, self.OTHER_USER_ID), {"membership": Membership.JOIN}),
            ((EventTypes.ThirdPartyInvite, self.OTHER_USER_ID), {}),
        ]
        self.assertEqual(
            "Inviting email address",
            self._calculate_room_name(events, user_id=self.OTHER_USER_ID),
        )

    def test_one_other_member(self):
        """Behaviour of a room with a single other member."""
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.JOIN}),
            (
                (EventTypes.Member, self.OTHER_USER_ID),
                {"membership": Membership.JOIN, "displayname": "Other User"},
            ),
        ]
        self.assertEqual("Other User", self._calculate_room_name(events))
        self.assertIsNone(
            self._calculate_room_name(events, fallback_to_single_member=False)
        )

        # Check if the event content has no displayname and is an invite.
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.JOIN}),
            (
                (EventTypes.Member, self.OTHER_USER_ID),
                {"membership": Membership.INVITE},
            ),
        ]
        self.assertEqual("@user:test", self._calculate_room_name(events))

    def test_other_members(self):
        """Behaviour of a room with multiple other members."""
        # Two other members.
        events = [
            ((EventTypes.Member, self.USER_ID), {"membership": Membership.JOIN}),
            (
                (EventTypes.Member, self.OTHER_USER_ID),
                {"membership": Membership.JOIN, "displayname": "Other User"},
            ),
            ((EventTypes.Member, "@foo:test"), {"membership": Membership.JOIN}),
        ]
        self.assertEqual("Other User and @foo:test", self._calculate_room_name(events))

        # Three or more other members.
        events.append(
            ((EventTypes.Member, "@fourth:test"), {"membership": Membership.INVITE})
        )
        self.assertEqual("Other User and 2 others", self._calculate_room_name(events))
