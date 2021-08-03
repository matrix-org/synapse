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
from typing import Any, Iterable, Optional, Tuple
from unittest import mock

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    JoinRules,
    Membership,
    RestrictedJoinRuleTypes,
    RoomTypes,
)
from synapse.api.errors import AuthError, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import make_event_from_dict
from synapse.handlers.space_summary import _child_events_comparison_key, _RoomEntry
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict

from tests import unittest


def _create_event(room_id: str, order: Optional[Any] = None):
    result = mock.Mock()
    result.room_id = room_id
    result.content = {}
    if order is not None:
        result.content["order"] = order
    return result


def _order(*events):
    return sorted(events, key=_child_events_comparison_key)


class TestSpaceSummarySort(unittest.TestCase):
    def test_no_order_last(self):
        """An event with no ordering is placed behind those with an ordering."""
        ev1 = _create_event("!abc:test")
        ev2 = _create_event("!xyz:test", "xyz")

        self.assertEqual([ev2, ev1], _order(ev1, ev2))

    def test_order(self):
        """The ordering should be used."""
        ev1 = _create_event("!abc:test", "xyz")
        ev2 = _create_event("!xyz:test", "abc")

        self.assertEqual([ev2, ev1], _order(ev1, ev2))

    def test_order_room_id(self):
        """Room ID is a tie-breaker for ordering."""
        ev1 = _create_event("!abc:test", "abc")
        ev2 = _create_event("!xyz:test", "abc")

        self.assertEqual([ev1, ev2], _order(ev1, ev2))

    def test_invalid_ordering_type(self):
        """Invalid orderings are considered the same as missing."""
        ev1 = _create_event("!abc:test", 1)
        ev2 = _create_event("!xyz:test", "xyz")

        self.assertEqual([ev2, ev1], _order(ev1, ev2))

        ev1 = _create_event("!abc:test", {})
        self.assertEqual([ev2, ev1], _order(ev1, ev2))

        ev1 = _create_event("!abc:test", [])
        self.assertEqual([ev2, ev1], _order(ev1, ev2))

        ev1 = _create_event("!abc:test", True)
        self.assertEqual([ev2, ev1], _order(ev1, ev2))

    def test_invalid_ordering_value(self):
        """Invalid orderings are considered the same as missing."""
        ev1 = _create_event("!abc:test", "foo\n")
        ev2 = _create_event("!xyz:test", "xyz")

        self.assertEqual([ev2, ev1], _order(ev1, ev2))

        ev1 = _create_event("!abc:test", "a" * 51)
        self.assertEqual([ev2, ev1], _order(ev1, ev2))


class SpaceSummaryTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.hs = hs
        self.handler = self.hs.get_space_summary_handler()

        # Create a user.
        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

        # Create a space and a child room.
        self.space = self.helper.create_room_as(
            self.user,
            tok=self.token,
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )
        self.room = self.helper.create_room_as(self.user, tok=self.token)
        self._add_child(self.space, self.room, self.token)

    def _add_child(
        self, space_id: str, room_id: str, token: str, order: Optional[str] = None
    ) -> None:
        """Add a child room to a space."""
        content = {"via": [self.hs.hostname]}
        if order is not None:
            content["order"] = order
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body=content,
            tok=token,
            state_key=room_id,
        )

    def _assert_rooms(
        self, result: JsonDict, rooms_and_children: Iterable[Tuple[str, Iterable[str]]]
    ) -> None:
        """
        Assert that the expected room IDs and events are in the response.

        Args:
            result: The result from the API call.
            rooms_and_children: An iterable of tuples where each tuple is:
                The expected room ID.
                The expected IDs of any children rooms.
        """
        room_ids = []
        children_ids = []
        for room_id, children in rooms_and_children:
            room_ids.append(room_id)
            if children:
                children_ids.extend([(room_id, child_id) for child_id in children])
        self.assertCountEqual(
            [room.get("room_id") for room in result["rooms"]], room_ids
        )
        self.assertCountEqual(
            [
                (event.get("room_id"), event.get("state_key"))
                for event in result["events"]
            ],
            children_ids,
        )

    def _assert_hierarchy(
        self, result: JsonDict, rooms_and_children: Iterable[Tuple[str, Iterable[str]]]
    ) -> None:
        """
        Assert that the expected room IDs are in the response.

        Args:
            result: The result from the API call.
            rooms_and_children: An iterable of tuples where each tuple is:
                The expected room ID.
                The expected IDs of any children rooms.
        """
        result_room_ids = []
        result_children_ids = []
        for result_room in result["rooms"]:
            result_room_ids.append(result_room["room_id"])
            result_children_ids.append(
                [
                    (cs["room_id"], cs["state_key"])
                    for cs in result_room.get("children_state")
                ]
            )

        room_ids = []
        children_ids = []
        for room_id, children in rooms_and_children:
            room_ids.append(room_id)
            children_ids.append([(room_id, child_id) for child_id in children])

        # Note that order matters.
        self.assertEqual(result_room_ids, room_ids)
        self.assertEqual(result_children_ids, children_ids)

    def test_simple_space(self):
        """Test a simple space with a single room."""
        result = self.get_success(self.handler.get_space_summary(self.user, self.space))
        # The result should have the space and the room in it, along with a link
        # from space -> room.
        expected = [(self.space, [self.room]), (self.room, ())]
        self._assert_rooms(result, expected)

        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space)
        )
        self._assert_hierarchy(result, expected)

    def test_visibility(self):
        """A user not in a space cannot inspect it."""
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")

        # The user cannot see the space.
        self.get_failure(self.handler.get_space_summary(user2, self.space), AuthError)
        self.get_failure(self.handler.get_room_hierarchy(user2, self.space), AuthError)

        # If the space is made world-readable it should return a result.
        self.helper.send_state(
            self.space,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.WORLD_READABLE},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_space_summary(user2, self.space))
        expected = [(self.space, [self.room]), (self.room, ())]
        self._assert_rooms(result, expected)

        result = self.get_success(self.handler.get_room_hierarchy(user2, self.space))
        self._assert_hierarchy(result, expected)

        # Make it not world-readable again and confirm it results in an error.
        self.helper.send_state(
            self.space,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.token,
        )
        self.get_failure(self.handler.get_space_summary(user2, self.space), AuthError)
        self.get_failure(self.handler.get_room_hierarchy(user2, self.space), AuthError)

        # Join the space and results should be returned.
        self.helper.join(self.space, user2, tok=token2)
        result = self.get_success(self.handler.get_space_summary(user2, self.space))
        self._assert_rooms(result, expected)

        result = self.get_success(self.handler.get_room_hierarchy(user2, self.space))
        self._assert_hierarchy(result, expected)

    def _create_room_with_join_rule(
        self, join_rule: str, room_version: Optional[str] = None, **extra_content
    ) -> str:
        """Create a room with the given join rule and add it to the space."""
        room_id = self.helper.create_room_as(
            self.user,
            room_version=room_version,
            tok=self.token,
            extra_content={
                "initial_state": [
                    {
                        "type": EventTypes.JoinRules,
                        "state_key": "",
                        "content": {
                            "join_rule": join_rule,
                            **extra_content,
                        },
                    }
                ]
            },
        )
        self._add_child(self.space, room_id, self.token)
        return room_id

    def test_filtering(self):
        """
        Rooms should be properly filtered to only include rooms the user has access to.
        """
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")

        # Create a few rooms which will have different properties.
        public_room = self._create_room_with_join_rule(JoinRules.PUBLIC)
        knock_room = self._create_room_with_join_rule(
            JoinRules.KNOCK, room_version=RoomVersions.V7.identifier
        )
        not_invited_room = self._create_room_with_join_rule(JoinRules.INVITE)
        invited_room = self._create_room_with_join_rule(JoinRules.INVITE)
        self.helper.invite(invited_room, targ=user2, tok=self.token)
        restricted_room = self._create_room_with_join_rule(
            JoinRules.RESTRICTED,
            room_version=RoomVersions.V8.identifier,
            allow=[],
        )
        restricted_accessible_room = self._create_room_with_join_rule(
            JoinRules.RESTRICTED,
            room_version=RoomVersions.V8.identifier,
            allow=[
                {
                    "type": RestrictedJoinRuleTypes.ROOM_MEMBERSHIP,
                    "room_id": self.space,
                    "via": [self.hs.hostname],
                }
            ],
        )
        world_readable_room = self._create_room_with_join_rule(JoinRules.INVITE)
        self.helper.send_state(
            world_readable_room,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.WORLD_READABLE},
            tok=self.token,
        )
        joined_room = self._create_room_with_join_rule(JoinRules.INVITE)
        self.helper.invite(joined_room, targ=user2, tok=self.token)
        self.helper.join(joined_room, user2, tok=token2)

        # Join the space.
        self.helper.join(self.space, user2, tok=token2)
        result = self.get_success(self.handler.get_space_summary(user2, self.space))
        expected = [
            (
                self.space,
                [
                    self.room,
                    public_room,
                    knock_room,
                    not_invited_room,
                    invited_room,
                    restricted_room,
                    restricted_accessible_room,
                    world_readable_room,
                    joined_room,
                ],
            ),
            (self.room, ()),
            (public_room, ()),
            (knock_room, ()),
            (invited_room, ()),
            (restricted_accessible_room, ()),
            (world_readable_room, ()),
            (joined_room, ()),
        ]
        self._assert_rooms(result, expected)

        result = self.get_success(self.handler.get_room_hierarchy(user2, self.space))
        self._assert_hierarchy(result, expected)

    def test_complex_space(self):
        """
        Create a "complex" space to see how it handles things like loops and subspaces.
        """
        # Create an inaccessible room.
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")
        room2 = self.helper.create_room_as(user2, is_public=False, tok=token2)
        # This is a bit odd as "user" is adding a room they don't know about, but
        # it works for the tests.
        self._add_child(self.space, room2, self.token)

        # Create a subspace under the space with an additional room in it.
        subspace = self.helper.create_room_as(
            self.user,
            tok=self.token,
            extra_content={
                "creation_content": {EventContentFields.ROOM_TYPE: RoomTypes.SPACE}
            },
        )
        subroom = self.helper.create_room_as(self.user, tok=self.token)
        self._add_child(self.space, subspace, token=self.token)
        self._add_child(subspace, subroom, token=self.token)
        # Also add the two rooms from the space into this subspace (causing loops).
        self._add_child(subspace, self.room, token=self.token)
        self._add_child(subspace, room2, self.token)

        result = self.get_success(self.handler.get_space_summary(self.user, self.space))

        # The result should include each room a single time and each link.
        expected = [
            (self.space, [self.room, room2, subspace]),
            (self.room, ()),
            (subspace, [subroom, self.room, room2]),
            (subroom, ()),
        ]
        self._assert_rooms(result, expected)

        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space)
        )
        self._assert_hierarchy(result, expected)

    def test_pagination(self):
        """Test simple pagination works."""
        room_ids = []
        for i in range(1, 10):
            room = self.helper.create_room_as(self.user, tok=self.token)
            self._add_child(self.space, room, self.token, order=str(i))
            room_ids.append(room)
        # The room created initially doesn't have an order, so comes last.
        room_ids.append(self.room)

        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space, limit=7)
        )
        # The result should have the space and all of the links, plus some of the
        # rooms and a pagination token.
        expected = [(self.space, room_ids)] + [
            (room_id, ()) for room_id in room_ids[:6]
        ]
        self._assert_hierarchy(result, expected)
        self.assertIn("next_token", result)

        # Check the next page.
        result = self.get_success(
            self.handler.get_room_hierarchy(
                self.user, self.space, limit=5, from_token=result["next_token"]
            )
        )
        # The result should have the space and the room in it, along with a link
        # from space -> room.
        expected = [(room_id, ()) for room_id in room_ids[6:]]
        self._assert_hierarchy(result, expected)
        self.assertNotIn("next_token", result)

    def test_invalid_pagination_token(self):
        """"""
        room_ids = []
        for i in range(1, 10):
            room = self.helper.create_room_as(self.user, tok=self.token)
            self._add_child(self.space, room, self.token, order=str(i))
            room_ids.append(room)
        # The room created initially doesn't have an order, so comes last.
        room_ids.append(self.room)

        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space, limit=7)
        )
        self.assertIn("next_token", result)

        # Changing the room ID, suggested-only, or max-depth causes an error.
        self.get_failure(
            self.handler.get_room_hierarchy(
                self.user, self.room, from_token=result["next_token"]
            ),
            SynapseError,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(
                self.user,
                self.space,
                suggested_only=True,
                from_token=result["next_token"],
            ),
            SynapseError,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(
                self.user, self.space, max_depth=0, from_token=result["next_token"]
            ),
            SynapseError,
        )

        # An invalid token is ignored.
        self.get_failure(
            self.handler.get_room_hierarchy(self.user, self.space, from_token="foo"),
            SynapseError,
        )

    def test_max_depth(self):
        """Create a deep tree to test the max depth against."""
        spaces = [self.space]
        rooms = [self.room]
        for _ in range(5):
            spaces.append(
                self.helper.create_room_as(
                    self.user,
                    tok=self.token,
                    extra_content={
                        "creation_content": {
                            EventContentFields.ROOM_TYPE: RoomTypes.SPACE
                        }
                    },
                )
            )
            self._add_child(spaces[-2], spaces[-1], self.token)
            rooms.append(self.helper.create_room_as(self.user, tok=self.token))
            self._add_child(spaces[-1], rooms[-1], self.token)

        # Test just the space itself.
        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space, max_depth=0)
        )
        expected = [(spaces[0], [rooms[0], spaces[1]])]
        self._assert_hierarchy(result, expected)

        # A single additional layer.
        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space, max_depth=1)
        )
        expected += [
            (rooms[0], ()),
            (spaces[1], [rooms[1], spaces[2]]),
        ]
        self._assert_hierarchy(result, expected)

        # A few layers.
        result = self.get_success(
            self.handler.get_room_hierarchy(self.user, self.space, max_depth=3)
        )
        expected += [
            (rooms[1], ()),
            (spaces[2], [rooms[2], spaces[3]]),
            (rooms[2], ()),
            (spaces[3], [rooms[3], spaces[4]]),
        ]
        self._assert_hierarchy(result, expected)

    def test_fed_complex(self):
        """
        Return data over federation and ensure that it is handled properly.
        """
        fed_hostname = self.hs.hostname + "2"
        subspace = "#subspace:" + fed_hostname
        subroom = "#subroom:" + fed_hostname

        async def summarize_remote_room(
            _self, room, suggested_only, max_children, exclude_rooms
        ):
            # Return some good data, and some bad data:
            #
            # * Event *back* to the root room.
            # * Unrelated events / rooms
            # * Multiple levels of events (in a not-useful order, e.g. grandchild
            #   events before child events).

            # Note that these entries are brief, but should contain enough info.
            return [
                _RoomEntry(
                    subspace,
                    {
                        "room_id": subspace,
                        "world_readable": True,
                        "room_type": RoomTypes.SPACE,
                    },
                    [
                        {
                            "room_id": subspace,
                            "state_key": subroom,
                            "content": {"via": [fed_hostname]},
                        }
                    ],
                ),
                _RoomEntry(
                    subroom,
                    {
                        "room_id": subroom,
                        "world_readable": True,
                    },
                ),
            ]

        # Add a room to the space which is on another server.
        self._add_child(self.space, subspace, self.token)

        with mock.patch(
            "synapse.handlers.space_summary.SpaceSummaryHandler._summarize_remote_room",
            new=summarize_remote_room,
        ):
            result = self.get_success(
                self.handler.get_space_summary(self.user, self.space)
            )

        expected = [
            (self.space, [self.room, subspace]),
            (self.room, ()),
            (subspace, [subroom]),
            (subroom, ()),
        ]
        self._assert_rooms(result, expected)

    def test_fed_filtering(self):
        """
        Rooms returned over federation should be properly filtered to only include
        rooms the user has access to.
        """
        fed_hostname = self.hs.hostname + "2"
        subspace = "#subspace:" + fed_hostname

        # Create a few rooms which will have different properties.
        public_room = "#public:" + fed_hostname
        knock_room = "#knock:" + fed_hostname
        not_invited_room = "#not_invited:" + fed_hostname
        invited_room = "#invited:" + fed_hostname
        restricted_room = "#restricted:" + fed_hostname
        restricted_accessible_room = "#restricted_accessible:" + fed_hostname
        world_readable_room = "#world_readable:" + fed_hostname
        joined_room = self.helper.create_room_as(self.user, tok=self.token)

        # Poke an invite over federation into the database.
        fed_handler = self.hs.get_federation_handler()
        event = make_event_from_dict(
            {
                "room_id": invited_room,
                "event_id": "!abcd:" + fed_hostname,
                "type": EventTypes.Member,
                "sender": "@remote:" + fed_hostname,
                "state_key": self.user,
                "content": {"membership": Membership.INVITE},
                "prev_events": [],
                "auth_events": [],
                "depth": 1,
                "origin_server_ts": 1234,
            }
        )
        self.get_success(
            fed_handler.on_invite_request(fed_hostname, event, RoomVersions.V6)
        )

        async def summarize_remote_room(
            _self, room, suggested_only, max_children, exclude_rooms
        ):
            # Note that these entries are brief, but should contain enough info.
            rooms = [
                _RoomEntry(
                    public_room,
                    {
                        "room_id": public_room,
                        "world_readable": False,
                        "join_rules": JoinRules.PUBLIC,
                    },
                ),
                _RoomEntry(
                    knock_room,
                    {
                        "room_id": knock_room,
                        "world_readable": False,
                        "join_rules": JoinRules.KNOCK,
                    },
                ),
                _RoomEntry(
                    not_invited_room,
                    {
                        "room_id": not_invited_room,
                        "world_readable": False,
                        "join_rules": JoinRules.INVITE,
                    },
                ),
                _RoomEntry(
                    invited_room,
                    {
                        "room_id": invited_room,
                        "world_readable": False,
                        "join_rules": JoinRules.INVITE,
                    },
                ),
                _RoomEntry(
                    restricted_room,
                    {
                        "room_id": restricted_room,
                        "world_readable": False,
                        "join_rules": JoinRules.RESTRICTED,
                        "allowed_spaces": [],
                    },
                ),
                _RoomEntry(
                    restricted_accessible_room,
                    {
                        "room_id": restricted_accessible_room,
                        "world_readable": False,
                        "join_rules": JoinRules.RESTRICTED,
                        "allowed_spaces": [self.room],
                    },
                ),
                _RoomEntry(
                    world_readable_room,
                    {
                        "room_id": world_readable_room,
                        "world_readable": True,
                        "join_rules": JoinRules.INVITE,
                    },
                ),
                _RoomEntry(
                    joined_room,
                    {
                        "room_id": joined_room,
                        "world_readable": False,
                        "join_rules": JoinRules.INVITE,
                    },
                ),
            ]

            # Also include the subspace.
            rooms.insert(
                0,
                _RoomEntry(
                    subspace,
                    {
                        "room_id": subspace,
                        "world_readable": True,
                    },
                    # Place each room in the sub-space.
                    [
                        {
                            "room_id": subspace,
                            "state_key": room.room_id,
                            "content": {"via": [fed_hostname]},
                        }
                        for room in rooms
                    ],
                ),
            )
            return rooms

        # Add a room to the space which is on another server.
        self._add_child(self.space, subspace, self.token)

        with mock.patch(
            "synapse.handlers.space_summary.SpaceSummaryHandler._summarize_remote_room",
            new=summarize_remote_room,
        ):
            result = self.get_success(
                self.handler.get_space_summary(self.user, self.space)
            )

        expected = [
            (self.space, [self.room, subspace]),
            (self.room, ()),
            (
                subspace,
                [
                    public_room,
                    knock_room,
                    not_invited_room,
                    invited_room,
                    restricted_room,
                    restricted_accessible_room,
                    world_readable_room,
                    joined_room,
                ],
            ),
            (public_room, ()),
            (knock_room, ()),
            (invited_room, ()),
            (restricted_accessible_room, ()),
            (world_readable_room, ()),
            (joined_room, ()),
        ]
        self._assert_rooms(result, expected)
