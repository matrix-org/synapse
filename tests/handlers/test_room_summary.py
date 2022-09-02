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
from typing import Any, Iterable, List, Optional, Tuple
from unittest import mock

from twisted.internet.defer import ensureDeferred

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    JoinRules,
    Membership,
    RestrictedJoinRuleTypes,
    RoomTypes,
)
from synapse.api.errors import AuthError, NotFoundError, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import make_event_from_dict
from synapse.federation.transport.client import TransportLayerClient
from synapse.handlers.room_summary import _child_events_comparison_key, _RoomEntry
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID, create_requester

from tests import unittest


def _create_event(room_id: str, order: Optional[Any] = None, origin_server_ts: int = 0):
    result = mock.Mock(name=room_id)
    result.room_id = room_id
    result.content = {}
    result.origin_server_ts = origin_server_ts
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

    def test_order_origin_server_ts(self):
        """Origin server  is a tie-breaker for ordering."""
        ev1 = _create_event("!abc:test", origin_server_ts=10)
        ev2 = _create_event("!xyz:test", origin_server_ts=30)

        self.assertEqual([ev1, ev2], _order(ev1, ev2))

    def test_order_room_id(self):
        """Room ID is a final tie-breaker for ordering."""
        ev1 = _create_event("!abc:test")
        ev2 = _create_event("!xyz:test")

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
        self.handler = self.hs.get_room_summary_handler()

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
        self,
        space_id: str,
        room_id: str,
        token: str,
        order: Optional[str] = None,
        via: Optional[List[str]] = None,
    ) -> None:
        """Add a child room to a space."""
        if via is None:
            via = [self.hs.hostname]

        content: JsonDict = {"via": via}
        if order is not None:
            content["order"] = order
        self.helper.send_state(
            space_id,
            event_type=EventTypes.SpaceChild,
            body=content,
            tok=token,
            state_key=room_id,
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
            # Ensure federation results are not leaking over the client-server API.
            self.assertNotIn("allowed_room_ids", result_room)

            result_room_ids.append(result_room["room_id"])
            result_children_ids.append(
                [
                    (result_room["room_id"], cs["state_key"])
                    for cs in result_room["children_state"]
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

    def _poke_fed_invite(self, room_id: str, from_user: str) -> None:
        """
        Creates a invite (as if received over federation) for the room from the
        given hostname.

        Args:
            room_id: The room ID to issue an invite for.
            fed_hostname: The user to invite from.
        """
        # Poke an invite over federation into the database.
        fed_handler = self.hs.get_federation_handler()
        fed_hostname = UserID.from_string(from_user).domain
        event = make_event_from_dict(
            {
                "room_id": room_id,
                "event_id": "!abcd:" + fed_hostname,
                "type": EventTypes.Member,
                "sender": from_user,
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

    def test_simple_space(self):
        """Test a simple space with a single room."""
        # The result should have the space and the room in it, along with a link
        # from space -> room.
        expected = [(self.space, [self.room]), (self.room, ())]

        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        self._assert_hierarchy(result, expected)

    def test_large_space(self):
        """Test a space with a large number of rooms."""
        rooms = [self.room]
        # Make at least 51 rooms that are part of the space.
        for _ in range(55):
            room = self.helper.create_room_as(self.user, tok=self.token)
            self._add_child(self.space, room, self.token)
            rooms.append(room)

        # The result should have the space and the rooms in it, along with the links
        # from space -> room.
        expected = [(self.space, rooms)] + [(room, []) for room in rooms]

        # Make two requests to fully paginate the results.
        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        result2 = self.get_success(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, from_token=result["next_batch"]
            )
        )
        # Combine the results.
        result["rooms"] += result2["rooms"]
        self._assert_hierarchy(result, expected)

    def test_visibility(self):
        """A user not in a space cannot inspect it."""
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")

        # The user can see the space since it is publicly joinable.
        expected = [(self.space, [self.room]), (self.room, ())]
        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(user2), self.space)
        )
        self._assert_hierarchy(result, expected)

        # If the space is made invite-only, it should no longer be viewable.
        self.helper.send_state(
            self.space,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(create_requester(user2), self.space),
            AuthError,
        )

        # If the space is made world-readable it should return a result.
        self.helper.send_state(
            self.space,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.WORLD_READABLE},
            tok=self.token,
        )
        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(user2), self.space)
        )
        self._assert_hierarchy(result, expected)

        # Make it not world-readable again and confirm it results in an error.
        self.helper.send_state(
            self.space,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.token,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(create_requester(user2), self.space),
            AuthError,
        )

        # Join the space and results should be returned.
        self.helper.invite(self.space, targ=user2, tok=self.token)
        self.helper.join(self.space, user2, tok=token2)
        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(user2), self.space)
        )
        self._assert_hierarchy(result, expected)

        # Attempting to view an unknown room returns the same error.
        self.get_failure(
            self.handler.get_room_hierarchy(
                create_requester(user2), "#not-a-space:" + self.hs.hostname
            ),
            AuthError,
        )

    def test_room_hierarchy_cache(self) -> None:
        """In-flight room hierarchy requests are deduplicated."""
        # Run two `get_room_hierarchy` calls up until they block.
        deferred1 = ensureDeferred(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        deferred2 = ensureDeferred(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )

        # Complete the two calls.
        result1 = self.get_success(deferred1)
        result2 = self.get_success(deferred2)

        # Both `get_room_hierarchy` calls should return the same result.
        expected = [(self.space, [self.room]), (self.room, ())]
        self._assert_hierarchy(result1, expected)
        self._assert_hierarchy(result2, expected)
        self.assertIs(result1, result2)

        # A subsequent `get_room_hierarchy` call should not reuse the result.
        result3 = self.get_success(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        self._assert_hierarchy(result3, expected)
        self.assertIsNot(result1, result3)

    def test_room_hierarchy_cache_sharing(self) -> None:
        """Room hierarchy responses for different users are not shared."""
        user2 = self.register_user("user2", "pass")

        # Make the room within the space invite-only.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )

        # Run two `get_room_hierarchy` calls for different users up until they block.
        deferred1 = ensureDeferred(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        deferred2 = ensureDeferred(
            self.handler.get_room_hierarchy(create_requester(user2), self.space)
        )

        # Complete the two calls.
        result1 = self.get_success(deferred1)
        result2 = self.get_success(deferred2)

        # The `get_room_hierarchy` calls should return different results.
        self._assert_hierarchy(result1, [(self.space, [self.room]), (self.room, ())])
        self._assert_hierarchy(result2, [(self.space, [self.room])])

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

        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(user2), self.space)
        )
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

        # The result should include each room a single time and each link.
        expected = [
            (self.space, [self.room, room2, subspace]),
            (self.room, ()),
            (subspace, [subroom, self.room, room2]),
            (subroom, ()),
        ]

        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
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
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, limit=7
            )
        )
        # The result should have the space and all of the links, plus some of the
        # rooms and a pagination token.
        expected: List[Tuple[str, Iterable[str]]] = [(self.space, room_ids)]
        expected += [(room_id, ()) for room_id in room_ids[:6]]
        self._assert_hierarchy(result, expected)
        self.assertIn("next_batch", result)

        # Check the next page.
        result = self.get_success(
            self.handler.get_room_hierarchy(
                create_requester(self.user),
                self.space,
                limit=5,
                from_token=result["next_batch"],
            )
        )
        # The result should have the space and the room in it, along with a link
        # from space -> room.
        expected = [(room_id, ()) for room_id in room_ids[6:]]
        self._assert_hierarchy(result, expected)
        self.assertNotIn("next_batch", result)

    def test_invalid_pagination_token(self):
        """An invalid pagination token, or changing other parameters, shoudl be rejected."""
        room_ids = []
        for i in range(1, 10):
            room = self.helper.create_room_as(self.user, tok=self.token)
            self._add_child(self.space, room, self.token, order=str(i))
            room_ids.append(room)
        # The room created initially doesn't have an order, so comes last.
        room_ids.append(self.room)

        result = self.get_success(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, limit=7
            )
        )
        self.assertIn("next_batch", result)

        # Changing the room ID, suggested-only, or max-depth causes an error.
        self.get_failure(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.room, from_token=result["next_batch"]
            ),
            SynapseError,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(
                create_requester(self.user),
                self.space,
                suggested_only=True,
                from_token=result["next_batch"],
            ),
            SynapseError,
        )
        self.get_failure(
            self.handler.get_room_hierarchy(
                create_requester(self.user),
                self.space,
                max_depth=0,
                from_token=result["next_batch"],
            ),
            SynapseError,
        )

        # An invalid token is ignored.
        self.get_failure(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, from_token="foo"
            ),
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
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, max_depth=0
            )
        )
        expected: List[Tuple[str, Iterable[str]]] = [(spaces[0], [rooms[0], spaces[1]])]
        self._assert_hierarchy(result, expected)

        # A single additional layer.
        result = self.get_success(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, max_depth=1
            )
        )
        expected += [
            (rooms[0], ()),
            (spaces[1], [rooms[1], spaces[2]]),
        ]
        self._assert_hierarchy(result, expected)

        # A few layers.
        result = self.get_success(
            self.handler.get_room_hierarchy(
                create_requester(self.user), self.space, max_depth=3
            )
        )
        expected += [
            (rooms[1], ()),
            (spaces[2], [rooms[2], spaces[3]]),
            (rooms[2], ()),
            (spaces[3], [rooms[3], spaces[4]]),
        ]
        self._assert_hierarchy(result, expected)

    def test_unknown_room_version(self):
        """
        If a room with an unknown room version is encountered it should not cause
        the entire summary to skip.
        """
        # Poke the database and update the room version to an unknown one.
        self.get_success(
            self.hs.get_datastores().main.db_pool.simple_update(
                "rooms",
                keyvalues={"room_id": self.room},
                updatevalues={"room_version": "unknown-room-version"},
                desc="updated-room-version",
            )
        )
        # Invalidate method so that it returns the currently updated version
        # instead of the cached version.
        self.hs.get_datastores().main.get_room_version_id.invalidate((self.room,))

        # The result should have only the space, along with a link from space -> room.
        expected = [(self.space, [self.room])]

        result = self.get_success(
            self.handler.get_room_hierarchy(create_requester(self.user), self.space)
        )
        self._assert_hierarchy(result, expected)

    def test_fed_complex(self):
        """
        Return data over federation and ensure that it is handled properly.
        """
        fed_hostname = self.hs.hostname + "2"
        subspace = "#subspace:" + fed_hostname
        subroom = "#subroom:" + fed_hostname

        # Generate some good data, and some bad data:
        #
        # * Event *back* to the root room.
        # * Unrelated events / rooms
        # * Multiple levels of events (in a not-useful order, e.g. grandchild
        #   events before child events).

        # Note that these entries are brief, but should contain enough info.
        requested_room_entry = _RoomEntry(
            subspace,
            {
                "room_id": subspace,
                "world_readable": True,
                "room_type": RoomTypes.SPACE,
            },
            [
                {
                    "type": EventTypes.SpaceChild,
                    "room_id": subspace,
                    "state_key": subroom,
                    "content": {"via": [fed_hostname]},
                }
            ],
        )
        child_room = {
            "room_id": subroom,
            "world_readable": True,
        }

        async def summarize_remote_room_hierarchy(_self, room, suggested_only):
            return requested_room_entry, {subroom: child_room}, set()

        # Add a room to the space which is on another server.
        self._add_child(self.space, subspace, self.token)

        expected = [
            (self.space, [self.room, subspace]),
            (self.room, ()),
            (subspace, [subroom]),
            (subroom, ()),
        ]

        with mock.patch(
            "synapse.handlers.room_summary.RoomSummaryHandler._summarize_remote_room_hierarchy",
            new=summarize_remote_room_hierarchy,
        ):
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
        self._assert_hierarchy(result, expected)

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
        self._poke_fed_invite(invited_room, "@remote:" + fed_hostname)

        # Note that these entries are brief, but should contain enough info.
        children_rooms = (
            (
                public_room,
                {
                    "room_id": public_room,
                    "world_readable": False,
                    "join_rule": JoinRules.PUBLIC,
                },
            ),
            (
                knock_room,
                {
                    "room_id": knock_room,
                    "world_readable": False,
                    "join_rule": JoinRules.KNOCK,
                },
            ),
            (
                not_invited_room,
                {
                    "room_id": not_invited_room,
                    "world_readable": False,
                    "join_rule": JoinRules.INVITE,
                },
            ),
            (
                invited_room,
                {
                    "room_id": invited_room,
                    "world_readable": False,
                    "join_rule": JoinRules.INVITE,
                },
            ),
            (
                restricted_room,
                {
                    "room_id": restricted_room,
                    "world_readable": False,
                    "join_rule": JoinRules.RESTRICTED,
                    "allowed_room_ids": [],
                },
            ),
            (
                restricted_accessible_room,
                {
                    "room_id": restricted_accessible_room,
                    "world_readable": False,
                    "join_rule": JoinRules.RESTRICTED,
                    "allowed_room_ids": [self.room],
                },
            ),
            (
                world_readable_room,
                {
                    "room_id": world_readable_room,
                    "world_readable": True,
                    "join_rule": JoinRules.INVITE,
                },
            ),
            (
                joined_room,
                {
                    "room_id": joined_room,
                    "world_readable": False,
                    "join_rule": JoinRules.INVITE,
                },
            ),
        )

        subspace_room_entry = _RoomEntry(
            subspace,
            {
                "room_id": subspace,
                "world_readable": True,
            },
            # Place each room in the sub-space.
            [
                {
                    "type": EventTypes.SpaceChild,
                    "room_id": subspace,
                    "state_key": room_id,
                    "content": {"via": [fed_hostname]},
                }
                for room_id, _ in children_rooms
            ],
        )

        async def summarize_remote_room_hierarchy(_self, room, suggested_only):
            return subspace_room_entry, dict(children_rooms), set()

        # Add a room to the space which is on another server.
        self._add_child(self.space, subspace, self.token)

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

        with mock.patch(
            "synapse.handlers.room_summary.RoomSummaryHandler._summarize_remote_room_hierarchy",
            new=summarize_remote_room_hierarchy,
        ):
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
        self._assert_hierarchy(result, expected)

    def test_fed_invited(self):
        """
        A room which the user was invited to should be included in the response.

        This differs from test_fed_filtering in that the room itself is being
        queried over federation, instead of it being included as a sub-room of
        a space in the response.
        """
        fed_hostname = self.hs.hostname + "2"
        fed_room = "#subroom:" + fed_hostname

        # Poke an invite over federation into the database.
        self._poke_fed_invite(fed_room, "@remote:" + fed_hostname)

        fed_room_entry = _RoomEntry(
            fed_room,
            {
                "room_id": fed_room,
                "world_readable": False,
                "join_rule": JoinRules.INVITE,
            },
        )

        async def summarize_remote_room_hierarchy(_self, room, suggested_only):
            return fed_room_entry, {}, set()

        # Add a room to the space which is on another server.
        self._add_child(self.space, fed_room, self.token)

        expected = [
            (self.space, [self.room, fed_room]),
            (self.room, ()),
            (fed_room, ()),
        ]

        with mock.patch(
            "synapse.handlers.room_summary.RoomSummaryHandler._summarize_remote_room_hierarchy",
            new=summarize_remote_room_hierarchy,
        ):
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
        self._assert_hierarchy(result, expected)

    def test_fed_caching(self):
        """
        Federation `/hierarchy` responses should be cached.
        """
        fed_hostname = self.hs.hostname + "2"
        fed_subspace = "#space:" + fed_hostname
        fed_room = "#room:" + fed_hostname

        # Add a room to the space which is on another server.
        self._add_child(self.space, fed_subspace, self.token, via=[fed_hostname])

        federation_requests = 0

        async def get_room_hierarchy(
            _self: TransportLayerClient,
            destination: str,
            room_id: str,
            suggested_only: bool,
        ) -> JsonDict:
            nonlocal federation_requests
            federation_requests += 1

            return {
                "room": {
                    "room_id": fed_subspace,
                    "world_readable": True,
                    "room_type": RoomTypes.SPACE,
                    "children_state": [
                        {
                            "type": EventTypes.SpaceChild,
                            "room_id": fed_subspace,
                            "state_key": fed_room,
                            "content": {"via": [fed_hostname]},
                        },
                    ],
                },
                "children": [
                    {
                        "room_id": fed_room,
                        "world_readable": True,
                    },
                ],
                "inaccessible_children": [],
            }

        expected = [
            (self.space, [self.room, fed_subspace]),
            (self.room, ()),
            (fed_subspace, [fed_room]),
            (fed_room, ()),
        ]

        with mock.patch(
            "synapse.federation.transport.client.TransportLayerClient.get_room_hierarchy",
            new=get_room_hierarchy,
        ):
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
            self.assertEqual(federation_requests, 1)
            self._assert_hierarchy(result, expected)

            # The previous federation response should be reused.
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
            self.assertEqual(federation_requests, 1)
            self._assert_hierarchy(result, expected)

            # Expire the response cache
            self.reactor.advance(5 * 60 + 1)

            # A new federation request should be made.
            result = self.get_success(
                self.handler.get_room_hierarchy(create_requester(self.user), self.space)
            )
            self.assertEqual(federation_requests, 2)
            self._assert_hierarchy(result, expected)


class RoomSummaryTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets_for_client_rest_resource,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs: HomeServer):
        self.hs = hs
        self.handler = self.hs.get_room_summary_handler()

        # Create a user.
        self.user = self.register_user("user", "pass")
        self.token = self.login("user", "pass")

        # Create a simple room.
        self.room = self.helper.create_room_as(self.user, tok=self.token)
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )

    def test_own_room(self):
        """Test a simple room created by the requester."""
        result = self.get_success(self.handler.get_room_summary(self.user, self.room))
        self.assertEqual(result.get("room_id"), self.room)

    def test_visibility(self):
        """A user not in a private room cannot get its summary."""
        user2 = self.register_user("user2", "pass")
        token2 = self.login("user2", "pass")

        # The user cannot see the room.
        self.get_failure(self.handler.get_room_summary(user2, self.room), NotFoundError)

        # If the room is made world-readable it should return a result.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.WORLD_READABLE},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)

        # Make it not world-readable again and confirm it results in an error.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.RoomHistoryVisibility,
            body={"history_visibility": HistoryVisibility.JOINED},
            tok=self.token,
        )
        self.get_failure(self.handler.get_room_summary(user2, self.room), NotFoundError)

        # If the room is made public it should return a result.
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.PUBLIC},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)

        # Join the space, make it invite-only again and results should be returned.
        self.helper.join(self.room, user2, tok=token2)
        self.helper.send_state(
            self.room,
            event_type=EventTypes.JoinRules,
            body={"join_rule": JoinRules.INVITE},
            tok=self.token,
        )
        result = self.get_success(self.handler.get_room_summary(user2, self.room))
        self.assertEqual(result.get("room_id"), self.room)

    def test_fed(self):
        """
        Return data over federation and ensure that it is handled properly.
        """
        fed_hostname = self.hs.hostname + "2"
        fed_room = "#fed_room:" + fed_hostname

        requested_room_entry = _RoomEntry(
            fed_room,
            {"room_id": fed_room, "world_readable": True},
        )

        async def summarize_remote_room_hierarchy(_self, room, suggested_only):
            return requested_room_entry, {}, set()

        with mock.patch(
            "synapse.handlers.room_summary.RoomSummaryHandler._summarize_remote_room_hierarchy",
            new=summarize_remote_room_hierarchy,
        ):
            result = self.get_success(
                self.handler.get_room_summary(
                    self.user, fed_room, remote_room_hosts=[fed_hostname]
                )
            )
        self.assertEqual(result.get("room_id"), fed_room)
