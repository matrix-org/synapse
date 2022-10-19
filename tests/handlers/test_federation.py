# Copyright 2019 The Matrix.org Foundation C.I.C.
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
import logging
from typing import cast
from unittest import TestCase
from unittest.mock import Mock, patch

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes
from synapse.api.errors import (
    AuthError,
    Codes,
    LimitExceededError,
    NotFoundError,
    SynapseError,
)
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase, make_event_from_dict
from synapse.federation.federation_base import event_from_pdu_json
from synapse.federation.federation_client import SendJoinResult
from synapse.logging.context import LoggingContext, run_in_background
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.storage.databases.main.events_worker import EventCacheEntry
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import event_injection, make_awaitable

logger = logging.getLogger(__name__)


def generate_fake_event_id() -> str:
    return "$fake_" + random_string(43)


class FederationTestCase(unittest.FederatingHomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor: MemoryReactor, clock: Clock) -> HomeServer:
        hs = self.setup_test_homeserver(federation_http_client=None)
        self.handler = hs.get_federation_handler()
        self.store = hs.get_datastores().main
        return hs

    def test_exchange_revoked_invite(self) -> None:
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)

        # Send a 3PID invite event with an empty body so it's considered as a revoked one.
        invite_token = "sometoken"
        self.helper.send_state(
            room_id=room_id,
            event_type=EventTypes.ThirdPartyInvite,
            state_key=invite_token,
            body={},
            tok=tok,
        )

        d = self.handler.on_exchange_third_party_invite_request(
            event_dict={
                "type": EventTypes.Member,
                "room_id": room_id,
                "sender": user_id,
                "state_key": "@someone:example.org",
                "content": {
                    "membership": "invite",
                    "third_party_invite": {
                        "display_name": "alice",
                        "signed": {
                            "mxid": "@alice:localhost",
                            "token": invite_token,
                            "signatures": {
                                "magic.forest": {
                                    "ed25519:3": "fQpGIW1Snz+pwLZu6sTy2aHy/DYWWTspTJRPyNp0PKkymfIsNffysMl6ObMMFdIJhk6g6pwlIqZ54rxo8SLmAg"
                                }
                            },
                        },
                    },
                },
            },
        )

        failure = self.get_failure(d, AuthError).value

        self.assertEqual(failure.code, 403, failure)
        self.assertEqual(failure.errcode, Codes.FORBIDDEN, failure)
        self.assertEqual(failure.msg, "You are not invited to this room.")

    def test_rejected_message_event_state(self) -> None:
        """
        Check that we store the state group correctly for rejected non-state events.

        Regression test for #6289.
        """
        OTHER_SERVER = "otherserver"
        OTHER_USER = "@otheruser:" + OTHER_SERVER

        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(self.store.get_room_version(room_id))

        # pretend that another server has joined
        join_event = self._build_and_send_join_event(OTHER_SERVER, OTHER_USER, room_id)

        # check the state group
        sg = self.get_success(
            self.store._get_state_group_for_event(join_event.event_id)
        )

        # build and send an event which will be rejected
        ev = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "content": {},
                "room_id": room_id,
                "sender": "@yetanotheruser:" + OTHER_SERVER,
                "depth": cast(int, join_event["depth"]) + 1,
                "prev_events": [join_event.event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )

        with LoggingContext("send_rejected"):
            d = run_in_background(
                self.hs.get_federation_event_handler().on_receive_pdu, OTHER_SERVER, ev
            )
        self.get_success(d)

        # that should have been rejected
        e = self.get_success(self.store.get_event(ev.event_id, allow_rejected=True))
        self.assertIsNotNone(e.rejected_reason)

        # ... and the state group should be the same as before
        sg2 = self.get_success(self.store._get_state_group_for_event(ev.event_id))

        self.assertEqual(sg, sg2)

    def test_rejected_state_event_state(self) -> None:
        """
        Check that we store the state group correctly for rejected state events.

        Regression test for #6289.
        """
        OTHER_SERVER = "otherserver"
        OTHER_USER = "@otheruser:" + OTHER_SERVER

        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(self.store.get_room_version(room_id))

        # pretend that another server has joined
        join_event = self._build_and_send_join_event(OTHER_SERVER, OTHER_USER, room_id)

        # check the state group
        sg = self.get_success(
            self.store._get_state_group_for_event(join_event.event_id)
        )

        # build and send an event which will be rejected
        ev = event_from_pdu_json(
            {
                "type": "org.matrix.test",
                "state_key": "test_key",
                "content": {},
                "room_id": room_id,
                "sender": "@yetanotheruser:" + OTHER_SERVER,
                "depth": cast(int, join_event["depth"]) + 1,
                "prev_events": [join_event.event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )

        with LoggingContext("send_rejected"):
            d = run_in_background(
                self.hs.get_federation_event_handler().on_receive_pdu, OTHER_SERVER, ev
            )
        self.get_success(d)

        # that should have been rejected
        e = self.get_success(self.store.get_event(ev.event_id, allow_rejected=True))
        self.assertIsNotNone(e.rejected_reason)

        # ... and the state group should be the same as before
        sg2 = self.get_success(self.store._get_state_group_for_event(ev.event_id))

        self.assertEqual(sg, sg2)

    def test_backfill_with_many_backward_extremities(self) -> None:
        """
        Check that we can backfill with many backward extremities.
        The goal is to make sure that when we only use a portion
        of backwards extremities(the magic number is more than 5),
        no errors are thrown.

        Regression test, see #11027
        """
        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(self.store.get_room_version(room_id))

        # we need a user on the remote server to be a member, so that we can send
        # extremity-causing events.
        remote_server_user_id = f"@user:{self.OTHER_SERVER_NAME}"
        self.get_success(
            event_injection.inject_member_event(
                self.hs, room_id, remote_server_user_id, "join"
            )
        )

        send_result = self.helper.send(room_id, "first message", tok=tok)
        ev1 = self.get_success(
            self.store.get_event(send_result["event_id"], allow_none=False)
        )
        current_state = self.get_success(
            self.store.get_events_as_list(
                (
                    self.get_success(self.store.get_partial_current_state_ids(room_id))
                ).values()
            )
        )

        # Create "many" backward extremities. The magic number we're trying to
        # create more than is 5 which corresponds to the number of backward
        # extremities we slice off in `_maybe_backfill_inner`
        federation_event_handler = self.hs.get_federation_event_handler()
        auth_events = [
            ev
            for ev in current_state
            if (ev.type, ev.state_key)
            in {("m.room.create", ""), ("m.room.member", remote_server_user_id)}
        ]
        for _ in range(0, 8):
            event = make_event_from_dict(
                self.add_hashes_and_signatures_from_other_server(
                    {
                        "origin_server_ts": 1,
                        "type": "m.room.message",
                        "content": {
                            "msgtype": "m.text",
                            "body": "message connected to fake event",
                        },
                        "room_id": room_id,
                        "sender": remote_server_user_id,
                        "prev_events": [
                            ev1.event_id,
                            # We're creating an backward extremity each time thanks
                            # to this fake event
                            generate_fake_event_id(),
                        ],
                        "auth_events": [ev.event_id for ev in auth_events],
                        "depth": ev1.depth + 1,
                    },
                    room_version,
                ),
                room_version,
            )

            # we poke this directly into _process_received_pdu, to avoid the
            # federation handler wanting to backfill the fake event.
            state_handler = self.hs.get_state_handler()
            context = self.get_success(
                state_handler.compute_event_context(
                    event,
                    state_ids_before_event={
                        (e.type, e.state_key): e.event_id for e in current_state
                    },
                    partial_state=False,
                )
            )
            self.get_success(
                federation_event_handler._process_received_pdu(
                    self.OTHER_SERVER_NAME,
                    event,
                    context,
                )
            )

        # we should now have 8 backwards extremities.
        backwards_extremities = self.get_success(
            self.store.db_pool.simple_select_list(
                "event_backward_extremities",
                keyvalues={"room_id": room_id},
                retcols=["event_id"],
            )
        )
        self.assertEqual(len(backwards_extremities), 8)

        current_depth = 1
        limit = 100
        with LoggingContext("receive_pdu"):
            # Make sure backfill still works
            d = run_in_background(
                self.hs.get_federation_handler().maybe_backfill,
                room_id,
                current_depth,
                limit,
            )
        self.get_success(d)

    def test_backfill_ignores_known_events(self) -> None:
        """
        Tests that events that we already know about are ignored when backfilling.
        """
        # Set up users
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        other_server = "otherserver"
        other_user = "@otheruser:" + other_server

        # Create a room to backfill events into
        room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
        room_version = self.get_success(self.store.get_room_version(room_id))

        # Build an event to backfill
        event = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "content": {"body": "hello world", "msgtype": "m.text"},
                "room_id": room_id,
                "sender": other_user,
                "depth": 32,
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )

        # Ensure the event is not already in the DB
        self.get_failure(
            self.store.get_event(event.event_id),
            NotFoundError,
        )

        # Backfill the event and check that it has entered the DB.

        # We mock out the FederationClient.backfill method, to pretend that a remote
        # server has returned our fake event.
        federation_client_backfill_mock = Mock(return_value=make_awaitable([event]))
        self.hs.get_federation_client().backfill = federation_client_backfill_mock

        # We also mock the persist method with a side effect of itself. This allows us
        # to track when it has been called while preserving its function.
        persist_events_and_notify_mock = Mock(
            side_effect=self.hs.get_federation_event_handler().persist_events_and_notify
        )
        self.hs.get_federation_event_handler().persist_events_and_notify = (
            persist_events_and_notify_mock
        )

        # Small side-tangent. We populate the event cache with the event, even though
        # it is not yet in the DB. This is an invalid scenario that can currently occur
        # due to not properly invalidating the event cache.
        # See https://github.com/matrix-org/synapse/issues/13476.
        #
        # As a result, backfill should not rely on the event cache to check whether
        # we already have an event in the DB.
        # TODO: Remove this bit when the event cache is properly invalidated.
        cache_entry = EventCacheEntry(
            event=event,
            redacted_event=None,
        )
        self.store._get_event_cache.set_local((event.event_id,), cache_entry)

        # We now call FederationEventHandler.backfill (a separate method) to trigger
        # a backfill request. It should receive the fake event.
        self.get_success(
            self.hs.get_federation_event_handler().backfill(
                other_user,
                room_id,
                limit=10,
                extremities=[],
            )
        )

        # Check that our fake event was persisted.
        persist_events_and_notify_mock.assert_called_once()
        persist_events_and_notify_mock.reset_mock()

        # Now we repeat the backfill, having the homeserver receive the fake event
        # again.
        self.get_success(
            self.hs.get_federation_event_handler().backfill(
                other_user,
                room_id,
                limit=10,
                extremities=[],
            ),
        )

        # This time, we expect no event persistence to have occurred, as we already
        # have this event.
        persist_events_and_notify_mock.assert_not_called()

    @unittest.override_config(
        {"rc_invites": {"per_user": {"per_second": 0.5, "burst_count": 3}}}
    )
    def test_invite_by_user_ratelimit(self) -> None:
        """Tests that invites from federation to a particular user are
        actually rate-limited.
        """
        other_server = "otherserver"
        other_user = "@otheruser:" + other_server

        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        def create_invite():
            room_id = self.helper.create_room_as(room_creator=user_id, tok=tok)
            room_version = self.get_success(self.store.get_room_version(room_id))
            return event_from_pdu_json(
                {
                    "type": EventTypes.Member,
                    "content": {"membership": "invite"},
                    "room_id": room_id,
                    "sender": other_user,
                    "state_key": "@user:test",
                    "depth": 32,
                    "prev_events": [],
                    "auth_events": [],
                    "origin_server_ts": self.clock.time_msec(),
                },
                room_version,
            )

        for _ in range(3):
            event = create_invite()
            self.get_success(
                self.handler.on_invite_request(
                    other_server,
                    event,
                    event.room_version,
                )
            )

        event = create_invite()
        self.get_failure(
            self.handler.on_invite_request(
                other_server,
                event,
                event.room_version,
            ),
            exc=LimitExceededError,
        )

    def _build_and_send_join_event(
        self, other_server: str, other_user: str, room_id: str
    ) -> EventBase:
        join_event = self.get_success(
            self.handler.on_make_join_request(other_server, room_id, other_user)
        )
        # the auth code requires that a signature exists, but doesn't check that
        # signature... go figure.
        join_event.signatures[other_server] = {"x": "y"}
        with LoggingContext("send_join"):
            d = run_in_background(
                self.hs.get_federation_event_handler().on_send_membership_event,
                other_server,
                join_event,
            )
        self.get_success(d)

        # sanity-check: the room should show that the new user is a member
        r = self.get_success(self.store.get_partial_current_state_ids(room_id))
        self.assertEqual(r[(EventTypes.Member, other_user)], join_event.event_id)

        return join_event


class EventFromPduTestCase(TestCase):
    def test_valid_json(self) -> None:
        """Valid JSON should be turned into an event."""
        ev = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "content": {"bool": True, "null": None, "int": 1, "str": "foobar"},
                "room_id": "!room:test",
                "sender": "@user:test",
                "depth": 1,
                "prev_events": [],
                "auth_events": [],
                "origin_server_ts": 1234,
            },
            RoomVersions.V6,
        )

        self.assertIsInstance(ev, EventBase)

    def test_invalid_numbers(self) -> None:
        """Invalid values for an integer should be rejected, all floats should be rejected."""
        for value in [
            -(2**53),
            2**53,
            1.0,
            float("inf"),
            float("-inf"),
            float("nan"),
        ]:
            with self.assertRaises(SynapseError):
                event_from_pdu_json(
                    {
                        "type": EventTypes.Message,
                        "content": {"foo": value},
                        "room_id": "!room:test",
                        "sender": "@user:test",
                        "depth": 1,
                        "prev_events": [],
                        "auth_events": [],
                        "origin_server_ts": 1234,
                    },
                    RoomVersions.V6,
                )

    def test_invalid_nested(self) -> None:
        """List and dictionaries are recursively searched."""
        with self.assertRaises(SynapseError):
            event_from_pdu_json(
                {
                    "type": EventTypes.Message,
                    "content": {"foo": [{"bar": 2**56}]},
                    "room_id": "!room:test",
                    "sender": "@user:test",
                    "depth": 1,
                    "prev_events": [],
                    "auth_events": [],
                    "origin_server_ts": 1234,
                },
                RoomVersions.V6,
            )


class PartialJoinTestCase(unittest.FederatingHomeserverTestCase):
    def test_failed_partial_join_is_clean(self) -> None:
        """
        Tests that, when failing to partial-join a room, we don't get stuck with
        a partial-state flag on a room.
        """

        fed_handler = self.hs.get_federation_handler()
        fed_client = fed_handler.federation_client

        room_id = "!room:example.com"
        membership_event = make_event_from_dict(
            {
                "room_id": room_id,
                "type": "m.room.member",
                "sender": "@alice:test",
                "state_key": "@alice:test",
                "content": {"membership": "join"},
            },
            RoomVersions.V10,
        )

        mock_make_membership_event = Mock(
            return_value=make_awaitable(
                (
                    "example.com",
                    membership_event,
                    RoomVersions.V10,
                )
            )
        )

        EVENT_CREATE = make_event_from_dict(
            {
                "room_id": room_id,
                "type": "m.room.create",
                "sender": "@kristina:example.com",
                "state_key": "",
                "depth": 0,
                "content": {"creator": "@kristina:example.com", "room_version": "10"},
                "auth_events": [],
                "origin_server_ts": 1,
            },
            room_version=RoomVersions.V10,
        )
        EVENT_CREATOR_MEMBERSHIP = make_event_from_dict(
            {
                "room_id": room_id,
                "type": "m.room.member",
                "sender": "@kristina:example.com",
                "state_key": "@kristina:example.com",
                "content": {"membership": "join"},
                "depth": 1,
                "prev_events": [EVENT_CREATE.event_id],
                "auth_events": [EVENT_CREATE.event_id],
                "origin_server_ts": 1,
            },
            room_version=RoomVersions.V10,
        )
        EVENT_INVITATION_MEMBERSHIP = make_event_from_dict(
            {
                "room_id": room_id,
                "type": "m.room.member",
                "sender": "@kristina:example.com",
                "state_key": "@alice:test",
                "content": {"membership": "invite"},
                "depth": 2,
                "prev_events": [EVENT_CREATOR_MEMBERSHIP.event_id],
                "auth_events": [
                    EVENT_CREATE.event_id,
                    EVENT_CREATOR_MEMBERSHIP.event_id,
                ],
                "origin_server_ts": 1,
            },
            room_version=RoomVersions.V10,
        )
        mock_send_join = Mock(
            return_value=make_awaitable(
                SendJoinResult(
                    membership_event,
                    "example.com",
                    state=[
                        EVENT_CREATE,
                        EVENT_CREATOR_MEMBERSHIP,
                        EVENT_INVITATION_MEMBERSHIP,
                    ],
                    auth_chain=[
                        EVENT_CREATE,
                        EVENT_CREATOR_MEMBERSHIP,
                        EVENT_INVITATION_MEMBERSHIP,
                    ],
                    partial_state=True,
                    servers_in_room=["example.com"],
                )
            )
        )

        with patch.object(
            fed_client, "make_membership_event", mock_make_membership_event
        ), patch.object(fed_client, "send_join", mock_send_join):
            # Join and check that our join event is rejected
            # (The join event is rejected because it doesn't have any signatures)
            join_exc = self.get_failure(
                fed_handler.do_invite_join(["example.com"], room_id, "@alice:test", {}),
                SynapseError,
            )
        self.assertIn("Join event was rejected", str(join_exc))

        store = self.hs.get_datastores().main

        # Check that we don't have a left-over partial_state entry.
        self.assertFalse(
            self.get_success(store.is_partial_state_room(room_id)),
            f"Stale partial-stated room flag left over for {room_id} after a"
            f" failed do_invite_join!",
        )
