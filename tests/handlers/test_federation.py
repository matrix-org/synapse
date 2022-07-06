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
from typing import List, cast
from unittest import TestCase

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError, Codes, LimitExceededError, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase, make_event_from_dict
from synapse.federation.federation_base import event_from_pdu_json
from synapse.logging.context import LoggingContext, run_in_background
from synapse.rest import admin
from synapse.rest.client import login, room
from synapse.server import HomeServer
from synapse.util import Clock
from synapse.util.stringutils import random_string

from tests import unittest
from tests.test_utils import event_injection

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
        self.state_storage_controller = hs.get_storage_controllers().state
        self._event_auth_handler = hs.get_event_auth_handler()
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
                self.add_hashes_and_signatures(
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
            self.get_success(
                federation_event_handler._process_received_pdu(
                    self.OTHER_SERVER_NAME,
                    event,
                    state_ids={
                        (e.type, e.state_key): e.event_id for e in current_state
                    },
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

    def test_backfill_floating_outlier_membership_auth(self) -> None:
        """
        As the local homeserver, check that we can properly process a federated
        event from the OTHER_SERVER with auth_events that include a floating
        membership event from the OTHER_SERVER.

        Regression test, see #10439.
        """
        OTHER_SERVER = "otherserver"
        OTHER_USER = "@otheruser:" + OTHER_SERVER

        # create the room
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")
        room_id = self.helper.create_room_as(
            room_creator=user_id,
            is_public=True,
            tok=tok,
            extra_content={
                "preset": "public_chat",
            },
        )
        room_version = self.get_success(self.store.get_room_version(room_id))

        prev_event_ids = self.get_success(self.store.get_prev_events_for_room(room_id))
        (
            most_recent_prev_event_id,
            most_recent_prev_event_depth,
        ) = self.get_success(self.store.get_max_depth_of(prev_event_ids))
        # mapping from (type, state_key) -> state_event_id
        assert most_recent_prev_event_id is not None
        prev_state_map = self.get_success(
            self.state_storage_controller.get_state_ids_for_event(
                most_recent_prev_event_id
            )
        )
        # List of state event ID's
        prev_state_ids = list(prev_state_map.values())
        auth_event_ids = prev_state_ids
        auth_events = list(
            self.get_success(self.store.get_events(auth_event_ids)).values()
        )

        # build a floating outlier member state event
        fake_prev_event_id = "$" + random_string(43)
        member_event_dict = {
            "type": EventTypes.Member,
            "content": {
                "membership": "join",
            },
            "state_key": OTHER_USER,
            "room_id": room_id,
            "sender": OTHER_USER,
            "depth": most_recent_prev_event_depth,
            "prev_events": [fake_prev_event_id],
            "origin_server_ts": self.clock.time_msec(),
            "signatures": {OTHER_SERVER: {"ed25519:key_version": "SomeSignatureHere"}},
        }
        builder = self.hs.get_event_builder_factory().for_room_version(
            room_version, member_event_dict
        )
        member_event = self.get_success(
            builder.build(
                prev_event_ids=member_event_dict["prev_events"],
                auth_event_ids=self._event_auth_handler.compute_auth_events(
                    builder,
                    prev_state_map,
                    for_verification=False,
                ),
                depth=member_event_dict["depth"],
            )
        )
        # Override the signature added from "test" homeserver that we created the event with
        member_event.signatures = member_event_dict["signatures"]

        # Add the new member_event to the StateMap
        updated_state_map = dict(prev_state_map)
        updated_state_map[
            (member_event.type, member_event.state_key)
        ] = member_event.event_id
        auth_events.append(member_event)

        # build and send an event authed based on the member event
        message_event_dict = {
            "type": EventTypes.Message,
            "content": {},
            "room_id": room_id,
            "sender": OTHER_USER,
            "depth": most_recent_prev_event_depth,
            "prev_events": prev_event_ids.copy(),
            "origin_server_ts": self.clock.time_msec(),
            "signatures": {OTHER_SERVER: {"ed25519:key_version": "SomeSignatureHere"}},
        }
        builder = self.hs.get_event_builder_factory().for_room_version(
            room_version, message_event_dict
        )
        message_event = self.get_success(
            builder.build(
                prev_event_ids=message_event_dict["prev_events"],
                auth_event_ids=self._event_auth_handler.compute_auth_events(
                    builder,
                    updated_state_map,
                    for_verification=False,
                ),
                depth=message_event_dict["depth"],
            )
        )
        # Override the signature added from "test" homeserver that we created the event with
        message_event.signatures = message_event_dict["signatures"]

        # Stub the /event_auth response from the OTHER_SERVER
        async def get_event_auth(
            destination: str, room_id: str, event_id: str
        ) -> List[EventBase]:
            return [
                event_from_pdu_json(ae.get_pdu_json(), room_version=room_version)
                for ae in auth_events
            ]

        self.handler.federation_client.get_event_auth = get_event_auth  # type: ignore[assignment]

        with LoggingContext("receive_pdu"):
            # Fake the OTHER_SERVER federating the message event over to our local homeserver
            d = run_in_background(
                self.hs.get_federation_event_handler().on_receive_pdu,
                OTHER_SERVER,
                message_event,
            )
        self.get_success(d)

        # Now try and get the events on our local homeserver
        stored_event = self.get_success(
            self.store.get_event(message_event.event_id, allow_none=True)
        )
        self.assertTrue(stored_event is not None)

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
