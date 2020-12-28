# -*- coding: utf-8 -*-
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
from unittest import TestCase

from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.federation.federation_base import event_from_pdu_json
from synapse.logging.context import LoggingContext, run_in_background
from synapse.rest import admin
from synapse.rest.client.v1 import login, room

from tests import unittest

logger = logging.getLogger(__name__)


class FederationTestCase(unittest.HomeserverTestCase):
    servlets = [
        admin.register_servlets,
        login.register_servlets,
        room.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(federation_http_client=None)
        self.handler = hs.get_federation_handler()
        self.store = hs.get_datastore()
        return hs

    def test_exchange_revoked_invite(self):
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

    def test_rejected_message_event_state(self):
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
        sg = self.successResultOf(
            self.store._get_state_group_for_event(join_event.event_id)
        )

        # build and send an event which will be rejected
        ev = event_from_pdu_json(
            {
                "type": EventTypes.Message,
                "content": {},
                "room_id": room_id,
                "sender": "@yetanotheruser:" + OTHER_SERVER,
                "depth": join_event["depth"] + 1,
                "prev_events": [join_event.event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )

        with LoggingContext("send_rejected"):
            d = run_in_background(self.handler.on_receive_pdu, OTHER_SERVER, ev)
        self.get_success(d)

        # that should have been rejected
        e = self.get_success(self.store.get_event(ev.event_id, allow_rejected=True))
        self.assertIsNotNone(e.rejected_reason)

        # ... and the state group should be the same as before
        sg2 = self.successResultOf(self.store._get_state_group_for_event(ev.event_id))

        self.assertEqual(sg, sg2)

    def test_rejected_state_event_state(self):
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
        sg = self.successResultOf(
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
                "depth": join_event["depth"] + 1,
                "prev_events": [join_event.event_id],
                "auth_events": [],
                "origin_server_ts": self.clock.time_msec(),
            },
            room_version,
        )

        with LoggingContext("send_rejected"):
            d = run_in_background(self.handler.on_receive_pdu, OTHER_SERVER, ev)
        self.get_success(d)

        # that should have been rejected
        e = self.get_success(self.store.get_event(ev.event_id, allow_rejected=True))
        self.assertIsNotNone(e.rejected_reason)

        # ... and the state group should be the same as before
        sg2 = self.successResultOf(self.store._get_state_group_for_event(ev.event_id))

        self.assertEqual(sg, sg2)

    def _build_and_send_join_event(self, other_server, other_user, room_id):
        join_event = self.get_success(
            self.handler.on_make_join_request(other_server, room_id, other_user)
        )
        # the auth code requires that a signature exists, but doesn't check that
        # signature... go figure.
        join_event.signatures[other_server] = {"x": "y"}
        with LoggingContext("send_join"):
            d = run_in_background(
                self.handler.on_send_join_request, other_server, join_event
            )
        self.get_success(d)

        # sanity-check: the room should show that the new user is a member
        r = self.get_success(self.store.get_current_state_ids(room_id))
        self.assertEqual(r[(EventTypes.Member, other_user)], join_event.event_id)

        return join_event


class EventFromPduTestCase(TestCase):
    def test_valid_json(self):
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

    def test_invalid_numbers(self):
        """Invalid values for an integer should be rejected, all floats should be rejected."""
        for value in [
            -(2 ** 53),
            2 ** 53,
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

    def test_invalid_nested(self):
        """List and dictionaries are recursively searched."""
        with self.assertRaises(SynapseError):
            event_from_pdu_json(
                {
                    "type": EventTypes.Message,
                    "content": {"foo": [{"bar": 2 ** 56}]},
                    "room_id": "!room:test",
                    "sender": "@user:test",
                    "depth": 1,
                    "prev_events": [],
                    "auth_events": [],
                    "origin_server_ts": 1234,
                },
                RoomVersions.V6,
            )
