# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

import unittest

from synapse import event_auth
from synapse.api.errors import AuthError
from synapse.events import FrozenEvent


class EventAuthTestCase(unittest.TestCase):
    def test_random_users_cannot_send_state_before_first_pl(self):
        """
        Check that, before the first PL lands, the creator is the only user
        that can send a state event.
        """
        creator = "@creator:example.com"
        joiner = "@joiner:example.com"
        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.member", joiner): _join_event(joiner),
        }

        # creator should be able to send state
        event_auth.check(_random_state_event(creator), auth_events, do_sig_check=False)

        # joiner should not be able to send state
        self.assertRaises(
            AuthError,
            event_auth.check,
            _random_state_event(joiner),
            auth_events,
            do_sig_check=False,
        ),

    def test_state_default_level(self):
        """
        Check that users above the state_default level can send state and
        those below cannot
        """
        creator = "@creator:example.com"
        pleb = "@joiner:example.com"
        king = "@joiner2:example.com"

        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.power_levels", ""): _power_levels_event(
                creator, {"state_default": "30", "users": {pleb: "29", king: "30"}}
            ),
            ("m.room.member", pleb): _join_event(pleb),
            ("m.room.member", king): _join_event(king),
        }

        # pleb should not be able to send state
        self.assertRaises(
            AuthError,
            event_auth.check,
            _random_state_event(pleb),
            auth_events,
            do_sig_check=False,
        ),

        # king should be able to send state
        event_auth.check(_random_state_event(king), auth_events, do_sig_check=False)


# helpers for making events

TEST_ROOM_ID = "!test:room"


def _create_event(user_id):
    return FrozenEvent(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.create",
            "sender": user_id,
            "content": {"creator": user_id},
        }
    )


def _join_event(user_id):
    return FrozenEvent(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.member",
            "sender": user_id,
            "state_key": user_id,
            "content": {"membership": "join"},
        }
    )


def _power_levels_event(sender, content):
    return FrozenEvent(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.power_levels",
            "sender": sender,
            "state_key": "",
            "content": content,
        }
    )


def _random_state_event(sender):
    return FrozenEvent(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "test.state",
            "sender": sender,
            "state_key": "",
            "content": {"membership": "join"},
        }
    )


event_count = 0


def _get_event_id():
    global event_count
    c = event_count
    event_count += 1
    return "!%i:example.com" % (c,)
