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
from synapse.api.room_versions import RoomVersions
from synapse.events import make_event_from_dict
from synapse.types import get_domain_from_id


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
        event_auth.check(
            RoomVersions.V1,
            _random_state_event(creator),
            auth_events,
            do_sig_check=False,
        )

        # joiner should not be able to send state
        self.assertRaises(
            AuthError,
            event_auth.check,
            RoomVersions.V1,
            _random_state_event(joiner),
            auth_events,
            do_sig_check=False,
        )

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
            RoomVersions.V1,
            _random_state_event(pleb),
            auth_events,
            do_sig_check=False,
        ),

        # king should be able to send state
        event_auth.check(
            RoomVersions.V1,
            _random_state_event(king),
            auth_events,
            do_sig_check=False,
        )

    def test_alias_event(self):
        """Alias events have special behavior up through room version 6."""
        creator = "@creator:example.com"
        other = "@other:example.com"
        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
        }

        # creator should be able to send aliases
        event_auth.check(
            RoomVersions.V1,
            _alias_event(creator),
            auth_events,
            do_sig_check=False,
        )

        # Reject an event with no state key.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V1,
                _alias_event(creator, state_key=""),
                auth_events,
                do_sig_check=False,
            )

        # If the domain of the sender does not match the state key, reject.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V1,
                _alias_event(creator, state_key="test.com"),
                auth_events,
                do_sig_check=False,
            )

        # Note that the member does *not* need to be in the room.
        event_auth.check(
            RoomVersions.V1,
            _alias_event(other),
            auth_events,
            do_sig_check=False,
        )

    def test_msc2432_alias_event(self):
        """After MSC2432, alias events have no special behavior."""
        creator = "@creator:example.com"
        other = "@other:example.com"
        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
        }

        # creator should be able to send aliases
        event_auth.check(
            RoomVersions.V6,
            _alias_event(creator),
            auth_events,
            do_sig_check=False,
        )

        # No particular checks are done on the state key.
        event_auth.check(
            RoomVersions.V6,
            _alias_event(creator, state_key=""),
            auth_events,
            do_sig_check=False,
        )
        event_auth.check(
            RoomVersions.V6,
            _alias_event(creator, state_key="test.com"),
            auth_events,
            do_sig_check=False,
        )

        # Per standard auth rules, the member must be in the room.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _alias_event(other),
                auth_events,
                do_sig_check=False,
            )

    def test_msc2209(self):
        """
        Notifications power levels get checked due to MSC2209.
        """
        creator = "@creator:example.com"
        pleb = "@joiner:example.com"

        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.power_levels", ""): _power_levels_event(
                creator, {"state_default": "30", "users": {pleb: "30"}}
            ),
            ("m.room.member", pleb): _join_event(pleb),
        }

        # pleb should be able to modify the notifications power level.
        event_auth.check(
            RoomVersions.V1,
            _power_levels_event(pleb, {"notifications": {"room": 100}}),
            auth_events,
            do_sig_check=False,
        )

        # But an MSC2209 room rejects this change.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _power_levels_event(pleb, {"notifications": {"room": 100}}),
                auth_events,
                do_sig_check=False,
            )

    def test_join_rules_public(self):
        """
        Test joining a public room.
        """
        creator = "@creator:example.com"
        pleb = "@joiner:example.com"

        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.join_rules", ""): _join_rules_event(creator, "public"),
        }

        # Check join.
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user cannot be force-joined to a room.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _member_event(pleb, "join", sender=creator),
                auth_events,
                do_sig_check=False,
            )

        # Banned should be rejected.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "ban")
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # A user who left can re-join.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "leave")
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user can send a join if they're in the room.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "join")
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user can accept an invite.
        auth_events[("m.room.member", pleb)] = _member_event(
            pleb, "invite", sender=creator
        )
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

    def test_join_rules_invite(self):
        """
        Test joining an invite only room.
        """
        creator = "@creator:example.com"
        pleb = "@joiner:example.com"

        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.join_rules", ""): _join_rules_event(creator, "invite"),
        }

        # A join without an invite is rejected.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # A user cannot be force-joined to a room.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _member_event(pleb, "join", sender=creator),
                auth_events,
                do_sig_check=False,
            )

        # Banned should be rejected.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "ban")
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # A user who left cannot re-join.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "leave")
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # A user can send a join if they're in the room.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "join")
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user can accept an invite.
        auth_events[("m.room.member", pleb)] = _member_event(
            pleb, "invite", sender=creator
        )
        event_auth.check(
            RoomVersions.V6,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

    def test_join_rules_msc3083_restricted(self):
        """
        Test joining a restricted room from MSC3083.

        This is pretty much the same test as public.
        """
        creator = "@creator:example.com"
        pleb = "@joiner:example.com"

        auth_events = {
            ("m.room.create", ""): _create_event(creator),
            ("m.room.member", creator): _join_event(creator),
            ("m.room.join_rules", ""): _join_rules_event(creator, "restricted"),
        }

        # Older room versions don't understand this join rule
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.V6,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # Check join.
        event_auth.check(
            RoomVersions.MSC3083,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user cannot be force-joined to a room.
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.MSC3083,
                _member_event(pleb, "join", sender=creator),
                auth_events,
                do_sig_check=False,
            )

        # Banned should be rejected.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "ban")
        with self.assertRaises(AuthError):
            event_auth.check(
                RoomVersions.MSC3083,
                _join_event(pleb),
                auth_events,
                do_sig_check=False,
            )

        # A user who left can re-join.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "leave")
        event_auth.check(
            RoomVersions.MSC3083,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user can send a join if they're in the room.
        auth_events[("m.room.member", pleb)] = _member_event(pleb, "join")
        event_auth.check(
            RoomVersions.MSC3083,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )

        # A user can accept an invite.
        auth_events[("m.room.member", pleb)] = _member_event(
            pleb, "invite", sender=creator
        )
        event_auth.check(
            RoomVersions.MSC3083,
            _join_event(pleb),
            auth_events,
            do_sig_check=False,
        )


# helpers for making events

TEST_ROOM_ID = "!test:room"


def _create_event(user_id):
    return make_event_from_dict(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.create",
            "sender": user_id,
            "content": {"creator": user_id},
        }
    )


def _member_event(user_id, membership, sender=None):
    return make_event_from_dict(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.member",
            "sender": sender or user_id,
            "state_key": user_id,
            "content": {"membership": membership},
            "prev_events": [],
        }
    )


def _join_event(user_id):
    return _member_event(user_id, "join")


def _power_levels_event(sender, content):
    return make_event_from_dict(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.power_levels",
            "sender": sender,
            "state_key": "",
            "content": content,
        }
    )


def _alias_event(sender, **kwargs):
    data = {
        "room_id": TEST_ROOM_ID,
        "event_id": _get_event_id(),
        "type": "m.room.aliases",
        "sender": sender,
        "state_key": get_domain_from_id(sender),
        "content": {"aliases": []},
    }
    data.update(**kwargs)
    return make_event_from_dict(data)


def _random_state_event(sender):
    return make_event_from_dict(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "test.state",
            "sender": sender,
            "state_key": "",
            "content": {"membership": "join"},
        }
    )


def _join_rules_event(sender, join_rule):
    return make_event_from_dict(
        {
            "room_id": TEST_ROOM_ID,
            "event_id": _get_event_id(),
            "type": "m.room.join_rules",
            "sender": sender,
            "state_key": "",
            "content": {
                "join_rule": join_rule,
            },
        }
    )


event_count = 0


def _get_event_id():
    global event_count
    c = event_count
    event_count += 1
    return "!%i:example.com" % (c,)
