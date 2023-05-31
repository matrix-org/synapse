# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2017 Vector Creations Ltd
# Copyright 2018-2019 New Vector Ltd
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
from typing import List
from unittest.mock import patch

import jsonschema

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EduTypes, EventContentFields
from synapse.api.errors import SynapseError
from synapse.api.filtering import Filter
from synapse.api.presence import UserPresenceState
from synapse.server import HomeServer
from synapse.types import JsonDict, UserID
from synapse.util import Clock
from synapse.util.frozenutils import freeze

from tests import unittest
from tests.events.test_utils import MockEvent

user_id = UserID.from_string("@test_user:test")
user2_id = UserID.from_string("@test_user2:test")


class FilteringTestCase(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.filtering = hs.get_filtering()
        self.datastore = hs.get_datastores().main

    def test_errors_on_invalid_filters(self) -> None:
        # See USER_FILTER_SCHEMA for the filter schema.
        invalid_filters: List[JsonDict] = [
            # `account_data` must be a dictionary
            {"account_data": "Hello World"},
            # `event_format` must be "client" or "federation"
            {"event_format": "other"},
            # `not_rooms` must contain valid room IDs
            {"room": {"not_rooms": ["#foo:pik-test"]}},
            # `senders` must contain valid user IDs
            {"presence": {"senders": ["@bar;pik.test.com"]}},
        ]
        for filter in invalid_filters:
            with self.assertRaises(SynapseError):
                self.filtering.check_valid_filter(filter)

    def test_ignores_unknown_filter_fields(self) -> None:
        # For forward compatibility, we must ignore unknown filter fields.
        # See USER_FILTER_SCHEMA for the filter schema.
        filters: List[JsonDict] = [
            {"org.matrix.msc9999.future_option": True},
            {"presence": {"org.matrix.msc9999.future_option": True}},
            {"room": {"org.matrix.msc9999.future_option": True}},
            {"room": {"timeline": {"org.matrix.msc9999.future_option": True}}},
        ]
        for filter in filters:
            self.filtering.check_valid_filter(filter)
            # Must not raise.

    def test_valid_filters(self) -> None:
        valid_filters: List[JsonDict] = [
            {
                "room": {
                    "timeline": {"limit": 20},
                    "state": {"not_types": ["m.room.member"]},
                    "ephemeral": {"limit": 0, "not_types": ["*"]},
                    "include_leave": False,
                    "rooms": ["!dee:pik-test"],
                    "not_rooms": ["!gee:pik-test"],
                    "account_data": {"limit": 0, "types": ["*"]},
                }
            },
            {
                "room": {
                    "state": {
                        "types": ["m.room.*"],
                        "not_rooms": ["!726s6s6q:example.com"],
                    },
                    "timeline": {
                        "limit": 10,
                        "types": ["m.room.message"],
                        "not_rooms": ["!726s6s6q:example.com"],
                        "not_senders": ["@spam:example.com"],
                        "org.matrix.labels": ["#fun"],
                        "org.matrix.not_labels": ["#work"],
                    },
                    "ephemeral": {
                        "types": [EduTypes.RECEIPT, EduTypes.TYPING],
                        "not_rooms": ["!726s6s6q:example.com"],
                        "not_senders": ["@spam:example.com"],
                    },
                },
                "presence": {
                    "types": [EduTypes.PRESENCE],
                    "not_senders": ["@alice:example.com"],
                },
                "event_format": "client",
                "event_fields": ["type", "content", "sender"],
            },
            # (note that event_fields is implemented in
            # synapse.events.utils.serialize_event, and so whether this actually works
            # is tested elsewhere. We just want to check that it is allowed through the
            # filter validation)
            {"event_fields": [r"foo\.bar"]},
        ]
        for filter in valid_filters:
            try:
                self.filtering.check_valid_filter(filter)
            except jsonschema.ValidationError as e:
                self.fail(e)

    def test_limits_are_applied(self) -> None:
        # TODO
        pass

    def test_definition_types_works_with_literals(self) -> None:
        definition = {"types": ["m.room.message", "org.matrix.foo.bar"]}
        event = MockEvent(sender="@foo:bar", type="m.room.message", room_id="!foo:bar")

        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_types_works_with_wildcards(self) -> None:
        definition = {"types": ["m.*", "org.matrix.foo.bar"]}
        event = MockEvent(sender="@foo:bar", type="m.room.message", room_id="!foo:bar")
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_types_works_with_unknowns(self) -> None:
        definition = {"types": ["m.room.message", "org.matrix.foo.bar"]}
        event = MockEvent(
            sender="@foo:bar",
            type="now.for.something.completely.different",
            room_id="!foo:bar",
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_types_works_with_literals(self) -> None:
        definition = {"not_types": ["m.room.message", "org.matrix.foo.bar"]}
        event = MockEvent(sender="@foo:bar", type="m.room.message", room_id="!foo:bar")
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_types_works_with_wildcards(self) -> None:
        definition = {"not_types": ["m.room.message", "org.matrix.*"]}
        event = MockEvent(
            sender="@foo:bar", type="org.matrix.custom.event", room_id="!foo:bar"
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_types_works_with_unknowns(self) -> None:
        definition = {"not_types": ["m.*", "org.*"]}
        event = MockEvent(sender="@foo:bar", type="com.nom.nom.nom", room_id="!foo:bar")
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_not_types_takes_priority_over_types(self) -> None:
        definition = {
            "not_types": ["m.*", "org.*"],
            "types": ["m.room.message", "m.room.topic"],
        }
        event = MockEvent(sender="@foo:bar", type="m.room.topic", room_id="!foo:bar")
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_senders_works_with_literals(self) -> None:
        definition = {"senders": ["@flibble:wibble"]}
        event = MockEvent(
            sender="@flibble:wibble", type="com.nom.nom.nom", room_id="!foo:bar"
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_senders_works_with_unknowns(self) -> None:
        definition = {"senders": ["@flibble:wibble"]}
        event = MockEvent(
            sender="@challenger:appears", type="com.nom.nom.nom", room_id="!foo:bar"
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_senders_works_with_literals(self) -> None:
        definition = {"not_senders": ["@flibble:wibble"]}
        event = MockEvent(
            sender="@flibble:wibble", type="com.nom.nom.nom", room_id="!foo:bar"
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_senders_works_with_unknowns(self) -> None:
        definition = {"not_senders": ["@flibble:wibble"]}
        event = MockEvent(
            sender="@challenger:appears", type="com.nom.nom.nom", room_id="!foo:bar"
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_not_senders_takes_priority_over_senders(self) -> None:
        definition = {
            "not_senders": ["@misspiggy:muppets"],
            "senders": ["@kermit:muppets", "@misspiggy:muppets"],
        }
        event = MockEvent(
            sender="@misspiggy:muppets", type="m.room.topic", room_id="!foo:bar"
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_rooms_works_with_literals(self) -> None:
        definition = {"rooms": ["!secretbase:unknown"]}
        event = MockEvent(
            sender="@foo:bar", type="m.room.message", room_id="!secretbase:unknown"
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_rooms_works_with_unknowns(self) -> None:
        definition = {"rooms": ["!secretbase:unknown"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!anothersecretbase:unknown",
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_rooms_works_with_literals(self) -> None:
        definition = {"not_rooms": ["!anothersecretbase:unknown"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!anothersecretbase:unknown",
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_not_rooms_works_with_unknowns(self) -> None:
        definition = {"not_rooms": ["!secretbase:unknown"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!anothersecretbase:unknown",
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_not_rooms_takes_priority_over_rooms(self) -> None:
        definition = {
            "not_rooms": ["!secretbase:unknown"],
            "rooms": ["!secretbase:unknown"],
        }
        event = MockEvent(
            sender="@foo:bar", type="m.room.message", room_id="!secretbase:unknown"
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_combined_event(self) -> None:
        definition = {
            "not_senders": ["@misspiggy:muppets"],
            "senders": ["@kermit:muppets"],
            "rooms": ["!stage:unknown"],
            "not_rooms": ["!piggyshouse:muppets"],
            "types": ["m.room.message", "muppets.kermit.*"],
            "not_types": ["muppets.misspiggy.*"],
        }
        event = MockEvent(
            sender="@kermit:muppets",  # yup
            type="m.room.message",  # yup
            room_id="!stage:unknown",  # yup
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_definition_combined_event_bad_sender(self) -> None:
        definition = {
            "not_senders": ["@misspiggy:muppets"],
            "senders": ["@kermit:muppets"],
            "rooms": ["!stage:unknown"],
            "not_rooms": ["!piggyshouse:muppets"],
            "types": ["m.room.message", "muppets.kermit.*"],
            "not_types": ["muppets.misspiggy.*"],
        }
        event = MockEvent(
            sender="@misspiggy:muppets",  # nope
            type="m.room.message",  # yup
            room_id="!stage:unknown",  # yup
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_combined_event_bad_room(self) -> None:
        definition = {
            "not_senders": ["@misspiggy:muppets"],
            "senders": ["@kermit:muppets"],
            "rooms": ["!stage:unknown"],
            "not_rooms": ["!piggyshouse:muppets"],
            "types": ["m.room.message", "muppets.kermit.*"],
            "not_types": ["muppets.misspiggy.*"],
        }
        event = MockEvent(
            sender="@kermit:muppets",  # yup
            type="m.room.message",  # yup
            room_id="!piggyshouse:muppets",  # nope
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_definition_combined_event_bad_type(self) -> None:
        definition = {
            "not_senders": ["@misspiggy:muppets"],
            "senders": ["@kermit:muppets"],
            "rooms": ["!stage:unknown"],
            "not_rooms": ["!piggyshouse:muppets"],
            "types": ["m.room.message", "muppets.kermit.*"],
            "not_types": ["muppets.misspiggy.*"],
        }
        event = MockEvent(
            sender="@kermit:muppets",  # yup
            type="muppets.misspiggy.kisses",  # nope
            room_id="!stage:unknown",  # yup
        )
        self.assertFalse(Filter(self.hs, definition)._check(event))

    def test_filter_labels(self) -> None:
        definition = {"org.matrix.labels": ["#fun"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={EventContentFields.LABELS: ["#fun"]},
        )

        self.assertTrue(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={EventContentFields.LABELS: ["#notfun"]},
        )

        self.assertFalse(Filter(self.hs, definition)._check(event))

        # check it works with frozen dictionaries too
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content=freeze({EventContentFields.LABELS: ["#fun"]}),
        )
        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_filter_not_labels(self) -> None:
        definition = {"org.matrix.not_labels": ["#fun"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={EventContentFields.LABELS: ["#fun"]},
        )

        self.assertFalse(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={EventContentFields.LABELS: ["#notfun"]},
        )

        self.assertTrue(Filter(self.hs, definition)._check(event))

    @unittest.override_config({"experimental_features": {"msc3874_enabled": True}})
    def test_filter_rel_type(self) -> None:
        definition = {"org.matrix.msc3874.rel_types": ["m.thread"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={},
        )

        self.assertFalse(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={"m.relates_to": {"event_id": "$abc", "rel_type": "m.reference"}},
        )

        self.assertFalse(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={"m.relates_to": {"event_id": "$abc", "rel_type": "m.thread"}},
        )

        self.assertTrue(Filter(self.hs, definition)._check(event))

    @unittest.override_config({"experimental_features": {"msc3874_enabled": True}})
    def test_filter_not_rel_type(self) -> None:
        definition = {"org.matrix.msc3874.not_rel_types": ["m.thread"]}
        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={"m.relates_to": {"event_id": "$abc", "rel_type": "m.thread"}},
        )

        self.assertFalse(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={},
        )

        self.assertTrue(Filter(self.hs, definition)._check(event))

        event = MockEvent(
            sender="@foo:bar",
            type="m.room.message",
            room_id="!secretbase:unknown",
            content={"m.relates_to": {"event_id": "$abc", "rel_type": "m.reference"}},
        )

        self.assertTrue(Filter(self.hs, definition)._check(event))

    def test_filter_presence_match(self) -> None:
        """Check that filter_presence return events which matches the filter."""
        user_filter_json = {"presence": {"senders": ["@foo:bar"]}}
        filter_id = self.get_success(
            self.datastore.add_user_filter(
                user_id=user_id, user_filter=user_filter_json
            )
        )
        presence_states = [
            UserPresenceState(
                user_id="@foo:bar",
                state="unavailable",
                last_active_ts=0,
                last_federation_update_ts=0,
                last_user_sync_ts=0,
                status_msg=None,
                currently_active=False,
            ),
        ]

        user_filter = self.get_success(
            self.filtering.get_user_filter(user_id=user_id, filter_id=filter_id)
        )

        results = self.get_success(user_filter.filter_presence(presence_states))
        self.assertEqual(presence_states, results)

    def test_filter_presence_no_match(self) -> None:
        """Check that filter_presence does not return events rejected by the filter."""
        user_filter_json = {"presence": {"not_senders": ["@foo:bar"]}}

        filter_id = self.get_success(
            self.datastore.add_user_filter(
                user_id=user2_id, user_filter=user_filter_json
            )
        )
        presence_states = [
            UserPresenceState(
                user_id="@foo:bar",
                state="unavailable",
                last_active_ts=0,
                last_federation_update_ts=0,
                last_user_sync_ts=0,
                status_msg=None,
                currently_active=False,
            ),
        ]

        user_filter = self.get_success(
            self.filtering.get_user_filter(user_id=user2_id, filter_id=filter_id)
        )

        results = self.get_success(user_filter.filter_presence(presence_states))
        self.assertEqual([], results)

    def test_filter_room_state_match(self) -> None:
        user_filter_json = {"room": {"state": {"types": ["m.*"]}}}
        filter_id = self.get_success(
            self.datastore.add_user_filter(
                user_id=user_id, user_filter=user_filter_json
            )
        )
        event = MockEvent(sender="@foo:bar", type="m.room.topic", room_id="!foo:bar")
        events = [event]

        user_filter = self.get_success(
            self.filtering.get_user_filter(user_id=user_id, filter_id=filter_id)
        )

        results = self.get_success(user_filter.filter_room_state(events=events))
        self.assertEqual(events, results)

    def test_filter_room_state_no_match(self) -> None:
        user_filter_json = {"room": {"state": {"types": ["m.*"]}}}
        filter_id = self.get_success(
            self.datastore.add_user_filter(
                user_id=user_id, user_filter=user_filter_json
            )
        )
        event = MockEvent(
            sender="@foo:bar", type="org.matrix.custom.event", room_id="!foo:bar"
        )
        events = [event]

        user_filter = self.get_success(
            self.filtering.get_user_filter(user_id=user_id, filter_id=filter_id)
        )

        results = self.get_success(user_filter.filter_room_state(events))
        self.assertEqual([], results)

    def test_filter_rooms(self) -> None:
        definition = {
            "rooms": ["!allowed:example.com", "!excluded:example.com"],
            "not_rooms": ["!excluded:example.com"],
        }

        room_ids = [
            "!allowed:example.com",  # Allowed because in rooms and not in not_rooms.
            "!excluded:example.com",  # Disallowed because in not_rooms.
            "!not_included:example.com",  # Disallowed because not in rooms.
        ]

        filtered_room_ids = list(Filter(self.hs, definition).filter_rooms(room_ids))

        self.assertEqual(filtered_room_ids, ["!allowed:example.com"])

    def test_filter_relations(self) -> None:
        events = [
            # An event without a relation.
            MockEvent(
                event_id="$no_relation",
                sender="@foo:bar",
                type="org.matrix.custom.event",
                room_id="!foo:bar",
            ),
            # An event with a relation.
            MockEvent(
                event_id="$with_relation",
                sender="@foo:bar",
                type="org.matrix.custom.event",
                room_id="!foo:bar",
            ),
        ]
        jsondicts: List[JsonDict] = [{}]

        # For the following tests we patch the datastore method (intead of injecting
        # events). This is a bit cheeky, but tests the logic of _check_event_relations.

        # Filter for a particular sender.
        definition = {"related_by_senders": ["@foo:bar"]}

        async def events_have_relations(*args: object, **kwargs: object) -> List[str]:
            return ["$with_relation"]

        with patch.object(
            self.datastore, "events_have_relations", new=events_have_relations
        ):
            filtered_events = list(
                self.get_success(
                    Filter(self.hs, definition)._check_event_relations(events)
                )
            )
            # Non-EventBase objects get passed through.
            filtered_jsondicts = list(
                self.get_success(
                    Filter(self.hs, definition)._check_event_relations(jsondicts)
                )
            )

        self.assertEqual(filtered_events, events[1:])
        self.assertEqual(filtered_jsondicts, [{}])

    def test_add_filter(self) -> None:
        user_filter_json = {"room": {"state": {"types": ["m.*"]}}}

        filter_id = self.get_success(
            self.filtering.add_user_filter(
                user_id=user_id, user_filter=user_filter_json
            )
        )

        self.assertEqual(filter_id, 0)
        self.assertEqual(
            user_filter_json,
            (
                self.get_success(
                    self.datastore.get_user_filter(user_id=user_id, filter_id=0)
                )
            ),
        )

    def test_get_filter(self) -> None:
        user_filter_json = {"room": {"state": {"types": ["m.*"]}}}

        filter_id = self.get_success(
            self.datastore.add_user_filter(
                user_id=user_id, user_filter=user_filter_json
            )
        )

        filter = self.get_success(
            self.filtering.get_user_filter(user_id=user_id, filter_id=filter_id)
        )

        self.assertEqual(filter.get_filter_json(), user_filter_json)

        self.assertRegex(repr(filter), r"<FilterCollection \{.*\}>")
