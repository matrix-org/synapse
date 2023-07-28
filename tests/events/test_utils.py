# Copyright 2015, 2016 OpenMarket Ltd
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest as stdlib_unittest
from typing import Any, List, Mapping, Optional

import attr
from parameterized import parameterized

from synapse.api.constants import EventContentFields
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase, make_event_from_dict
from synapse.events.utils import (
    PowerLevelsContent,
    SerializeEventConfig,
    _split_field,
    copy_and_fixup_power_levels_contents,
    maybe_upsert_event_field,
    prune_event,
    serialize_event,
)
from synapse.types import JsonDict
from synapse.util.frozenutils import freeze


def MockEvent(**kwargs: Any) -> EventBase:
    if "event_id" not in kwargs:
        kwargs["event_id"] = "fake_event_id"
    if "type" not in kwargs:
        kwargs["type"] = "fake_type"
    if "content" not in kwargs:
        kwargs["content"] = {}
    return make_event_from_dict(kwargs)


class TestMaybeUpsertEventField(stdlib_unittest.TestCase):
    def test_update_okay(self) -> None:
        event = make_event_from_dict({"event_id": "$1234"})
        success = maybe_upsert_event_field(event, event.unsigned, "key", "value")
        self.assertTrue(success)
        self.assertEqual(event.unsigned["key"], "value")

    def test_update_not_okay(self) -> None:
        event = make_event_from_dict({"event_id": "$1234"})
        LARGE_STRING = "a" * 100_000
        success = maybe_upsert_event_field(event, event.unsigned, "key", LARGE_STRING)
        self.assertFalse(success)
        self.assertNotIn("key", event.unsigned)

    def test_update_not_okay_leaves_original_value(self) -> None:
        event = make_event_from_dict(
            {"event_id": "$1234", "unsigned": {"key": "value"}}
        )
        LARGE_STRING = "a" * 100_000
        success = maybe_upsert_event_field(event, event.unsigned, "key", LARGE_STRING)
        self.assertFalse(success)
        self.assertEqual(event.unsigned["key"], "value")


class PruneEventTestCase(stdlib_unittest.TestCase):
    def run_test(self, evdict: JsonDict, matchdict: JsonDict, **kwargs: Any) -> None:
        """
        Asserts that a new event constructed with `evdict` will look like
        `matchdict` when it is redacted.

        Args:
             evdict: The dictionary to build the event from.
             matchdict: The expected resulting dictionary.
             kwargs: Additional keyword arguments used to create the event.
        """
        self.assertEqual(
            prune_event(make_event_from_dict(evdict, **kwargs)).get_dict(), matchdict
        )

    def test_minimal(self) -> None:
        self.run_test(
            {"type": "A", "event_id": "$test:domain"},
            {
                "type": "A",
                "event_id": "$test:domain",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
        )

    def test_basic_keys(self) -> None:
        """Ensure that the keys that should be untouched are kept."""
        # Note that some of the values below don't really make sense, but the
        # pruning of events doesn't worry about the values of any fields (with
        # the exception of the content field).
        self.run_test(
            {
                "event_id": "$3:domain",
                "type": "A",
                "room_id": "!1:domain",
                "sender": "@2:domain",
                "state_key": "B",
                "content": {"other_key": "foo"},
                "hashes": "hashes",
                "signatures": {"domain": {"algo:1": "sigs"}},
                "depth": 4,
                "prev_events": "prev_events",
                "prev_state": "prev_state",
                "auth_events": "auth_events",
                "origin": "domain",
                "origin_server_ts": 1234,
                "membership": "join",
                # Also include a key that should be removed.
                "other_key": "foo",
            },
            {
                "event_id": "$3:domain",
                "type": "A",
                "room_id": "!1:domain",
                "sender": "@2:domain",
                "state_key": "B",
                "hashes": "hashes",
                "depth": 4,
                "prev_events": "prev_events",
                "prev_state": "prev_state",
                "auth_events": "auth_events",
                "origin": "domain",
                "origin_server_ts": 1234,
                "membership": "join",
                "content": {},
                "signatures": {"domain": {"algo:1": "sigs"}},
                "unsigned": {},
            },
        )

        # As of room versions we now redact the membership, prev_states, and origin keys.
        self.run_test(
            {
                "type": "A",
                "prev_state": "prev_state",
                "membership": "join",
                "origin": "example.com",
            },
            {"type": "A", "content": {}, "signatures": {}, "unsigned": {}},
            room_version=RoomVersions.V11,
        )

    def test_unsigned(self) -> None:
        """Ensure that unsigned properties get stripped (except age_ts and replaces_state)."""
        self.run_test(
            {
                "type": "B",
                "event_id": "$test:domain",
                "unsigned": {
                    "age_ts": 20,
                    "replaces_state": "$test2:domain",
                    "other_key": "foo",
                },
            },
            {
                "type": "B",
                "event_id": "$test:domain",
                "content": {},
                "signatures": {},
                "unsigned": {"age_ts": 20, "replaces_state": "$test2:domain"},
            },
        )

    def test_content(self) -> None:
        """The content dictionary should be stripped in most cases."""
        self.run_test(
            {"type": "C", "event_id": "$test:domain", "content": {"things": "here"}},
            {
                "type": "C",
                "event_id": "$test:domain",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
        )

        # Some events keep a single content key/value.
        EVENT_KEEP_CONTENT_KEYS = [
            ("member", "membership", "join"),
            ("join_rules", "join_rule", "invite"),
            ("history_visibility", "history_visibility", "shared"),
        ]
        for event_type, key, value in EVENT_KEEP_CONTENT_KEYS:
            self.run_test(
                {
                    "type": "m.room." + event_type,
                    "event_id": "$test:domain",
                    "content": {key: value, "other_key": "foo"},
                },
                {
                    "type": "m.room." + event_type,
                    "event_id": "$test:domain",
                    "content": {key: value},
                    "signatures": {},
                    "unsigned": {},
                },
            )

    def test_create(self) -> None:
        """Create events are partially redacted until MSC2176."""
        self.run_test(
            {
                "type": "m.room.create",
                "event_id": "$test:domain",
                "content": {"creator": "@2:domain", "other_key": "foo"},
            },
            {
                "type": "m.room.create",
                "event_id": "$test:domain",
                "content": {"creator": "@2:domain"},
                "signatures": {},
                "unsigned": {},
            },
        )

        # After MSC2176, create events should preserve field `content`
        self.run_test(
            {
                "type": "m.room.create",
                "content": {"not_a_real_key": True},
                "origin": "some_homeserver",
                "nonsense_field": "some_random_garbage",
            },
            {
                "type": "m.room.create",
                "content": {"not_a_real_key": True},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

    def test_power_levels(self) -> None:
        """Power level events keep a variety of content keys."""
        self.run_test(
            {
                "type": "m.room.power_levels",
                "event_id": "$test:domain",
                "content": {
                    "ban": 1,
                    "events": {"m.room.name": 100},
                    "events_default": 2,
                    "invite": 3,
                    "kick": 4,
                    "redact": 5,
                    "state_default": 6,
                    "users": {"@admin:domain": 100},
                    "users_default": 7,
                    "other_key": 8,
                },
            },
            {
                "type": "m.room.power_levels",
                "event_id": "$test:domain",
                "content": {
                    "ban": 1,
                    "events": {"m.room.name": 100},
                    "events_default": 2,
                    # Note that invite is not here.
                    "kick": 4,
                    "redact": 5,
                    "state_default": 6,
                    "users": {"@admin:domain": 100},
                    "users_default": 7,
                },
                "signatures": {},
                "unsigned": {},
            },
        )

        # After MSC2176, power levels events keep the invite key.
        self.run_test(
            {"type": "m.room.power_levels", "content": {"invite": 75}},
            {
                "type": "m.room.power_levels",
                "content": {"invite": 75},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

    def test_alias_event(self) -> None:
        """Alias events have special behavior up through room version 6."""
        self.run_test(
            {
                "type": "m.room.aliases",
                "event_id": "$test:domain",
                "content": {"aliases": ["test"]},
            },
            {
                "type": "m.room.aliases",
                "event_id": "$test:domain",
                "content": {"aliases": ["test"]},
                "signatures": {},
                "unsigned": {},
            },
        )

        # After MSC2432, alias events have no special behavior.
        self.run_test(
            {"type": "m.room.aliases", "content": {"aliases": ["test"]}},
            {
                "type": "m.room.aliases",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V6,
        )

    def test_redacts(self) -> None:
        """Redaction events have no special behaviour until MSC2174/MSC2176."""

        self.run_test(
            {
                "type": "m.room.redaction",
                "content": {"redacts": "$test2:domain"},
                "redacts": "$test2:domain",
            },
            {
                "type": "m.room.redaction",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V6,
        )

        # After MSC2174, redaction events keep the redacts content key.
        self.run_test(
            {
                "type": "m.room.redaction",
                "content": {"redacts": "$test2:domain"},
                "redacts": "$test2:domain",
            },
            {
                "type": "m.room.redaction",
                "content": {"redacts": "$test2:domain"},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

    def test_join_rules(self) -> None:
        """Join rules events have changed behavior starting with MSC3083."""
        self.run_test(
            {
                "type": "m.room.join_rules",
                "event_id": "$test:domain",
                "content": {
                    "join_rule": "invite",
                    "allow": [],
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.join_rules",
                "event_id": "$test:domain",
                "content": {"join_rule": "invite"},
                "signatures": {},
                "unsigned": {},
            },
        )

        # After MSC3083, the allow key is protected from redaction.
        self.run_test(
            {
                "type": "m.room.join_rules",
                "content": {
                    "join_rule": "invite",
                    "allow": [],
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.join_rules",
                "content": {
                    "join_rule": "invite",
                    "allow": [],
                },
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V8,
        )

    def test_member(self) -> None:
        """Member events have changed behavior in MSC3375 and MSC3821."""
        self.run_test(
            {
                "type": "m.room.member",
                "event_id": "$test:domain",
                "content": {
                    "membership": "join",
                    EventContentFields.AUTHORISING_USER: "@user:domain",
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.member",
                "event_id": "$test:domain",
                "content": {"membership": "join"},
                "signatures": {},
                "unsigned": {},
            },
        )

        # After MSC3375, the join_authorised_via_users_server key is protected
        # from redaction.
        self.run_test(
            {
                "type": "m.room.member",
                "content": {
                    "membership": "join",
                    EventContentFields.AUTHORISING_USER: "@user:domain",
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.member",
                "content": {
                    "membership": "join",
                    EventContentFields.AUTHORISING_USER: "@user:domain",
                },
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V9,
        )

        # After MSC3821, the signed key under third_party_invite is protected
        # from redaction.
        THIRD_PARTY_INVITE = {
            "display_name": "alice",
            "signed": {
                "mxid": "@alice:example.org",
                "signatures": {
                    "magic.forest": {
                        "ed25519:3": "fQpGIW1Snz+pwLZu6sTy2aHy/DYWWTspTJRPyNp0PKkymfIsNffysMl6ObMMFdIJhk6g6pwlIqZ54rxo8SLmAg"
                    }
                },
                "token": "abc123",
            },
        }

        self.run_test(
            {
                "type": "m.room.member",
                "content": {
                    "membership": "invite",
                    "third_party_invite": THIRD_PARTY_INVITE,
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.member",
                "content": {
                    "membership": "invite",
                    "third_party_invite": {"signed": THIRD_PARTY_INVITE["signed"]},
                },
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

        # Ensure this doesn't break if an invalid field is sent.
        self.run_test(
            {
                "type": "m.room.member",
                "content": {
                    "membership": "invite",
                    "third_party_invite": {},
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.member",
                "content": {"membership": "invite", "third_party_invite": {}},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

        self.run_test(
            {
                "type": "m.room.member",
                "content": {
                    "membership": "invite",
                    "third_party_invite": "stripped",
                    "other_key": "stripped",
                },
            },
            {
                "type": "m.room.member",
                "content": {"membership": "invite"},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V11,
        )

    def test_relations(self) -> None:
        """Event relations get redacted until MSC3389."""
        # Normally the m._relates_to field is redacted.
        self.run_test(
            {
                "type": "m.room.message",
                "content": {
                    "body": "foo",
                    "m.relates_to": {
                        "rel_type": "rel_type",
                        "event_id": "$parent:domain",
                        "other": "stripped",
                    },
                },
            },
            {
                "type": "m.room.message",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
            room_version=RoomVersions.V10,
        )

        # Create a new room version.
        msc3389_room_ver = attr.evolve(
            RoomVersions.V10, msc3389_relation_redactions=True
        )

        self.run_test(
            {
                "type": "m.room.message",
                "content": {
                    "body": "foo",
                    "m.relates_to": {
                        "rel_type": "rel_type",
                        "event_id": "$parent:domain",
                        "other": "stripped",
                    },
                },
            },
            {
                "type": "m.room.message",
                "content": {
                    "m.relates_to": {
                        "rel_type": "rel_type",
                        "event_id": "$parent:domain",
                    },
                },
                "signatures": {},
                "unsigned": {},
            },
            room_version=msc3389_room_ver,
        )

        # If the field is not an object, redact it.
        self.run_test(
            {
                "type": "m.room.message",
                "content": {
                    "body": "foo",
                    "m.relates_to": "stripped",
                },
            },
            {
                "type": "m.room.message",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
            room_version=msc3389_room_ver,
        )

        # If the m.relates_to property would be empty, redact it.
        self.run_test(
            {
                "type": "m.room.message",
                "content": {"body": "foo", "m.relates_to": {"foo": "stripped"}},
            },
            {
                "type": "m.room.message",
                "content": {},
                "signatures": {},
                "unsigned": {},
            },
            room_version=msc3389_room_ver,
        )


class SerializeEventTestCase(stdlib_unittest.TestCase):
    def serialize(self, ev: EventBase, fields: Optional[List[str]]) -> JsonDict:
        return serialize_event(
            ev, 1479807801915, config=SerializeEventConfig(only_event_fields=fields)
        )

    def test_event_fields_works_with_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(sender="@alice:localhost", room_id="!foo:bar"), ["room_id"]
            ),
            {"room_id": "!foo:bar"},
        )

    def test_event_fields_works_with_nested_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={"body": "A message"},
                ),
                ["content.body"],
            ),
            {"content": {"body": "A message"}},
        )

    def test_event_fields_works_with_dot_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={"key.with.dots": {}},
                ),
                [r"content.key\.with\.dots"],
            ),
            {"content": {"key.with.dots": {}}},
        )

    def test_event_fields_works_with_nested_dot_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={
                        "not_me": 1,
                        "nested.dot.key": {"leaf.key": 42, "not_me_either": 1},
                    },
                ),
                [r"content.nested\.dot\.key.leaf\.key"],
            ),
            {"content": {"nested.dot.key": {"leaf.key": 42}}},
        )

    def test_event_fields_nops_with_unknown_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={"foo": "bar"},
                ),
                ["content.foo", "content.notexists"],
            ),
            {"content": {"foo": "bar"}},
        )

    def test_event_fields_nops_with_non_dict_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={"foo": ["I", "am", "an", "array"]},
                ),
                ["content.foo.am"],
            ),
            {},
        )

    def test_event_fields_nops_with_array_keys(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={"foo": ["I", "am", "an", "array"]},
                ),
                ["content.foo.1"],
            ),
            {},
        )

    def test_event_fields_all_fields_if_empty(self) -> None:
        self.assertEqual(
            self.serialize(
                MockEvent(
                    type="foo",
                    event_id="test",
                    room_id="!foo:bar",
                    content={"foo": "bar"},
                ),
                [],
            ),
            {
                "type": "foo",
                "event_id": "test",
                "room_id": "!foo:bar",
                "content": {"foo": "bar"},
                "unsigned": {},
            },
        )

    def test_event_fields_fail_if_fields_not_str(self) -> None:
        with self.assertRaises(TypeError):
            self.serialize(
                MockEvent(room_id="!foo:bar", content={"foo": "bar"}), ["room_id", 4]  # type: ignore[list-item]
            )


class CopyPowerLevelsContentTestCase(stdlib_unittest.TestCase):
    def setUp(self) -> None:
        self.test_content: PowerLevelsContent = {
            "ban": 50,
            "events": {"m.room.name": 100, "m.room.power_levels": 100},
            "events_default": 0,
            "invite": 50,
            "kick": 50,
            "notifications": {"room": 20},
            "redact": 50,
            "state_default": 50,
            "users": {"@example:localhost": 100},
            "users_default": 0,
        }

    def _test(self, input: PowerLevelsContent) -> None:
        a = copy_and_fixup_power_levels_contents(input)

        self.assertEqual(a["ban"], 50)
        assert isinstance(a["events"], Mapping)
        self.assertEqual(a["events"]["m.room.name"], 100)

        # make sure that changing the copy changes the copy and not the orig
        a["ban"] = 10
        a["events"]["m.room.power_levels"] = 20

        self.assertEqual(input["ban"], 50)
        assert isinstance(input["events"], Mapping)
        self.assertEqual(input["events"]["m.room.power_levels"], 100)

    def test_unfrozen(self) -> None:
        self._test(self.test_content)

    def test_frozen(self) -> None:
        input = freeze(self.test_content)
        self._test(input)

    def test_stringy_integers(self) -> None:
        """String representations of decimal integers are converted to integers."""
        input: PowerLevelsContent = {
            "a": "100",
            "b": {
                "foo": 99,
                "bar": "-98",
            },
            "d": "0999",
        }
        output = copy_and_fixup_power_levels_contents(input)
        expected_output = {
            "a": 100,
            "b": {
                "foo": 99,
                "bar": -98,
            },
            "d": 999,
        }

        self.assertEqual(output, expected_output)

    def test_strings_that_dont_represent_decimal_integers(self) -> None:
        """Should raise when given inputs `s` for which `int(s, base=10)` raises."""
        for invalid_string in ["0x123", "123.0", "123.45", "hello", "0b1", "0o777"]:
            with self.assertRaises(TypeError):
                copy_and_fixup_power_levels_contents({"a": invalid_string})

    def test_invalid_types_raise_type_error(self) -> None:
        with self.assertRaises(TypeError):
            copy_and_fixup_power_levels_contents({"a": ["hello", "grandma"]})  # type: ignore[dict-item]
            copy_and_fixup_power_levels_contents({"a": None})  # type: ignore[dict-item]

    def test_invalid_nesting_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            copy_and_fixup_power_levels_contents({"a": {"b": {"c": 1}}})  # type: ignore[dict-item]


class SplitFieldTestCase(stdlib_unittest.TestCase):
    @parameterized.expand(
        [
            # A field with no dots.
            ["m", ["m"]],
            # Simple dotted fields.
            ["m.foo", ["m", "foo"]],
            ["m.foo.bar", ["m", "foo", "bar"]],
            # Backslash is used as an escape character.
            [r"m\.foo", ["m.foo"]],
            [r"m\\.foo", ["m\\", "foo"]],
            [r"m\\\.foo", [r"m\.foo"]],
            [r"m\\\\.foo", ["m\\\\", "foo"]],
            [r"m\foo", [r"m\foo"]],
            [r"m\\foo", [r"m\foo"]],
            [r"m\\\foo", [r"m\\foo"]],
            [r"m\\\\foo", [r"m\\foo"]],
            # Ensure that escapes at the end don't cause issues.
            ["m.foo\\", ["m", "foo\\"]],
            ["m.foo\\", ["m", "foo\\"]],
            [r"m.foo\.", ["m", "foo."]],
            [r"m.foo\\.", ["m", "foo\\", ""]],
            [r"m.foo\\\.", ["m", r"foo\."]],
            # Empty parts (corresponding to properties which are an empty string) are allowed.
            [".m", ["", "m"]],
            ["..m", ["", "", "m"]],
            ["m.", ["m", ""]],
            ["m..", ["m", "", ""]],
            ["m..foo", ["m", "", "foo"]],
            # Invalid escape sequences.
            [r"\m", [r"\m"]],
        ]
    )
    def test_split_field(self, input: str, expected: str) -> None:
        self.assertEqual(_split_field(input), expected)
