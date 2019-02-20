# -*- coding: utf-8 -*-
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


from synapse.events import FrozenEvent
from synapse.events.utils import prune_event, serialize_event

from .. import unittest


def MockEvent(**kwargs):
    if "event_id" not in kwargs:
        kwargs["event_id"] = "fake_event_id"
    if "type" not in kwargs:
        kwargs["type"] = "fake_type"
    return FrozenEvent(kwargs)


class PruneEventTestCase(unittest.TestCase):
    """ Asserts that a new event constructed with `evdict` will look like
    `matchdict` when it is redacted. """

    def run_test(self, evdict, matchdict):
        self.assertEquals(prune_event(FrozenEvent(evdict)).get_dict(), matchdict)

    def test_minimal(self):
        self.run_test(
            {'type': 'A', 'event_id': '$test:domain'},
            {
                'type': 'A',
                'event_id': '$test:domain',
                'content': {},
                'signatures': {},
                'unsigned': {},
            },
        )

    def test_basic_keys(self):
        self.run_test(
            {
                'type': 'A',
                'room_id': '!1:domain',
                'sender': '@2:domain',
                'event_id': '$3:domain',
                'origin': 'domain',
            },
            {
                'type': 'A',
                'room_id': '!1:domain',
                'sender': '@2:domain',
                'event_id': '$3:domain',
                'origin': 'domain',
                'content': {},
                'signatures': {},
                'unsigned': {},
            },
        )

    def test_unsigned_age_ts(self):
        self.run_test(
            {'type': 'B', 'event_id': '$test:domain', 'unsigned': {'age_ts': 20}},
            {
                'type': 'B',
                'event_id': '$test:domain',
                'content': {},
                'signatures': {},
                'unsigned': {'age_ts': 20},
            },
        )

        self.run_test(
            {
                'type': 'B',
                'event_id': '$test:domain',
                'unsigned': {'other_key': 'here'},
            },
            {
                'type': 'B',
                'event_id': '$test:domain',
                'content': {},
                'signatures': {},
                'unsigned': {},
            },
        )

    def test_content(self):
        self.run_test(
            {'type': 'C', 'event_id': '$test:domain', 'content': {'things': 'here'}},
            {
                'type': 'C',
                'event_id': '$test:domain',
                'content': {},
                'signatures': {},
                'unsigned': {},
            },
        )

        self.run_test(
            {
                'type': 'm.room.create',
                'event_id': '$test:domain',
                'content': {'creator': '@2:domain', 'other_field': 'here'},
            },
            {
                'type': 'm.room.create',
                'event_id': '$test:domain',
                'content': {'creator': '@2:domain'},
                'signatures': {},
                'unsigned': {},
            },
        )


class SerializeEventTestCase(unittest.TestCase):
    def serialize(self, ev, fields):
        return serialize_event(ev, 1479807801915, only_event_fields=fields)

    def test_event_fields_works_with_keys(self):
        self.assertEquals(
            self.serialize(
                MockEvent(sender="@alice:localhost", room_id="!foo:bar"), ["room_id"]
            ),
            {"room_id": "!foo:bar"},
        )

    def test_event_fields_works_with_nested_keys(self):
        self.assertEquals(
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

    def test_event_fields_works_with_dot_keys(self):
        self.assertEquals(
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

    def test_event_fields_works_with_nested_dot_keys(self):
        self.assertEquals(
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

    def test_event_fields_nops_with_unknown_keys(self):
        self.assertEquals(
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

    def test_event_fields_nops_with_non_dict_keys(self):
        self.assertEquals(
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

    def test_event_fields_nops_with_array_keys(self):
        self.assertEquals(
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

    def test_event_fields_all_fields_if_empty(self):
        self.assertEquals(
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

    def test_event_fields_fail_if_fields_not_str(self):
        with self.assertRaises(TypeError):
            self.serialize(
                MockEvent(room_id="!foo:bar", content={"foo": "bar"}), ["room_id", 4]
            )
