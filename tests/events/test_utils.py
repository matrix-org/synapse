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


from .. import unittest

from synapse.events import FrozenEvent
from synapse.events.utils import prune_event, serialize_event


def MockEvent(**kwargs):
    return FrozenEvent(kwargs)


class PruneEventTestCase(unittest.TestCase):
    """ Asserts that a new event constructed with `evdict` will look like
    `matchdict` when it is redacted. """
    def run_test(self, evdict, matchdict):
        self.assertEquals(
            prune_event(FrozenEvent(evdict)).get_dict(),
            matchdict
        )

    def test_minimal(self):
        self.run_test(
            {'type': 'A'},
            {
                'type': 'A',
                'content': {},
                'signatures': {},
                'unsigned': {},
            }
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
            }
        )

    def test_unsigned_age_ts(self):
        self.run_test(
            {
                'type': 'B',
                'unsigned': {'age_ts': 20},
            },
            {
                'type': 'B',
                'content': {},
                'signatures': {},
                'unsigned': {'age_ts': 20},
            }
        )

        self.run_test(
            {
                'type': 'B',
                'unsigned': {'other_key': 'here'},
            },
            {
                'type': 'B',
                'content': {},
                'signatures': {},
                'unsigned': {},
            }
        )

    def test_content(self):
        self.run_test(
            {
                'type': 'C',
                'content': {'things': 'here'},
            },
            {
                'type': 'C',
                'content': {},
                'signatures': {},
                'unsigned': {},
            }
        )

        self.run_test(
            {
                'type': 'm.room.create',
                'content': {'creator': '@2:domain', 'other_field': 'here'},
            },
            {
                'type': 'm.room.create',
                'content': {'creator': '@2:domain'},
                'signatures': {},
                'unsigned': {},
            }
        )


class SerializeEventTestCase(unittest.TestCase):

    def serialize(self, ev, fields):
        return serialize_event(ev, 1924354, event_fields=fields)

    def test_event_fields_works_with_keys(self):
        self.assertEquals(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar"
                ),
                ["room_id"]
            ),
            {
                "room_id": "!foo:bar",
            }
        )

    def test_event_fields_works_with_nested_keys(self):
        self.assertEquals(
            self.serialize(
                MockEvent(
                    sender="@alice:localhost",
                    room_id="!foo:bar",
                    content={
                        "body": "A message",
                    },
                ),
                ["content.body"]
            ),
            {
                "content": {
                    "body": "A message",
                }
            }
        )

    def test_event_fields_works_with_dot_keys(self):
        pass

    def test_event_fields_works_with_nested_dot_keys(self):
        pass

    def test_event_fields_nops_with_unknown_keys(self):
        pass

    def test_event_fields_nops_with_non_dict_keys(self):
        pass
