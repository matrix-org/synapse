# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from tests import unittest
from twisted.internet import defer

from synapse.state import StateHandler

from mock import Mock


class StateTestCase(unittest.TestCase):
    def setUp(self):
        self.store = Mock(
            spec_set=[
                "get_state_groups",
            ]
        )
        hs = Mock(spec=["get_datastore"])
        hs.get_datastore.return_value = self.store

        self.state = StateHandler(hs)
        self.event_id = 0

    @defer.inlineCallbacks
    def test_annotate_with_old_message(self):
        event = self.create_event(type="test_message", name="event")

        old_state = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        yield self.state.annotate_event_with_state(event, old_state=old_state)

        for k, v in event.old_state_events.items():
            type, state_key = k
            self.assertEqual(type, v.type)
            self.assertEqual(state_key, v.state_key)

        self.assertEqual(set(old_state), set(event.old_state_events.values()))
        self.assertDictEqual(event.old_state_events, event.state_events)

        self.assertIsNone(event.state_group)

    @defer.inlineCallbacks
    def test_annotate_with_old_state(self):
        event = self.create_event(type="state", state_key="", name="event")

        old_state = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        yield self.state.annotate_event_with_state(event, old_state=old_state)

        for k, v in event.old_state_events.items():
            type, state_key = k
            self.assertEqual(type, v.type)
            self.assertEqual(state_key, v.state_key)

        self.assertEqual(
            set(old_state + [event]),
            set(event.old_state_events.values())
        )

        self.assertDictEqual(event.old_state_events, event.state_events)

        self.assertIsNone(event.state_group)

    @defer.inlineCallbacks
    def test_trivial_annotate_message(self):
        event = self.create_event(type="test_message", name="event")
        event.prev_events = []

        old_state = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        group_name = "group_name_1"

        self.store.get_state_groups.return_value = {
            group_name: old_state,
        }

        yield self.state.annotate_event_with_state(event)

        for k, v in event.old_state_events.items():
            type, state_key = k
            self.assertEqual(type, v.type)
            self.assertEqual(state_key, v.state_key)

        self.assertEqual(
            set([e.event_id for e in old_state]),
            set([e.event_id for e in event.old_state_events.values()])
        )

        self.assertDictEqual(
            {
                k: v.event_id
                for k, v in event.old_state_events.items()
            },
            {
                k: v.event_id
                for k, v in event.state_events.items()
            }
        )

        self.assertEqual(group_name, event.state_group)

    @defer.inlineCallbacks
    def test_trivial_annotate_state(self):
        event = self.create_event(type="state", state_key="", name="event")
        event.prev_events = []

        old_state = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        group_name = "group_name_1"

        self.store.get_state_groups.return_value = {
            group_name: old_state,
        }

        yield self.state.annotate_event_with_state(event)

        for k, v in event.old_state_events.items():
            type, state_key = k
            self.assertEqual(type, v.type)
            self.assertEqual(state_key, v.state_key)

        self.assertEqual(
            set([e.event_id for e in old_state]),
            set([e.event_id for e in event.old_state_events.values()])
        )

        self.assertEqual(
            set([e.event_id for e in old_state] + [event.event_id]),
            set([e.event_id for e in event.state_events.values()])
        )

        new_state = {
            k: v.event_id
            for k, v in event.state_events.items()
        }
        old_state = {
            k: v.event_id
            for k, v in event.old_state_events.items()
        }
        old_state[(event.type, event.state_key)] = event.event_id
        self.assertDictEqual(
            old_state,
            new_state
        )

        self.assertIsNone(event.state_group)

    @defer.inlineCallbacks
    def test_resolve_message_conflict(self):
        event = self.create_event(type="test_message", name="event")
        event.prev_events = []

        old_state_1 = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        old_state_2 = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test3", state_key="2"),
            self.create_event(type="test4", state_key=""),
        ]

        group_name_1 = "group_name_1"
        group_name_2 = "group_name_2"

        self.store.get_state_groups.return_value = {
            group_name_1: old_state_1,
            group_name_2: old_state_2,
        }

        yield self.state.annotate_event_with_state(event)

        self.assertEqual(len(event.old_state_events), 5)

        self.assertEqual(
            set([e.event_id for e in event.state_events.values()]),
            set([e.event_id for e in event.old_state_events.values()])
        )

        self.assertIsNone(event.state_group)

    @defer.inlineCallbacks
    def test_resolve_state_conflict(self):
        event = self.create_event(type="test4", state_key="", name="event")
        event.prev_events = []

        old_state_1 = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test1", state_key="2"),
            self.create_event(type="test2", state_key=""),
        ]

        old_state_2 = [
            self.create_event(type="test1", state_key="1"),
            self.create_event(type="test3", state_key="2"),
            self.create_event(type="test4", state_key=""),
        ]

        group_name_1 = "group_name_1"
        group_name_2 = "group_name_2"

        self.store.get_state_groups.return_value = {
            group_name_1: old_state_1,
            group_name_2: old_state_2,
        }

        yield self.state.annotate_event_with_state(event)

        self.assertEqual(len(event.old_state_events), 5)

        expected_new = event.old_state_events
        expected_new[(event.type, event.state_key)] = event

        self.assertEqual(
            set([e.event_id for e in expected_new.values()]),
            set([e.event_id for e in event.state_events.values()]),
        )

        self.assertIsNone(event.state_group)

    def create_event(self, name=None, type=None, state_key=None):
        self.event_id += 1
        event_id = str(self.event_id)

        if not name:
            if state_key is not None:
                name = "<%s-%s>" % (type, state_key)
            else:
                name = "<%s>" % (type, )

        event = Mock(name=name, spec=[])
        event.type = type

        if state_key is not None:
            event.state_key = state_key
        event.event_id = event_id

        event.user_id = "@user_id:example.com"
        event.room_id = "!room_id:example.com"

        return event
