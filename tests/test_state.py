# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from synapse.events import FrozenEvent
from synapse.api.auth import Auth
from synapse.api.constants import EventTypes, Membership
from synapse.state import StateHandler

from .utils import MockClock

from mock import Mock


_next_event_id = 1000


def create_event(name=None, type=None, state_key=None, depth=2, event_id=None,
                 prev_events=[], **kwargs):
    global _next_event_id

    if not event_id:
        _next_event_id += 1
        event_id = "$%s:test" % (_next_event_id,)

    if not name:
        if state_key is not None:
            name = "<%s-%s, %s>" % (type, state_key, event_id,)
        else:
            name = "<%s, %s>" % (type, event_id,)

    d = {
        "event_id": event_id,
        "type": type,
        "sender": "@user_id:example.com",
        "room_id": "!room_id:example.com",
        "depth": depth,
        "prev_events": prev_events,
    }

    if state_key is not None:
        d["state_key"] = state_key

    d.update(kwargs)

    event = FrozenEvent(d)

    return event


class StateGroupStore(object):
    def __init__(self):
        self._event_to_state_group = {}
        self._group_to_state = {}

        self._event_id_to_event = {}

        self._next_group = 1

    def get_state_groups_ids(self, room_id, event_ids):
        groups = {}
        for event_id in event_ids:
            group = self._event_to_state_group.get(event_id)
            if group:
                groups[group] = self._group_to_state[group]

        return defer.succeed(groups)

    def store_state_groups(self, event, context):
        if context.current_state_ids is None:
            return

        state_events = dict(context.current_state_ids)

        self._group_to_state[context.state_group] = state_events
        self._event_to_state_group[event.event_id] = context.state_group

    def get_events(self, event_ids, **kwargs):
        return {
            e_id: self._event_id_to_event[e_id] for e_id in event_ids
            if e_id in self._event_id_to_event
        }

    def register_events(self, events):
        for e in events:
            self._event_id_to_event[e.event_id] = e


class DictObj(dict):
    def __init__(self, **kwargs):
        super(DictObj, self).__init__(kwargs)
        self.__dict__ = self


class Graph(object):
    def __init__(self, nodes, edges):
        events = {}
        clobbered = set(events.keys())

        for event_id, fields in nodes.items():
            refs = edges.get(event_id)
            if refs:
                clobbered.difference_update(refs)
                prev_events = [(r, {}) for r in refs]
            else:
                prev_events = []

            events[event_id] = create_event(
                event_id=event_id,
                prev_events=prev_events,
                **fields
            )

        self._leaves = clobbered
        self._events = sorted(events.values(), key=lambda e: e.depth)

    def walk(self):
        return iter(self._events)

    def get_leaves(self):
        return (self._events[i] for i in self._leaves)


class StateTestCase(unittest.TestCase):
    def setUp(self):
        self.store = Mock(
            spec_set=[
                "get_state_groups_ids",
                "add_event_hashes",
                "get_events",
                "get_next_state_group",
            ]
        )
        hs = Mock(spec_set=[
            "get_datastore", "get_auth", "get_state_handler", "get_clock",
        ])
        hs.get_datastore.return_value = self.store
        hs.get_state_handler.return_value = None
        hs.get_clock.return_value = MockClock()
        hs.get_auth.return_value = Auth(hs)

        self.store.get_next_state_group.side_effect = Mock

        self.state = StateHandler(hs)
        self.event_id = 0

    @defer.inlineCallbacks
    def test_branch_no_conflict(self):
        graph = Graph(
            nodes={
                "START": DictObj(
                    type=EventTypes.Create,
                    state_key="",
                    depth=1,
                ),
                "A": DictObj(
                    type=EventTypes.Message,
                    depth=2,
                ),
                "B": DictObj(
                    type=EventTypes.Message,
                    depth=3,
                ),
                "C": DictObj(
                    type=EventTypes.Name,
                    state_key="",
                    depth=3,
                ),
                "D": DictObj(
                    type=EventTypes.Message,
                    depth=4,
                ),
            },
            edges={
                "A": ["START"],
                "B": ["A"],
                "C": ["A"],
                "D": ["B", "C"]
            }
        )

        store = StateGroupStore()
        self.store.get_state_groups_ids.side_effect = store.get_state_groups_ids

        context_store = {}

        for event in graph.walk():
            context = yield self.state.compute_event_context(event)
            store.store_state_groups(event, context)
            context_store[event.event_id] = context

        self.assertEqual(2, len(context_store["D"].prev_state_ids))

    @defer.inlineCallbacks
    def test_branch_basic_conflict(self):
        graph = Graph(
            nodes={
                "START": DictObj(
                    type=EventTypes.Create,
                    state_key="",
                    content={"creator": "@user_id:example.com"},
                    depth=1,
                ),
                "A": DictObj(
                    type=EventTypes.Member,
                    state_key="@user_id:example.com",
                    content={"membership": Membership.JOIN},
                    membership=Membership.JOIN,
                    depth=2,
                ),
                "B": DictObj(
                    type=EventTypes.Name,
                    state_key="",
                    depth=3,
                ),
                "C": DictObj(
                    type=EventTypes.Name,
                    state_key="",
                    depth=4,
                ),
                "D": DictObj(
                    type=EventTypes.Message,
                    depth=5,
                ),
            },
            edges={
                "A": ["START"],
                "B": ["A"],
                "C": ["A"],
                "D": ["B", "C"]
            }
        )

        store = StateGroupStore()
        self.store.get_state_groups_ids.side_effect = store.get_state_groups_ids
        self.store.get_events = store.get_events
        store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield self.state.compute_event_context(event)
            store.store_state_groups(event, context)
            context_store[event.event_id] = context

        self.assertSetEqual(
            {"START", "A", "C"},
            {e_id for e_id in context_store["D"].prev_state_ids.values()}
        )

    @defer.inlineCallbacks
    def test_branch_have_banned_conflict(self):
        graph = Graph(
            nodes={
                "START": DictObj(
                    type=EventTypes.Create,
                    state_key="",
                    content={"creator": "@user_id:example.com"},
                    depth=1,
                ),
                "A": DictObj(
                    type=EventTypes.Member,
                    state_key="@user_id:example.com",
                    content={"membership": Membership.JOIN},
                    membership=Membership.JOIN,
                    depth=2,
                ),
                "B": DictObj(
                    type=EventTypes.Name,
                    state_key="",
                    depth=3,
                ),
                "C": DictObj(
                    type=EventTypes.Member,
                    state_key="@user_id_2:example.com",
                    content={"membership": Membership.BAN},
                    membership=Membership.BAN,
                    depth=4,
                ),
                "D": DictObj(
                    type=EventTypes.Name,
                    state_key="",
                    depth=4,
                    sender="@user_id_2:example.com",
                ),
                "E": DictObj(
                    type=EventTypes.Message,
                    depth=5,
                ),
            },
            edges={
                "A": ["START"],
                "B": ["A"],
                "C": ["B"],
                "D": ["B"],
                "E": ["C", "D"]
            }
        )

        store = StateGroupStore()
        self.store.get_state_groups_ids.side_effect = store.get_state_groups_ids
        self.store.get_events = store.get_events
        store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield self.state.compute_event_context(event)
            store.store_state_groups(event, context)
            context_store[event.event_id] = context

        self.assertSetEqual(
            {"START", "A", "B", "C"},
            {e for e in context_store["E"].prev_state_ids.values()}
        )

    @defer.inlineCallbacks
    def test_branch_have_perms_conflict(self):
        userid1 = "@user_id:example.com"
        userid2 = "@user_id2:example.com"

        nodes = {
            "A1": DictObj(
                type=EventTypes.Create,
                state_key="",
                content={"creator": userid1},
                depth=1,
            ),
            "A2": DictObj(
                type=EventTypes.Member,
                state_key=userid1,
                content={"membership": Membership.JOIN},
                membership=Membership.JOIN,
            ),
            "A3": DictObj(
                type=EventTypes.Member,
                state_key=userid2,
                content={"membership": Membership.JOIN},
                membership=Membership.JOIN,
            ),
            "A4": DictObj(
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "events": {"m.room.name": 50},
                    "users": {userid1: 100,
                              userid2: 60},
                },
            ),
            "A5": DictObj(
                type=EventTypes.Name,
                state_key="",
            ),
            "B": DictObj(
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "events": {"m.room.name": 50},
                    "users": {userid2: 30},
                },
            ),
            "C": DictObj(
                type=EventTypes.Name,
                state_key="",
                sender=userid2,
            ),
            "D": DictObj(
                type=EventTypes.Message,
            ),
        }
        edges = {
            "A2": ["A1"],
            "A3": ["A2"],
            "A4": ["A3"],
            "A5": ["A4"],
            "B": ["A5"],
            "C": ["A5"],
            "D": ["B", "C"]
        }
        self._add_depths(nodes, edges)
        graph = Graph(nodes, edges)

        store = StateGroupStore()
        self.store.get_state_groups_ids.side_effect = store.get_state_groups_ids
        self.store.get_events = store.get_events
        store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield self.state.compute_event_context(event)
            store.store_state_groups(event, context)
            context_store[event.event_id] = context

        self.assertSetEqual(
            {"A1", "A2", "A3", "A5", "B"},
            {e for e in context_store["D"].prev_state_ids.values()}
        )

    def _add_depths(self, nodes, edges):
        def _get_depth(ev):
            node = nodes[ev]
            if 'depth' not in node:
                prevs = edges[ev]
                depth = max(_get_depth(prev) for prev in prevs) + 1
                node['depth'] = depth
            return node['depth']

        for n in nodes:
            _get_depth(n)

    @defer.inlineCallbacks
    def test_annotate_with_old_message(self):
        event = create_event(type="test_message", name="event")

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        context = yield self.state.compute_event_context(
            event, old_state=old_state
        )

        self.assertEqual(
            set(e.event_id for e in old_state), set(context.current_state_ids.values())
        )

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_annotate_with_old_state(self):
        event = create_event(type="state", state_key="", name="event")

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        context = yield self.state.compute_event_context(
            event, old_state=old_state
        )

        self.assertEqual(
            set(e.event_id for e in old_state), set(context.prev_state_ids.values())
        )

    @defer.inlineCallbacks
    def test_trivial_annotate_message(self):
        event = create_event(type="test_message", name="event")

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        group_name = "group_name_1"

        self.store.get_state_groups_ids.return_value = {
            group_name: {(e.type, e.state_key): e.event_id for e in old_state},
        }

        context = yield self.state.compute_event_context(event)

        self.assertEqual(
            set([e.event_id for e in old_state]),
            set(context.current_state_ids.values())
        )

        self.assertEqual(group_name, context.state_group)

    @defer.inlineCallbacks
    def test_trivial_annotate_state(self):
        event = create_event(type="state", state_key="", name="event")

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        group_name = "group_name_1"

        self.store.get_state_groups_ids.return_value = {
            group_name: {(e.type, e.state_key): e.event_id for e in old_state},
        }

        context = yield self.state.compute_event_context(event)

        self.assertEqual(
            set([e.event_id for e in old_state]),
            set(context.prev_state_ids.values())
        )

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_resolve_message_conflict(self):
        event = create_event(type="test_message", name="event")

        creation = create_event(
            type=EventTypes.Create, state_key=""
        )

        old_state_1 = [
            creation,
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        old_state_2 = [
            creation,
            create_event(type="test1", state_key="1"),
            create_event(type="test3", state_key="2"),
            create_event(type="test4", state_key=""),
        ]

        store = StateGroupStore()
        store.register_events(old_state_1)
        store.register_events(old_state_2)
        self.store.get_events = store.get_events

        context = yield self._get_context(event, old_state_1, old_state_2)

        self.assertEqual(len(context.current_state_ids), 6)

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_resolve_state_conflict(self):
        event = create_event(type="test4", state_key="", name="event")

        creation = create_event(
            type=EventTypes.Create, state_key=""
        )

        old_state_1 = [
            creation,
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        old_state_2 = [
            creation,
            create_event(type="test1", state_key="1"),
            create_event(type="test3", state_key="2"),
            create_event(type="test4", state_key=""),
        ]

        store = StateGroupStore()
        store.register_events(old_state_1)
        store.register_events(old_state_2)
        self.store.get_events = store.get_events

        context = yield self._get_context(event, old_state_1, old_state_2)

        self.assertEqual(len(context.current_state_ids), 6)

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_standard_depth_conflict(self):
        event = create_event(type="test4", name="event")

        member_event = create_event(
            type=EventTypes.Member,
            state_key="@user_id:example.com",
            content={
                "membership": Membership.JOIN,
            }
        )

        creation = create_event(
            type=EventTypes.Create, state_key="",
            content={"creator": "@foo:bar"}
        )

        old_state_1 = [
            creation,
            member_event,
            create_event(type="test1", state_key="1", depth=1),
        ]

        old_state_2 = [
            creation,
            member_event,
            create_event(type="test1", state_key="1", depth=2),
        ]

        store = StateGroupStore()
        store.register_events(old_state_1)
        store.register_events(old_state_2)
        self.store.get_events = store.get_events

        context = yield self._get_context(event, old_state_1, old_state_2)

        self.assertEqual(
            old_state_2[2].event_id, context.current_state_ids[("test1", "1")]
        )

        # Reverse the depth to make sure we are actually using the depths
        # during state resolution.

        old_state_1 = [
            creation,
            member_event,
            create_event(type="test1", state_key="1", depth=2),
        ]

        old_state_2 = [
            creation,
            member_event,
            create_event(type="test1", state_key="1", depth=1),
        ]

        store.register_events(old_state_1)
        store.register_events(old_state_2)

        context = yield self._get_context(event, old_state_1, old_state_2)

        self.assertEqual(
            old_state_1[2].event_id, context.current_state_ids[("test1", "1")]
        )

    def _get_context(self, event, old_state_1, old_state_2):
        group_name_1 = "group_name_1"
        group_name_2 = "group_name_2"

        self.store.get_state_groups_ids.return_value = {
            group_name_1: {(e.type, e.state_key): e.event_id for e in old_state_1},
            group_name_2: {(e.type, e.state_key): e.event_id for e in old_state_2},
        }

        return self.state.compute_event_context(event)
