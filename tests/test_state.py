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

from mock import Mock

from twisted.internet import defer

from synapse.api.auth import Auth
from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events import make_event_from_dict
from synapse.events.snapshot import EventContext
from synapse.state import StateHandler, StateResolutionHandler

from tests import unittest

from .utils import MockClock, default_config

_next_event_id = 1000


def create_event(
    name=None,
    type=None,
    state_key=None,
    depth=2,
    event_id=None,
    prev_events=[],
    **kwargs
):
    global _next_event_id

    if not event_id:
        _next_event_id += 1
        event_id = "$%s:test" % (_next_event_id,)

    if not name:
        if state_key is not None:
            name = "<%s-%s, %s>" % (type, state_key, event_id)
        else:
            name = "<%s, %s>" % (type, event_id)

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

    event = make_event_from_dict(d)

    return event


class StateGroupStore:
    def __init__(self):
        self._event_to_state_group = {}
        self._group_to_state = {}

        self._event_id_to_event = {}

        self._next_group = 1

    async def get_state_groups_ids(self, room_id, event_ids):
        groups = {}
        for event_id in event_ids:
            group = self._event_to_state_group.get(event_id)
            if group:
                groups[group] = self._group_to_state[group]

        return groups

    async def store_state_group(
        self, event_id, room_id, prev_group, delta_ids, current_state_ids
    ):
        state_group = self._next_group
        self._next_group += 1

        self._group_to_state[state_group] = dict(current_state_ids)

        return state_group

    async def get_events(self, event_ids, **kwargs):
        return {
            e_id: self._event_id_to_event[e_id]
            for e_id in event_ids
            if e_id in self._event_id_to_event
        }

    async def get_state_group_delta(self, name):
        return (None, None)

    def register_events(self, events):
        for e in events:
            self._event_id_to_event[e.event_id] = e

    def register_event_context(self, event, context):
        self._event_to_state_group[event.event_id] = context.state_group

    def register_event_id_state_group(self, event_id, state_group):
        self._event_to_state_group[event_id] = state_group

    async def get_room_version_id(self, room_id):
        return RoomVersions.V1.identifier


class DictObj(dict):
    def __init__(self, **kwargs):
        super().__init__(kwargs)
        self.__dict__ = self


class Graph:
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
                event_id=event_id, prev_events=prev_events, **fields
            )

        self._leaves = clobbered
        self._events = sorted(events.values(), key=lambda e: e.depth)

    def walk(self):
        return iter(self._events)

    def get_leaves(self):
        return (self._events[i] for i in self._leaves)


class StateTestCase(unittest.TestCase):
    def setUp(self):
        self.store = StateGroupStore()
        storage = Mock(main=self.store, state=self.store)
        hs = Mock(
            spec_set=[
                "config",
                "get_datastore",
                "get_storage",
                "get_auth",
                "get_state_handler",
                "get_clock",
                "get_state_resolution_handler",
                "hostname",
            ]
        )
        hs.config = default_config("tesths", True)
        hs.get_datastore.return_value = self.store
        hs.get_state_handler.return_value = None
        hs.get_clock.return_value = MockClock()
        hs.get_auth.return_value = Auth(hs)
        hs.get_state_resolution_handler = lambda: StateResolutionHandler(hs)
        hs.get_storage.return_value = storage

        self.state = StateHandler(hs)
        self.event_id = 0

    @defer.inlineCallbacks
    def test_branch_no_conflict(self):
        graph = Graph(
            nodes={
                "START": DictObj(
                    type=EventTypes.Create, state_key="", content={}, depth=1
                ),
                "A": DictObj(type=EventTypes.Message, depth=2),
                "B": DictObj(type=EventTypes.Message, depth=3),
                "C": DictObj(type=EventTypes.Name, state_key="", depth=3),
                "D": DictObj(type=EventTypes.Message, depth=4),
            },
            edges={"A": ["START"], "B": ["A"], "C": ["A"], "D": ["B", "C"]},
        )

        self.store.register_events(graph.walk())

        context_store = {}  # type: dict[str, EventContext]

        for event in graph.walk():
            context = yield defer.ensureDeferred(
                self.state.compute_event_context(event)
            )
            self.store.register_event_context(event, context)
            context_store[event.event_id] = context

        ctx_c = context_store["C"]
        ctx_d = context_store["D"]

        prev_state_ids = yield defer.ensureDeferred(ctx_d.get_prev_state_ids())
        self.assertEqual(2, len(prev_state_ids))

        self.assertEqual(ctx_c.state_group, ctx_d.state_group_before_event)
        self.assertEqual(ctx_d.state_group_before_event, ctx_d.state_group)

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
                "B": DictObj(type=EventTypes.Name, state_key="", depth=3),
                "C": DictObj(type=EventTypes.Name, state_key="", depth=4),
                "D": DictObj(type=EventTypes.Message, depth=5),
            },
            edges={"A": ["START"], "B": ["A"], "C": ["A"], "D": ["B", "C"]},
        )

        self.store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield defer.ensureDeferred(
                self.state.compute_event_context(event)
            )
            self.store.register_event_context(event, context)
            context_store[event.event_id] = context

        # C ends up winning the resolution between B and C

        ctx_c = context_store["C"]
        ctx_d = context_store["D"]

        prev_state_ids = yield defer.ensureDeferred(ctx_d.get_prev_state_ids())
        self.assertSetEqual({"START", "A", "C"}, set(prev_state_ids.values()))

        self.assertEqual(ctx_c.state_group, ctx_d.state_group_before_event)
        self.assertEqual(ctx_d.state_group_before_event, ctx_d.state_group)

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
                "B": DictObj(type=EventTypes.Name, state_key="", depth=3),
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
                "E": DictObj(type=EventTypes.Message, depth=5),
            },
            edges={"A": ["START"], "B": ["A"], "C": ["B"], "D": ["B"], "E": ["C", "D"]},
        )

        self.store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield defer.ensureDeferred(
                self.state.compute_event_context(event)
            )
            self.store.register_event_context(event, context)
            context_store[event.event_id] = context

        # C ends up winning the resolution between C and D because bans win over other
        # changes

        ctx_c = context_store["C"]
        ctx_e = context_store["E"]

        prev_state_ids = yield defer.ensureDeferred(ctx_e.get_prev_state_ids())
        self.assertSetEqual({"START", "A", "B", "C"}, set(prev_state_ids.values()))
        self.assertEqual(ctx_c.state_group, ctx_e.state_group_before_event)
        self.assertEqual(ctx_e.state_group_before_event, ctx_e.state_group)

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
                    "users": {userid1: 100, userid2: 60},
                },
            ),
            "A5": DictObj(type=EventTypes.Name, state_key=""),
            "B": DictObj(
                type=EventTypes.PowerLevels,
                state_key="",
                content={"events": {"m.room.name": 50}, "users": {userid2: 30}},
            ),
            "C": DictObj(type=EventTypes.Name, state_key="", sender=userid2),
            "D": DictObj(type=EventTypes.Message),
        }
        edges = {
            "A2": ["A1"],
            "A3": ["A2"],
            "A4": ["A3"],
            "A5": ["A4"],
            "B": ["A5"],
            "C": ["A5"],
            "D": ["B", "C"],
        }
        self._add_depths(nodes, edges)
        graph = Graph(nodes, edges)

        self.store.register_events(graph.walk())

        context_store = {}

        for event in graph.walk():
            context = yield defer.ensureDeferred(
                self.state.compute_event_context(event)
            )
            self.store.register_event_context(event, context)
            context_store[event.event_id] = context

        # B ends up winning the resolution between B and C because power levels
        # win over other changes.

        ctx_b = context_store["B"]
        ctx_d = context_store["D"]

        prev_state_ids = yield defer.ensureDeferred(ctx_d.get_prev_state_ids())
        self.assertSetEqual({"A1", "A2", "A3", "A5", "B"}, set(prev_state_ids.values()))

        self.assertEqual(ctx_b.state_group, ctx_d.state_group_before_event)
        self.assertEqual(ctx_d.state_group_before_event, ctx_d.state_group)

    def _add_depths(self, nodes, edges):
        def _get_depth(ev):
            node = nodes[ev]
            if "depth" not in node:
                prevs = edges[ev]
                depth = max(_get_depth(prev) for prev in prevs) + 1
                node["depth"] = depth
            return node["depth"]

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

        context = yield defer.ensureDeferred(
            self.state.compute_event_context(event, old_state=old_state)
        )

        prev_state_ids = yield defer.ensureDeferred(context.get_prev_state_ids())
        self.assertCountEqual((e.event_id for e in old_state), prev_state_ids.values())

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())
        self.assertCountEqual(
            (e.event_id for e in old_state), current_state_ids.values()
        )

        self.assertIsNotNone(context.state_group_before_event)
        self.assertEqual(context.state_group_before_event, context.state_group)

    @defer.inlineCallbacks
    def test_annotate_with_old_state(self):
        event = create_event(type="state", state_key="", name="event")

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        context = yield defer.ensureDeferred(
            self.state.compute_event_context(event, old_state=old_state)
        )

        prev_state_ids = yield defer.ensureDeferred(context.get_prev_state_ids())
        self.assertCountEqual((e.event_id for e in old_state), prev_state_ids.values())

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())
        self.assertCountEqual(
            (e.event_id for e in old_state + [event]), current_state_ids.values()
        )

        self.assertIsNotNone(context.state_group_before_event)
        self.assertNotEqual(context.state_group_before_event, context.state_group)
        self.assertEqual(context.state_group_before_event, context.prev_group)
        self.assertEqual({("state", ""): event.event_id}, context.delta_ids)

    @defer.inlineCallbacks
    def test_trivial_annotate_message(self):
        prev_event_id = "prev_event_id"
        event = create_event(
            type="test_message", name="event2", prev_events=[(prev_event_id, {})]
        )

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        group_name = yield defer.ensureDeferred(
            self.store.store_state_group(
                prev_event_id,
                event.room_id,
                None,
                None,
                {(e.type, e.state_key): e.event_id for e in old_state},
            )
        )
        self.store.register_event_id_state_group(prev_event_id, group_name)

        context = yield defer.ensureDeferred(self.state.compute_event_context(event))

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())

        self.assertEqual(
            {e.event_id for e in old_state}, set(current_state_ids.values())
        )

        self.assertEqual(group_name, context.state_group)

    @defer.inlineCallbacks
    def test_trivial_annotate_state(self):
        prev_event_id = "prev_event_id"
        event = create_event(
            type="state", state_key="", name="event2", prev_events=[(prev_event_id, {})]
        )

        old_state = [
            create_event(type="test1", state_key="1"),
            create_event(type="test1", state_key="2"),
            create_event(type="test2", state_key=""),
        ]

        group_name = yield defer.ensureDeferred(
            self.store.store_state_group(
                prev_event_id,
                event.room_id,
                None,
                None,
                {(e.type, e.state_key): e.event_id for e in old_state},
            )
        )
        self.store.register_event_id_state_group(prev_event_id, group_name)

        context = yield defer.ensureDeferred(self.state.compute_event_context(event))

        prev_state_ids = yield defer.ensureDeferred(context.get_prev_state_ids())

        self.assertEqual({e.event_id for e in old_state}, set(prev_state_ids.values()))

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_resolve_message_conflict(self):
        prev_event_id1 = "event_id1"
        prev_event_id2 = "event_id2"
        event = create_event(
            type="test_message",
            name="event3",
            prev_events=[(prev_event_id1, {}), (prev_event_id2, {})],
        )

        creation = create_event(type=EventTypes.Create, state_key="")

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

        self.store.register_events(old_state_1)
        self.store.register_events(old_state_2)

        context = yield self._get_context(
            event, prev_event_id1, old_state_1, prev_event_id2, old_state_2
        )

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())

        self.assertEqual(len(current_state_ids), 6)

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_resolve_state_conflict(self):
        prev_event_id1 = "event_id1"
        prev_event_id2 = "event_id2"
        event = create_event(
            type="test4",
            state_key="",
            name="event",
            prev_events=[(prev_event_id1, {}), (prev_event_id2, {})],
        )

        creation = create_event(type=EventTypes.Create, state_key="")

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

        context = yield self._get_context(
            event, prev_event_id1, old_state_1, prev_event_id2, old_state_2
        )

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())

        self.assertEqual(len(current_state_ids), 6)

        self.assertIsNotNone(context.state_group)

    @defer.inlineCallbacks
    def test_standard_depth_conflict(self):
        prev_event_id1 = "event_id1"
        prev_event_id2 = "event_id2"
        event = create_event(
            type="test4",
            name="event",
            prev_events=[(prev_event_id1, {}), (prev_event_id2, {})],
        )

        member_event = create_event(
            type=EventTypes.Member,
            state_key="@user_id:example.com",
            content={"membership": Membership.JOIN},
        )

        power_levels = create_event(
            type=EventTypes.PowerLevels,
            state_key="",
            content={"users": {"@foo:bar": "100", "@user_id:example.com": "100"}},
        )

        creation = create_event(
            type=EventTypes.Create, state_key="", content={"creator": "@foo:bar"}
        )

        old_state_1 = [
            creation,
            power_levels,
            member_event,
            create_event(type="test1", state_key="1", depth=1),
        ]

        old_state_2 = [
            creation,
            power_levels,
            member_event,
            create_event(type="test1", state_key="1", depth=2),
        ]

        store = StateGroupStore()
        store.register_events(old_state_1)
        store.register_events(old_state_2)
        self.store.get_events = store.get_events

        context = yield self._get_context(
            event, prev_event_id1, old_state_1, prev_event_id2, old_state_2
        )

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())

        self.assertEqual(old_state_2[3].event_id, current_state_ids[("test1", "1")])

        # Reverse the depth to make sure we are actually using the depths
        # during state resolution.

        old_state_1 = [
            creation,
            power_levels,
            member_event,
            create_event(type="test1", state_key="1", depth=2),
        ]

        old_state_2 = [
            creation,
            power_levels,
            member_event,
            create_event(type="test1", state_key="1", depth=1),
        ]

        store.register_events(old_state_1)
        store.register_events(old_state_2)

        context = yield self._get_context(
            event, prev_event_id1, old_state_1, prev_event_id2, old_state_2
        )

        current_state_ids = yield defer.ensureDeferred(context.get_current_state_ids())

        self.assertEqual(old_state_1[3].event_id, current_state_ids[("test1", "1")])

    @defer.inlineCallbacks
    def _get_context(
        self, event, prev_event_id_1, old_state_1, prev_event_id_2, old_state_2
    ):
        sg1 = yield defer.ensureDeferred(
            self.store.store_state_group(
                prev_event_id_1,
                event.room_id,
                None,
                None,
                {(e.type, e.state_key): e.event_id for e in old_state_1},
            )
        )
        self.store.register_event_id_state_group(prev_event_id_1, sg1)

        sg2 = yield defer.ensureDeferred(
            self.store.store_state_group(
                prev_event_id_2,
                event.room_id,
                None,
                None,
                {(e.type, e.state_key): e.event_id for e in old_state_2},
            )
        )
        self.store.register_event_id_state_group(prev_event_id_2, sg2)

        result = yield defer.ensureDeferred(self.state.compute_event_context(event))
        return result
