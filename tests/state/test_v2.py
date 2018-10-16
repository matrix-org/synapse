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

import itertools

import networkx

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.event_auth import auth_types_for_event
from synapse.events import FrozenEvent
from synapse.state.v2 import resolve_events_with_factory
from synapse.types import EventID

from tests import unittest

ALICE = "@alice:example.com"
BOB = "@bob:example.com"
CHARLIE = "@charlie:example.com"
EVELYN = "@evelyn:example.com"
ZARA = "@zara:example.com"

ROOM_ID = "!test:example.com"

MEMBERSHIP_CONTENT_JOIN = {"membership": Membership.JOIN}
MEMBERSHIP_CONTENT_BAN = {"membership": Membership.BAN}


ORIGIN_SERVER_TS = 0


class FakeEvent(object):
    """A fake event we use as a convenience.

    NOTE: Again as a convenience we use "node_ids" rather than event_ids to
    refer to events. The event_id has node_id as localpart and example.com
    as domain.
    """
    def __init__(self, id, sender, type, state_key, content):
        self.node_id = id
        self.event_id = EventID(id, "example.com").to_string()
        self.sender = sender
        self.type = type
        self.state_key = state_key
        self.content = content

    def to_event(self, auth_events, prev_events):
        """Given the auth_events and prev_events, convert to a Frozen Event

        Args:
            auth_events (list[str]): list of event_ids
            prev_events (list[str]): list of event_ids

        Returns:
            FrozenEvent
        """
        global ORIGIN_SERVER_TS

        ts = ORIGIN_SERVER_TS
        ORIGIN_SERVER_TS = ORIGIN_SERVER_TS + 1

        event_dict = {
            "auth_events": [(a, {}) for a in auth_events],
            "prev_events": [(p, {}) for p in prev_events],
            "event_id": self.node_id,
            "sender": self.sender,
            "type": self.type,
            "content": self.content,
            "origin_server_ts": ts,
            "room_id": ROOM_ID,
        }

        if self.state_key is not None:
            event_dict["state_key"] = self.state_key

        return FrozenEvent(event_dict)


# All graphs start with this set of events
INITIAL_EVENTS = [
    FakeEvent(
        id="CREATE",
        sender=ALICE,
        type=EventTypes.Create,
        state_key="",
        content={"creator": ALICE},
    ),
    FakeEvent(
        id="IMA",
        sender=ALICE,
        type=EventTypes.Member,
        state_key=ALICE,
        content=MEMBERSHIP_CONTENT_JOIN,
    ),
    FakeEvent(
        id="IPOWER",
        sender=ALICE,
        type=EventTypes.PowerLevels,
        state_key="",
        content={"users": {ALICE: 100}},
    ),
    FakeEvent(
        id="IJR",
        sender=ALICE,
        type=EventTypes.JoinRules,
        state_key="",
        content={"join_rule": JoinRules.PUBLIC},
    ),
    FakeEvent(
        id="IMB",
        sender=BOB,
        type=EventTypes.Member,
        state_key=BOB,
        content=MEMBERSHIP_CONTENT_JOIN,
    ),
    FakeEvent(
        id="IMC",
        sender=CHARLIE,
        type=EventTypes.Member,
        state_key=CHARLIE,
        content=MEMBERSHIP_CONTENT_JOIN,
    ),
    FakeEvent(
        id="IMZ",
        sender=ZARA,
        type=EventTypes.Member,
        state_key=ZARA,
        content=MEMBERSHIP_CONTENT_JOIN,
    ),
    FakeEvent(
        id="START",
        sender=ZARA,
        type=EventTypes.Message,
        state_key=None,
        content={},
    ),
    FakeEvent(
        id="END",
        sender=ZARA,
        type=EventTypes.Message,
        state_key=None,
        content={},
    ),
]

INITIAL_EDGES = [
    "START", "IMZ", "IMC", "IMB", "IJR", "IPOWER", "IMA", "CREATE",
]


class StateTestCase(unittest.TestCase):
    def test_ban_vs_pl(self):
        events = [
            FakeEvent(
                id="PA",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    }
                },
            ),
            FakeEvent(
                id="MA",
                sender=ALICE,
                type=EventTypes.Member,
                state_key=ALICE,
                content={"membership": Membership.JOIN},
            ),
            FakeEvent(
                id="MB",
                sender=ALICE,
                type=EventTypes.Member,
                state_key=BOB,
                content={"membership": Membership.BAN},
            ),
            FakeEvent(
                id="PB",
                sender=BOB,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
        ]

        edges = [
            ["END", "MB", "MA", "PA", "START"],
            ["END", "PB", "PA"],
        ]

        expected_state_ids = ["PA", "MA", "MB"]

        self.do_check(events, edges, expected_state_ids)

    def test_join_rule_evasion(self):
        events = [
            FakeEvent(
                id="JR",
                sender=ALICE,
                type=EventTypes.JoinRules,
                state_key="",
                content={"join_rules": JoinRules.PRIVATE},
            ),
            FakeEvent(
                id="ME",
                sender=EVELYN,
                type=EventTypes.Member,
                state_key=EVELYN,
                content={"membership": Membership.JOIN},
            ),
        ]

        edges = [
            ["END", "JR", "START"],
            ["END", "ME", "START"],
        ]

        expected_state_ids = ["JR"]

        self.do_check(events, edges, expected_state_ids)

    def test_offtopic_pl(self):
        events = [
            FakeEvent(
                id="PA",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key="",
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    }
                },
            ),
            FakeEvent(
                id="PB",
                sender=BOB,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                        CHARLIE: 50,
                    },
                },
            ),
            FakeEvent(
                id="PC",
                sender=CHARLIE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                        CHARLIE: 0,
                    },
                },
            ),
        ]

        edges = [
            ["END", "PC", "PB", "PA", "START"],
            ["END", "PA"],
        ]

        expected_state_ids = ["PC"]

        self.do_check(events, edges, expected_state_ids)

    def test_topic_basic(self):
        events = [
            FakeEvent(
                id="T1",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="PA1",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
            FakeEvent(
                id="T2",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="PA2",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 0,
                    },
                },
            ),
            FakeEvent(
                id="PB",
                sender=BOB,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
            FakeEvent(
                id="T3",
                sender=BOB,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
        ]

        edges = [
            ["END", "PA2", "T2", "PA1", "T1", "START"],
            ["END", "T3", "PB", "PA1"],
        ]

        expected_state_ids = ["PA2", "T2"]

        self.do_check(events, edges, expected_state_ids)

    def test_topic_reset(self):
        events = [
            FakeEvent(
                id="T1",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="PA",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
            FakeEvent(
                id="T2",
                sender=BOB,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="MB",
                sender=ALICE,
                type=EventTypes.Member,
                state_key=BOB,
                content={"membership": Membership.BAN},
            ),
        ]

        edges = [
            ["END", "MB", "T2", "PA", "T1", "START"],
            ["END", "T1"],
        ]

        expected_state_ids = ["T1", "MB", "PA"]

        self.do_check(events, edges, expected_state_ids)

    def test_topic(self):
        events = [
            FakeEvent(
                id="T1",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="PA1",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
            FakeEvent(
                id="T2",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="PA2",
                sender=ALICE,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 0,
                    },
                },
            ),
            FakeEvent(
                id="PB",
                sender=BOB,
                type=EventTypes.PowerLevels,
                state_key='',
                content={
                    "users": {
                        ALICE: 100,
                        BOB: 50,
                    },
                },
            ),
            FakeEvent(
                id="T3",
                sender=BOB,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
            FakeEvent(
                id="MZ1",
                sender=ZARA,
                type=EventTypes.Message,
                state_key=None,
                content={},
            ),
            FakeEvent(
                id="T4",
                sender=ALICE,
                type=EventTypes.Topic,
                state_key="",
                content={},
            ),
        ]

        edges = [
            ["END", "T4", "MZ1", "PA2", "T2", "PA1", "T1", "START"],
            ["END", "MZ1", "T3", "PB", "PA1"],
        ]

        expected_state_ids = ["T4", "PA2"]

        self.do_check(events, edges, expected_state_ids)

    def do_check(self, events, edges, expected_state_ids):
        """Take a list of events and edges and calculate the state of the
        graph at END, and asserts it matches `expected_state_ids`

        Args:
            events (list[FakeEvent])
            edges (list[list[str]]): A list of chains of event edges, e.g.
                `[[A, B, C]]` are edges A->B and B->C.
            expected_state_ids (list[str]): The expected state at END, (excluding
                the keys that haven't changed since START).
        """
        graph = networkx.DiGraph()

        # node_id -> FakeEvent
        fake_event_map = {}

        for ev in itertools.chain(INITIAL_EVENTS, events):
            graph.add_node(ev.node_id)
            fake_event_map[ev.node_id] = ev

        graph.add_edges_from(pairwise(INITIAL_EDGES))
        for edge_list in edges:
            graph.add_edges_from(pairwise(edge_list))

        # event_id -> FrozenEvent
        event_map = {}
        # node_id -> state
        state_at_event = {}

        for node_id in reversed(list(networkx.topological_sort(graph))):
            fake_event = fake_event_map[node_id]
            event_id = fake_event.event_id

            prev_events = list(graph[node_id])

            if len(prev_events) == 0:
                state_before = {}
            elif len(prev_events) == 1:
                state_before = dict(state_at_event[prev_events[0]])
            else:
                state_d = resolve_events_with_factory(
                    [state_at_event[n] for n in prev_events],
                    event_map=event_map,
                    state_map_factory=None,
                )

                self.assertTrue(state_d.called)
                state_before = state_d.result

            state_after = dict(state_before)
            if fake_event.state_key is not None:
                state_after[(fake_event.type, fake_event.state_key)] = event_id

            auth_types = set(auth_types_for_event(fake_event))

            auth_events = []
            for key in auth_types:
                if key in state_before:
                    auth_events.append(state_before[key])

            event = fake_event.to_event(auth_events, prev_events)

            state_at_event[node_id] = state_after
            event_map[event_id] = event

        expected_state = {}
        for node_id in expected_state_ids:
            # expected_state_ids are node IDs rather than event IDs,
            # so we have to convert
            event_id = EventID(node_id, "example.com").to_string()
            event = event_map[event_id]

            key = (event.type, event.state_key)

            expected_state[key] = event_id

        start_state = state_at_event["START"]
        end_state = {
            key: value
            for key, value in state_at_event["END"].items()
            if key in expected_state or start_state.get(key) != value
        }

        self.assertEqual(expected_state, end_state)


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return itertools.izip(a, b)
