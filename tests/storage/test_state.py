# Copyright 2018-2021 The Matrix.org Foundation C.I.C.
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

import logging
from typing import List, Tuple, cast

from immutabledict import immutabledict

from twisted.test.proto_helpers import MemoryReactor

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.server import HomeServer
from synapse.types import JsonDict, RoomID, StateMap, UserID
from synapse.types.state import StateFilter
from synapse.util import Clock

from tests.unittest import HomeserverTestCase

logger = logging.getLogger(__name__)


class StateStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main
        self.storage = hs.get_storage_controllers()
        self.state_datastore = self.storage.state.stores.state
        self.event_builder_factory = hs.get_event_builder_factory()
        self.event_creation_handler = hs.get_event_creation_handler()

        self.u_alice = UserID.from_string("@alice:test")
        self.u_bob = UserID.from_string("@bob:test")

        self.room = RoomID.from_string("!abc123:test")

        self.get_success(
            self.store.store_room(
                self.room.to_string(),
                room_creator_user_id="@creator:text",
                is_public=True,
                room_version=RoomVersions.V1,
            )
        )

    def inject_state_event(
        self, room: RoomID, sender: UserID, typ: str, state_key: str, content: JsonDict
    ) -> EventBase:
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": typ,
                "sender": sender.to_string(),
                "state_key": state_key,
                "room_id": room.to_string(),
                "content": content,
            },
        )

        event, unpersisted_context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )

        context = self.get_success(unpersisted_context.persist(event))

        assert self.storage.persistence is not None
        self.get_success(self.storage.persistence.persist_event(event, context))

        return event

    def assertStateMapEqual(
        self, s1: StateMap[EventBase], s2: StateMap[EventBase]
    ) -> None:
        for t in s1:
            # just compare event IDs for simplicity
            self.assertEqual(s1[t].event_id, s2[t].event_id)
        self.assertEqual(len(s1), len(s2))

    def test_get_state_groups_ids(self) -> None:
        e1 = self.inject_state_event(self.room, self.u_alice, EventTypes.Create, "", {})
        e2 = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, "", {"name": "test room"}
        )

        state_group_map = self.get_success(
            self.storage.state.get_state_groups_ids(
                self.room.to_string(), [e2.event_id]
            )
        )
        self.assertEqual(len(state_group_map), 1)
        state_map = list(state_group_map.values())[0]
        self.assertDictEqual(
            state_map,
            {(EventTypes.Create, ""): e1.event_id, (EventTypes.Name, ""): e2.event_id},
        )

    def test_get_state_groups(self) -> None:
        e1 = self.inject_state_event(self.room, self.u_alice, EventTypes.Create, "", {})
        e2 = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, "", {"name": "test room"}
        )

        state_group_map = self.get_success(
            self.storage.state.get_state_groups(self.room.to_string(), [e2.event_id])
        )
        self.assertEqual(len(state_group_map), 1)
        state_list = list(state_group_map.values())[0]

        self.assertEqual({ev.event_id for ev in state_list}, {e1.event_id, e2.event_id})

    def test_get_state_for_event(self) -> None:
        # this defaults to a linear DAG as each new injection defaults to whatever
        # forward extremities are currently in the DB for this room.
        e1 = self.inject_state_event(self.room, self.u_alice, EventTypes.Create, "", {})
        e2 = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, "", {"name": "test room"}
        )
        e3 = self.inject_state_event(
            self.room,
            self.u_alice,
            EventTypes.Member,
            self.u_alice.to_string(),
            {"membership": Membership.JOIN},
        )
        e4 = self.inject_state_event(
            self.room,
            self.u_bob,
            EventTypes.Member,
            self.u_bob.to_string(),
            {"membership": Membership.JOIN},
        )
        e5 = self.inject_state_event(
            self.room,
            self.u_bob,
            EventTypes.Member,
            self.u_bob.to_string(),
            {"membership": Membership.LEAVE},
        )

        # check we get the full state as of the final event
        state = self.get_success(self.storage.state.get_state_for_event(e5.event_id))

        self.assertIsNotNone(e4)

        self.assertStateMapEqual(
            {
                (e1.type, e1.state_key): e1,
                (e2.type, e2.state_key): e2,
                (e3.type, e3.state_key): e3,
                # e4 is overwritten by e5
                (e5.type, e5.state_key): e5,
            },
            state,
        )

        # check we can filter to the m.room.name event (with a '' state key)
        state = self.get_success(
            self.storage.state.get_state_for_event(
                e5.event_id, StateFilter.from_types([(EventTypes.Name, "")])
            )
        )

        self.assertStateMapEqual({(e2.type, e2.state_key): e2}, state)

        # check we can filter to the m.room.name event (with a wildcard None state key)
        state = self.get_success(
            self.storage.state.get_state_for_event(
                e5.event_id, StateFilter.from_types([(EventTypes.Name, None)])
            )
        )

        self.assertStateMapEqual({(e2.type, e2.state_key): e2}, state)

        # check we can grab the m.room.member events (with a wildcard None state key)
        state = self.get_success(
            self.storage.state.get_state_for_event(
                e5.event_id, StateFilter.from_types([(EventTypes.Member, None)])
            )
        )

        self.assertStateMapEqual(
            {(e3.type, e3.state_key): e3, (e5.type, e5.state_key): e5}, state
        )

        # check we can grab a specific room member without filtering out the
        # other event types
        state = self.get_success(
            self.storage.state.get_state_for_event(
                e5.event_id,
                state_filter=StateFilter(
                    types=immutabledict(
                        {EventTypes.Member: frozenset({self.u_alice.to_string()})}
                    ),
                    include_others=True,
                ),
            )
        )

        self.assertStateMapEqual(
            {
                (e1.type, e1.state_key): e1,
                (e2.type, e2.state_key): e2,
                (e3.type, e3.state_key): e3,
            },
            state,
        )

        # check that we can grab everything except members
        state = self.get_success(
            self.storage.state.get_state_for_event(
                e5.event_id,
                state_filter=StateFilter(
                    types=immutabledict({EventTypes.Member: frozenset()}),
                    include_others=True,
                ),
            )
        )

        self.assertStateMapEqual(
            {(e1.type, e1.state_key): e1, (e2.type, e2.state_key): e2}, state
        )

        #######################################################
        # _get_state_for_group_using_cache tests against a full cache
        #######################################################

        room_id = self.room.to_string()
        group_ids = self.get_success(
            self.storage.state.get_state_groups_ids(room_id, [e5.event_id])
        )
        group = list(group_ids.keys())[0]

        # test _get_state_for_group_using_cache correctly filters out members
        # with types=[]
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset()}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual(
            {
                (e1.type, e1.state_key): e1.event_id,
                (e2.type, e2.state_key): e2.event_id,
            },
            state_dict,
        )

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset()}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with wildcard types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: None}), include_others=True
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual(
            {
                (e1.type, e1.state_key): e1.event_id,
                (e2.type, e2.state_key): e2.event_id,
            },
            state_dict,
        )

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: None}), include_others=True
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual(
            {
                (e3.type, e3.state_key): e3.event_id,
                # e4 is overwritten by e5
                (e5.type, e5.state_key): e5.event_id,
            },
            state_dict,
        )

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual(
            {
                (e1.type, e1.state_key): e1.event_id,
                (e2.type, e2.state_key): e2.event_id,
            },
            state_dict,
        )

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=False,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

        #######################################################
        # deliberately remove e2 (room name) from the _state_group_cache

        cache_entry = self.state_datastore._state_group_cache.get(group)
        state_dict_ids = cache_entry.value

        self.assertEqual(cache_entry.full, True)
        self.assertEqual(cache_entry.known_absent, set())
        self.assertDictEqual(
            state_dict_ids,
            {
                (e1.type, e1.state_key): e1.event_id,
                (e2.type, e2.state_key): e2.event_id,
            },
        )

        state_dict_ids.pop((e2.type, e2.state_key))
        self.state_datastore._state_group_cache.invalidate(group)
        self.state_datastore._state_group_cache.update(
            sequence=self.state_datastore._state_group_cache.sequence,
            key=group,
            value=state_dict_ids,
            # list fetched keys so it knows it's partial
            fetched_keys=((e1.type, e1.state_key),),
        )

        cache_entry = self.state_datastore._state_group_cache.get(group)
        state_dict_ids = cache_entry.value

        self.assertEqual(cache_entry.full, False)
        self.assertEqual(cache_entry.known_absent, set())
        self.assertDictEqual(state_dict_ids, {})

        ############################################
        # test that things work with a partial cache

        # test _get_state_for_group_using_cache correctly filters out members
        # with types=[]
        room_id = self.room.to_string()
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset()}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        room_id = self.room.to_string()
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset()}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # wildcard types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: None}), include_others=True
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: None}), include_others=True
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual(
            {
                (e3.type, e3.state_key): e3.event_id,
                (e5.type, e5.state_key): e5.event_id,
            },
            state_dict,
        )

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=False,
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        state_dict, is_all = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=immutabledict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=False,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

    def test_batched_state_group_storing(self) -> None:
        creation_event = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Create, "", {}
        )
        state_to_event = self.get_success(
            self.storage.state.get_state_groups(
                self.room.to_string(), [creation_event.event_id]
            )
        )
        current_state_group = list(state_to_event.keys())[0]

        # create some unpersisted events and event contexts to store against room
        events_and_context = []
        builder = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": EventTypes.Name,
                "sender": self.u_alice.to_string(),
                "state_key": "",
                "room_id": self.room.to_string(),
                "content": {"name": "first rename of room"},
            },
        )

        event1, unpersisted_context1 = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )
        events_and_context.append((event1, unpersisted_context1))

        builder2 = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": EventTypes.JoinRules,
                "sender": self.u_alice.to_string(),
                "state_key": "",
                "room_id": self.room.to_string(),
                "content": {"join_rule": "private"},
            },
        )

        event2, unpersisted_context2 = self.get_success(
            self.event_creation_handler.create_new_client_event(builder2)
        )
        events_and_context.append((event2, unpersisted_context2))

        builder3 = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": EventTypes.Message,
                "sender": self.u_alice.to_string(),
                "room_id": self.room.to_string(),
                "content": {"body": "hello from event 3", "msgtype": "m.text"},
            },
        )

        event3, unpersisted_context3 = self.get_success(
            self.event_creation_handler.create_new_client_event(builder3)
        )
        events_and_context.append((event3, unpersisted_context3))

        builder4 = self.event_builder_factory.for_room_version(
            RoomVersions.V1,
            {
                "type": EventTypes.JoinRules,
                "sender": self.u_alice.to_string(),
                "state_key": "",
                "room_id": self.room.to_string(),
                "content": {"join_rule": "public"},
            },
        )

        event4, unpersisted_context4 = self.get_success(
            self.event_creation_handler.create_new_client_event(builder4)
        )
        events_and_context.append((event4, unpersisted_context4))

        processed_events_and_context = self.get_success(
            self.hs.get_datastores().state.store_state_deltas_for_batched(
                events_and_context, self.room.to_string(), current_state_group
            )
        )

        # check that only state events are in state_groups, and all state events are in state_groups
        res = cast(
            List[Tuple[str]],
            self.get_success(
                self.store.db_pool.simple_select_list(
                    table="state_groups",
                    keyvalues=None,
                    retcols=("event_id",),
                )
            ),
        )

        events = []
        for result in res:
            self.assertNotIn(event3.event_id, result)  # XXX
            events.append(result[0])

        for event, _ in processed_events_and_context:
            if event.is_state():
                self.assertIn(event.event_id, events)

        # check that each unique state has state group in state_groups_state and that the
        # type/state key is correct, and check that each state event's state group
        # has an entry and prev event in state_group_edges
        for event, context in processed_events_and_context:
            if event.is_state():
                state = cast(
                    List[Tuple[str, str]],
                    self.get_success(
                        self.store.db_pool.simple_select_list(
                            table="state_groups_state",
                            keyvalues={"state_group": context.state_group_after_event},
                            retcols=("type", "state_key"),
                        )
                    ),
                )
                self.assertEqual(event.type, state[0][0])
                self.assertEqual(event.state_key, state[0][1])

                groups = cast(
                    List[Tuple[str]],
                    self.get_success(
                        self.store.db_pool.simple_select_list(
                            table="state_group_edges",
                            keyvalues={
                                "state_group": str(context.state_group_after_event)
                            },
                            retcols=("prev_state_group",),
                        )
                    ),
                )
                self.assertEqual(context.state_group_before_event, groups[0][0])
