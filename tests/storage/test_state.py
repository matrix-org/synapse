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

from frozendict import frozendict

from synapse.api.constants import EventTypes, Membership
from synapse.api.room_versions import RoomVersions
from synapse.storage.state import StateFilter
from synapse.types import RoomID, UserID

from tests.unittest import HomeserverTestCase, TestCase

logger = logging.getLogger(__name__)


class StateStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
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

    def inject_state_event(self, room, sender, typ, state_key, content):
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

        event, context = self.get_success(
            self.event_creation_handler.create_new_client_event(builder)
        )

        self.get_success(self.storage.persistence.persist_event(event, context))

        return event

    def assertStateMapEqual(self, s1, s2):
        for t in s1:
            # just compare event IDs for simplicity
            self.assertEqual(s1[t].event_id, s2[t].event_id)
        self.assertEqual(len(s1), len(s2))

    def test_get_state_groups_ids(self):
        e1 = self.inject_state_event(self.room, self.u_alice, EventTypes.Create, "", {})
        e2 = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, "", {"name": "test room"}
        )

        state_group_map = self.get_success(
            self.storage.state.get_state_groups_ids(self.room, [e2.event_id])
        )
        self.assertEqual(len(state_group_map), 1)
        state_map = list(state_group_map.values())[0]
        self.assertDictEqual(
            state_map,
            {(EventTypes.Create, ""): e1.event_id, (EventTypes.Name, ""): e2.event_id},
        )

    def test_get_state_groups(self):
        e1 = self.inject_state_event(self.room, self.u_alice, EventTypes.Create, "", {})
        e2 = self.inject_state_event(
            self.room, self.u_alice, EventTypes.Name, "", {"name": "test room"}
        )

        state_group_map = self.get_success(
            self.storage.state.get_state_groups(self.room, [e2.event_id])
        )
        self.assertEqual(len(state_group_map), 1)
        state_list = list(state_group_map.values())[0]

        self.assertEqual({ev.event_id for ev in state_list}, {e1.event_id, e2.event_id})

    def test_get_state_for_event(self):
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
                    types=frozendict(
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
                    types=frozendict({EventTypes.Member: frozenset()}),
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
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset()}), include_others=True
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

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset()}), include_others=True
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with wildcard types
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: None}), include_others=True
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

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: None}), include_others=True
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
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
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

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
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
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset()}), include_others=True
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        room_id = self.room.to_string()
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset()}), include_others=True
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # wildcard types
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: None}), include_others=True
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: None}), include_others=True
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
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=True,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)

        # test _get_state_for_group_using_cache correctly filters in members
        # with specific types
        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=False,
            ),
        )

        self.assertEqual(is_all, False)
        self.assertDictEqual({}, state_dict)

        (state_dict, is_all,) = self.state_datastore._get_state_for_group_using_cache(
            self.state_datastore._state_group_members_cache,
            group,
            state_filter=StateFilter(
                types=frozendict({EventTypes.Member: frozenset({e5.state_key})}),
                include_others=False,
            ),
        )

        self.assertEqual(is_all, True)
        self.assertDictEqual({(e5.type, e5.state_key): e5.event_id}, state_dict)


class StateFilterDifferenceTestCase(TestCase):
    def assert_difference(
        self, minuend: StateFilter, subtrahend: StateFilter, expected: StateFilter
    ):
        self.assertEqual(
            minuend.approx_difference(subtrahend),
            expected,
            f"StateFilter difference not correct:\n\n\t{minuend!r}\nminus\n\t{subtrahend!r}\nwas\n\t{minuend.approx_difference(subtrahend)}\nexpected\n\t{expected}",
        )

    def test_state_filter_difference_no_include_other_minus_no_include_other(self):
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), both a and b do not have the
        include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
            StateFilter.freeze({EventTypes.Create: None}, include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:spqr"}},
                include_others=False,
            ),
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.CanonicalAlias: {""}},
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_include_other_minus_no_include_other(self):
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), only a has the include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Create: None,
                    EventTypes.Member: set(),
                    EventTypes.CanonicalAlias: set(),
                },
                include_others=True,
            ),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        # This also shows that the resultant state filter is normalised.
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=True),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.Create: {""},
                },
                include_others=False,
            ),
            StateFilter(types=frozendict(), include_others=True),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter(
                types=frozendict(),
                include_others=True,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.CanonicalAlias: {""},
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
        )

        # (specific state keys) - (specific state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
        )

    def test_state_filter_difference_include_other_minus_include_other(self):
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), both a and b have the include_others
        flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=True,
            ),
            StateFilter(types=frozendict(), include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=True),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=False,
            ),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter(
                types=frozendict(),
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                    EventTypes.Create: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                    EventTypes.Create: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                    EventTypes.Create: {""},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_no_include_other_minus_include_other(self):
        """
        Tests the StateFilter.approx_difference method
        where, in a.approx_difference(b), only b has the include_others flag set.
        """
        # (wildcard on state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.Create: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None, EventTypes.CanonicalAlias: None},
                include_others=True,
            ),
            StateFilter(types=frozendict(), include_others=False),
        )

        # (wildcard on state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:spqr"}},
                include_others=True,
            ),
            StateFilter.freeze({EventTypes.Member: None}, include_others=False),
        )

        # (wildcard on state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # (specific state keys) - (wildcard on state keys):
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=True,
            ),
            StateFilter(
                types=frozendict(),
                include_others=False,
            ),
        )

        # (specific state keys) - (specific state keys)
        # This one is an over-approximation because we can't represent
        # 'all state keys except a few named examples'
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr"},
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@spqr:spqr"},
                },
                include_others=False,
            ),
        )

        # (specific state keys) - (no state keys)
        self.assert_difference(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                    EventTypes.CanonicalAlias: {""},
                },
                include_others=False,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: set(),
                },
                include_others=True,
            ),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:spqr", "@spqr:spqr"},
                },
                include_others=False,
            ),
        )

    def test_state_filter_difference_simple_cases(self):
        """
        Tests some very simple cases of the StateFilter approx_difference,
        that are not explicitly tested by the more in-depth tests.
        """

        self.assert_difference(StateFilter.all(), StateFilter.all(), StateFilter.none())

        self.assert_difference(
            StateFilter.all(),
            StateFilter.none(),
            StateFilter.all(),
        )


class StateFilterTestCase(TestCase):
    def test_return_expanded(self):
        """
        Tests the behaviour of the return_expanded() function that expands
        StateFilters to include more state types (for the sake of cache hit rate).
        """

        self.assertEqual(StateFilter.all().return_expanded(), StateFilter.all())

        self.assertEqual(StateFilter.none().return_expanded(), StateFilter.none())

        # Concrete-only state filters stay the same
        # (Case: mixed filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": {""},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": {""},
                },
                include_others=False,
            ),
        )

        # Concrete-only state filters stay the same
        # (Case: non-member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {"some.other.state.type": {""}}, include_others=False
            ).return_expanded(),
            StateFilter.freeze({"some.other.state.type": {""}}, include_others=False),
        )

        # Concrete-only state filters stay the same
        # (Case: member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                },
                include_others=False,
            ),
        )

        # Wildcard member-only state filters stay the same
        self.assertEqual(
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {EventTypes.Member: None},
                include_others=False,
            ),
        )

        # If there is a wildcard in the non-member portion of the filter,
        # it's expanded to include ALL non-member events.
        # (Case: mixed filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    EventTypes.Member: {"@wombat:test", "@alicia:test"},
                    "some.other.state.type": None,
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze(
                {EventTypes.Member: {"@wombat:test", "@alicia:test"}},
                include_others=True,
            ),
        )

        # If there is a wildcard in the non-member portion of the filter,
        # it's expanded to include ALL non-member events.
        # (Case: non-member-only filter)
        self.assertEqual(
            StateFilter.freeze(
                {
                    "some.other.state.type": None,
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze({EventTypes.Member: set()}, include_others=True),
        )
        self.assertEqual(
            StateFilter.freeze(
                {
                    "some.other.state.type": None,
                    "yet.another.state.type": {"wombat"},
                },
                include_others=False,
            ).return_expanded(),
            StateFilter.freeze({EventTypes.Member: set()}, include_others=True),
        )
