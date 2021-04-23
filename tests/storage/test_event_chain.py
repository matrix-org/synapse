# Copyright 2020 The Matrix.org Foundation C.I.C.
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

from typing import Dict, List, Set, Tuple

from twisted.trial import unittest

from synapse.api.constants import EventTypes
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.rest import admin
from synapse.rest.client.v1 import login, room
from synapse.storage.databases.main.events import _LinkMap
from synapse.types import create_requester

from tests.unittest import HomeserverTestCase


class EventChainStoreTestCase(HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self._next_stream_ordering = 1

    def test_simple(self):
        """Test that the example in `docs/auth_chain_difference_algorithm.md`
        works.
        """

        event_factory = self.hs.get_event_builder_factory()
        bob = "@creator:test"
        alice = "@alice:test"
        room_id = "!room:test"

        # Ensure that we have a rooms entry so that we generate the chain index.
        self.get_success(
            self.store.store_room(
                room_id=room_id,
                room_creator_user_id="",
                is_public=True,
                room_version=RoomVersions.V6,
            )
        )

        create = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Create,
                    "state_key": "",
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "create"},
                },
            ).build(prev_event_ids=[], auth_event_ids=[])
        )

        bob_join = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": bob,
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "bob_join"},
                },
            ).build(prev_event_ids=[], auth_event_ids=[create.event_id])
        )

        power = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.PowerLevels,
                    "state_key": "",
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "power"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id],
            )
        )

        alice_invite = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "alice_invite"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id, power.event_id],
            )
        )

        alice_join = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": alice,
                    "room_id": room_id,
                    "content": {"tag": "alice_join"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, alice_invite.event_id, power.event_id],
            )
        )

        power_2 = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.PowerLevels,
                    "state_key": "",
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "power_2"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id, power.event_id],
            )
        )

        bob_join_2 = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": bob,
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "bob_join_2"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id, power.event_id],
            )
        )

        alice_join2 = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": alice,
                    "room_id": room_id,
                    "content": {"tag": "alice_join2"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[
                    create.event_id,
                    alice_join.event_id,
                    power_2.event_id,
                ],
            )
        )

        events = [
            create,
            bob_join,
            power,
            alice_invite,
            alice_join,
            bob_join_2,
            power_2,
            alice_join2,
        ]

        expected_links = [
            (bob_join, create),
            (power, create),
            (power, bob_join),
            (alice_invite, create),
            (alice_invite, power),
            (alice_invite, bob_join),
            (bob_join_2, power),
            (alice_join2, power_2),
        ]

        self.persist(events)
        chain_map, link_map = self.fetch_chains(events)

        # Check that the expected links and only the expected links have been
        # added.
        self.assertEqual(len(expected_links), len(list(link_map.get_additions())))

        for start, end in expected_links:
            start_id, start_seq = chain_map[start.event_id]
            end_id, end_seq = chain_map[end.event_id]

            self.assertIn(
                (start_seq, end_seq), list(link_map.get_links_between(start_id, end_id))
            )

        # Test that everything can reach the create event, but the create event
        # can't reach anything.
        for event in events[1:]:
            self.assertTrue(
                link_map.exists_path_from(
                    chain_map[event.event_id], chain_map[create.event_id]
                ),
            )

            self.assertFalse(
                link_map.exists_path_from(
                    chain_map[create.event_id],
                    chain_map[event.event_id],
                ),
            )

    def test_out_of_order_events(self):
        """Test that we handle persisting events that we don't have the full
        auth chain for yet (which should only happen for out of band memberships).
        """
        event_factory = self.hs.get_event_builder_factory()
        bob = "@creator:test"
        alice = "@alice:test"
        room_id = "!room:test"

        # Ensure that we have a rooms entry so that we generate the chain index.
        self.get_success(
            self.store.store_room(
                room_id=room_id,
                room_creator_user_id="",
                is_public=True,
                room_version=RoomVersions.V6,
            )
        )

        # First persist the base room.
        create = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Create,
                    "state_key": "",
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "create"},
                },
            ).build(prev_event_ids=[], auth_event_ids=[])
        )

        bob_join = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": bob,
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "bob_join"},
                },
            ).build(prev_event_ids=[], auth_event_ids=[create.event_id])
        )

        power = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.PowerLevels,
                    "state_key": "",
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "power"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id],
            )
        )

        self.persist([create, bob_join, power])

        # Now persist an invite and a couple of memberships out of order.
        alice_invite = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": bob,
                    "room_id": room_id,
                    "content": {"tag": "alice_invite"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, bob_join.event_id, power.event_id],
            )
        )

        alice_join = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": alice,
                    "room_id": room_id,
                    "content": {"tag": "alice_join"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, alice_invite.event_id, power.event_id],
            )
        )

        alice_join2 = self.get_success(
            event_factory.for_room_version(
                RoomVersions.V6,
                {
                    "type": EventTypes.Member,
                    "state_key": alice,
                    "sender": alice,
                    "room_id": room_id,
                    "content": {"tag": "alice_join2"},
                },
            ).build(
                prev_event_ids=[],
                auth_event_ids=[create.event_id, alice_join.event_id, power.event_id],
            )
        )

        self.persist([alice_join])
        self.persist([alice_join2])
        self.persist([alice_invite])

        # The end result should be sane.
        events = [create, bob_join, power, alice_invite, alice_join]

        chain_map, link_map = self.fetch_chains(events)

        expected_links = [
            (bob_join, create),
            (power, create),
            (power, bob_join),
            (alice_invite, create),
            (alice_invite, power),
            (alice_invite, bob_join),
        ]

        # Check that the expected links and only the expected links have been
        # added.
        self.assertEqual(len(expected_links), len(list(link_map.get_additions())))

        for start, end in expected_links:
            start_id, start_seq = chain_map[start.event_id]
            end_id, end_seq = chain_map[end.event_id]

            self.assertIn(
                (start_seq, end_seq), list(link_map.get_links_between(start_id, end_id))
            )

    def persist(
        self,
        events: List[EventBase],
    ):
        """Persist the given events and check that the links generated match
        those given.
        """

        persist_events_store = self.hs.get_datastores().persist_events

        for e in events:
            e.internal_metadata.stream_ordering = self._next_stream_ordering
            self._next_stream_ordering += 1

        def _persist(txn):
            # We need to persist the events to the events and state_events
            # tables.
            persist_events_store._store_event_txn(txn, [(e, {}) for e in events])

            # Actually call the function that calculates the auth chain stuff.
            persist_events_store._persist_event_auth_chain_txn(txn, events)

        self.get_success(
            persist_events_store.db_pool.runInteraction(
                "_persist",
                _persist,
            )
        )

    def fetch_chains(
        self, events: List[EventBase]
    ) -> Tuple[Dict[str, Tuple[int, int]], _LinkMap]:

        # Fetch the map from event ID -> (chain ID, sequence number)
        rows = self.get_success(
            self.store.db_pool.simple_select_many_batch(
                table="event_auth_chains",
                column="event_id",
                iterable=[e.event_id for e in events],
                retcols=("event_id", "chain_id", "sequence_number"),
                keyvalues={},
            )
        )

        chain_map = {
            row["event_id"]: (row["chain_id"], row["sequence_number"]) for row in rows
        }

        # Fetch all the links and pass them to the _LinkMap.
        rows = self.get_success(
            self.store.db_pool.simple_select_many_batch(
                table="event_auth_chain_links",
                column="origin_chain_id",
                iterable=[chain_id for chain_id, _ in chain_map.values()],
                retcols=(
                    "origin_chain_id",
                    "origin_sequence_number",
                    "target_chain_id",
                    "target_sequence_number",
                ),
                keyvalues={},
            )
        )

        link_map = _LinkMap()
        for row in rows:
            added = link_map.add_link(
                (row["origin_chain_id"], row["origin_sequence_number"]),
                (row["target_chain_id"], row["target_sequence_number"]),
            )

            # We shouldn't have persisted any redundant links
            self.assertTrue(added)

        return chain_map, link_map


class LinkMapTestCase(unittest.TestCase):
    def test_simple(self):
        """Basic tests for the LinkMap."""
        link_map = _LinkMap()

        link_map.add_link((1, 1), (2, 1), new=False)
        self.assertCountEqual(link_map.get_links_between(1, 2), [(1, 1)])
        self.assertCountEqual(link_map.get_links_from((1, 1)), [(2, 1)])
        self.assertCountEqual(link_map.get_additions(), [])
        self.assertTrue(link_map.exists_path_from((1, 5), (2, 1)))
        self.assertFalse(link_map.exists_path_from((1, 5), (2, 2)))
        self.assertTrue(link_map.exists_path_from((1, 5), (1, 1)))
        self.assertFalse(link_map.exists_path_from((1, 1), (1, 5)))

        # Attempting to add a redundant link is ignored.
        self.assertFalse(link_map.add_link((1, 4), (2, 1)))
        self.assertCountEqual(link_map.get_links_between(1, 2), [(1, 1)])

        # Adding new non-redundant links works
        self.assertTrue(link_map.add_link((1, 3), (2, 3)))
        self.assertCountEqual(link_map.get_links_between(1, 2), [(1, 1), (3, 3)])

        self.assertTrue(link_map.add_link((2, 5), (1, 3)))
        self.assertCountEqual(link_map.get_links_between(2, 1), [(5, 3)])
        self.assertCountEqual(link_map.get_links_between(1, 2), [(1, 1), (3, 3)])

        self.assertCountEqual(link_map.get_additions(), [(1, 3, 2, 3), (2, 5, 1, 3)])


class EventChainBackgroundUpdateTestCase(HomeserverTestCase):

    servlets = [
        admin.register_servlets,
        room.register_servlets,
        login.register_servlets,
    ]

    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()
        self.user_id = self.register_user("foo", "pass")
        self.token = self.login("foo", "pass")
        self.requester = create_requester(self.user_id)

    def _generate_room(self) -> Tuple[str, List[Set[str]]]:
        """Insert a room without a chain cover index."""
        room_id = self.helper.create_room_as(self.user_id, tok=self.token)

        # Mark the room as not having a chain cover index
        self.get_success(
            self.store.db_pool.simple_update(
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"has_auth_chain_index": False},
                desc="test",
            )
        )

        # Create a fork in the DAG with different events.
        event_handler = self.hs.get_event_creation_handler()
        latest_event_ids = self.get_success(
            self.store.get_prev_events_for_room(room_id)
        )
        event, context = self.get_success(
            event_handler.create_event(
                self.requester,
                {
                    "type": "some_state_type",
                    "state_key": "",
                    "content": {},
                    "room_id": room_id,
                    "sender": self.user_id,
                },
                prev_event_ids=latest_event_ids,
            )
        )
        self.get_success(
            event_handler.handle_new_client_event(self.requester, event, context)
        )
        state1 = set(self.get_success(context.get_current_state_ids()).values())

        event, context = self.get_success(
            event_handler.create_event(
                self.requester,
                {
                    "type": "some_state_type",
                    "state_key": "",
                    "content": {},
                    "room_id": room_id,
                    "sender": self.user_id,
                },
                prev_event_ids=latest_event_ids,
            )
        )
        self.get_success(
            event_handler.handle_new_client_event(self.requester, event, context)
        )
        state2 = set(self.get_success(context.get_current_state_ids()).values())

        # Delete the chain cover info.

        def _delete_tables(txn):
            txn.execute("DELETE FROM event_auth_chains")
            txn.execute("DELETE FROM event_auth_chain_links")

        self.get_success(self.store.db_pool.runInteraction("test", _delete_tables))

        return room_id, [state1, state2]

    def test_background_update_single_room(self):
        """Test that the background update to calculate auth chains for historic
        rooms works correctly.
        """

        # Create a room
        room_id, states = self._generate_room()

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {"update_name": "chain_cover", "progress_json": "{}"},
            )
        )

        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        # Test that the `has_auth_chain_index` has been set
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id)))

        # Test that calculating the auth chain difference using the newly
        # calculated chain cover works.
        self.get_success(
            self.store.db_pool.runInteraction(
                "test",
                self.store._get_auth_chain_difference_using_cover_index_txn,
                room_id,
                states,
            )
        )

    def test_background_update_multiple_rooms(self):
        """Test that the background update to calculate auth chains for historic
        rooms works correctly.
        """
        # Create a room
        room_id1, states1 = self._generate_room()
        room_id2, states2 = self._generate_room()
        room_id3, states2 = self._generate_room()

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {"update_name": "chain_cover", "progress_json": "{}"},
            )
        )

        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        # Test that the `has_auth_chain_index` has been set
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id1)))
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id2)))
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id3)))

        # Test that calculating the auth chain difference using the newly
        # calculated chain cover works.
        self.get_success(
            self.store.db_pool.runInteraction(
                "test",
                self.store._get_auth_chain_difference_using_cover_index_txn,
                room_id1,
                states1,
            )
        )

    def test_background_update_single_large_room(self):
        """Test that the background update to calculate auth chains for historic
        rooms works correctly.
        """

        # Create a room
        room_id, states = self._generate_room()

        # Add a bunch of state so that it takes multiple iterations of the
        # background update to process the room.
        for i in range(0, 150):
            self.helper.send_state(
                room_id, event_type="m.test", body={"index": i}, tok=self.token
            )

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {"update_name": "chain_cover", "progress_json": "{}"},
            )
        )

        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        iterations = 0
        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            iterations += 1
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        # Ensure that we did actually take multiple iterations to process the
        # room.
        self.assertGreater(iterations, 1)

        # Test that the `has_auth_chain_index` has been set
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id)))

        # Test that calculating the auth chain difference using the newly
        # calculated chain cover works.
        self.get_success(
            self.store.db_pool.runInteraction(
                "test",
                self.store._get_auth_chain_difference_using_cover_index_txn,
                room_id,
                states,
            )
        )

    def test_background_update_multiple_large_room(self):
        """Test that the background update to calculate auth chains for historic
        rooms works correctly.
        """

        # Create the rooms
        room_id1, _ = self._generate_room()
        room_id2, _ = self._generate_room()

        # Add a bunch of state so that it takes multiple iterations of the
        # background update to process the room.
        for i in range(0, 150):
            self.helper.send_state(
                room_id1, event_type="m.test", body={"index": i}, tok=self.token
            )

        for i in range(0, 150):
            self.helper.send_state(
                room_id2, event_type="m.test", body={"index": i}, tok=self.token
            )

        # Insert and run the background update.
        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                {"update_name": "chain_cover", "progress_json": "{}"},
            )
        )

        # Ugh, have to reset this flag
        self.store.db_pool.updates._all_done = False

        iterations = 0
        while not self.get_success(
            self.store.db_pool.updates.has_completed_background_updates()
        ):
            iterations += 1
            self.get_success(
                self.store.db_pool.updates.do_next_background_update(100), by=0.1
            )

        # Ensure that we did actually take multiple iterations to process the
        # room.
        self.assertGreater(iterations, 1)

        # Test that the `has_auth_chain_index` has been set
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id1)))
        self.assertTrue(self.get_success(self.store.has_auth_chain_index(room_id2)))
