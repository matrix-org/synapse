# -*- coding: utf-8 -*-
# Copyright 2018 New Vector Ltd
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

import attr
from parameterized import parameterized

from synapse.events import _EventInternalMetadata

import tests.unittest
import tests.utils


class EventFederationWorkerStoreTestCase(tests.unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.store = hs.get_datastore()

    def test_get_prev_events_for_room(self):
        room_id = "@ROOM:local"

        # add a bunch of events and hashes to act as forward extremities
        def insert_event(txn, i):
            event_id = "$event_%i:local" % i

            txn.execute(
                (
                    "INSERT INTO events ("
                    "   room_id, event_id, type, depth, topological_ordering,"
                    "   content, processed, outlier, stream_ordering) "
                    "VALUES (?, ?, 'm.test', ?, ?, 'test', ?, ?, ?)"
                ),
                (room_id, event_id, i, i, True, False, i),
            )

            txn.execute(
                (
                    "INSERT INTO event_forward_extremities (room_id, event_id) "
                    "VALUES (?, ?)"
                ),
                (room_id, event_id),
            )

            txn.execute(
                (
                    "INSERT INTO event_reference_hashes "
                    "(event_id, algorithm, hash) "
                    "VALUES (?, 'sha256', ?)"
                ),
                (event_id, bytearray(b"ffff")),
            )

        for i in range(0, 20):
            self.get_success(
                self.store.db_pool.runInteraction("insert", insert_event, i)
            )

        # this should get the last ten
        r = self.get_success(self.store.get_prev_events_for_room(room_id))
        self.assertEqual(10, len(r))
        for i in range(0, 10):
            self.assertEqual("$event_%i:local" % (19 - i), r[i])

    def test_get_rooms_with_many_extremities(self):
        room1 = "#room1"
        room2 = "#room2"
        room3 = "#room3"

        def insert_event(txn, i, room_id):
            event_id = "$event_%i:local" % i
            txn.execute(
                (
                    "INSERT INTO event_forward_extremities (room_id, event_id) "
                    "VALUES (?, ?)"
                ),
                (room_id, event_id),
            )

        for i in range(0, 20):
            self.get_success(
                self.store.db_pool.runInteraction("insert", insert_event, i, room1)
            )
            self.get_success(
                self.store.db_pool.runInteraction("insert", insert_event, i, room2)
            )
            self.get_success(
                self.store.db_pool.runInteraction("insert", insert_event, i, room3)
            )

        # Test simple case
        r = self.get_success(self.store.get_rooms_with_many_extremities(5, 5, []))
        self.assertEqual(len(r), 3)

        # Does filter work?

        r = self.get_success(self.store.get_rooms_with_many_extremities(5, 5, [room1]))
        self.assertTrue(room2 in r)
        self.assertTrue(room3 in r)
        self.assertEqual(len(r), 2)

        r = self.get_success(
            self.store.get_rooms_with_many_extremities(5, 5, [room1, room2])
        )
        self.assertEqual(r, [room3])

        # Does filter and limit work?

        r = self.get_success(self.store.get_rooms_with_many_extremities(5, 1, [room1]))
        self.assertTrue(r == [room2] or r == [room3])

    @parameterized.expand([(True,), (False,)])
    def test_auth_difference(self, use_chain_cover_index: bool):
        room_id = "@ROOM:local"

        # The silly auth graph we use to test the auth difference algorithm,
        # where the top are the most recent events.
        #
        #   A   B
        #    \ /
        #  D  E
        #  \  |
        #   ` F   C
        #     |  /|
        #     G ´ |
        #     | \ |
        #     H   I
        #     |   |
        #     K   J

        auth_graph = {
            "a": ["e"],
            "b": ["e"],
            "c": ["g", "i"],
            "d": ["f"],
            "e": ["f"],
            "f": ["g"],
            "g": ["h", "i"],
            "h": ["k"],
            "i": ["j"],
            "k": [],
            "j": [],
        }

        depth_map = {
            "a": 7,
            "b": 7,
            "c": 4,
            "d": 6,
            "e": 6,
            "f": 5,
            "g": 3,
            "h": 2,
            "i": 2,
            "k": 1,
            "j": 1,
        }

        # Mark the room as not having a cover index

        def store_room(txn):
            self.store.db_pool.simple_insert_txn(
                txn,
                "rooms",
                {
                    "room_id": room_id,
                    "creator": "room_creator_user_id",
                    "is_public": True,
                    "room_version": "6",
                    "has_auth_chain_index": use_chain_cover_index,
                },
            )

        self.get_success(self.store.db_pool.runInteraction("store_room", store_room))

        # We rudely fiddle with the appropriate tables directly, as that's much
        # easier than constructing events properly.

        def insert_event(txn):
            stream_ordering = 0

            for event_id in auth_graph:
                stream_ordering += 1
                depth = depth_map[event_id]

                self.store.db_pool.simple_insert_txn(
                    txn,
                    table="events",
                    values={
                        "event_id": event_id,
                        "room_id": room_id,
                        "depth": depth,
                        "topological_ordering": depth,
                        "type": "m.test",
                        "processed": True,
                        "outlier": False,
                        "stream_ordering": stream_ordering,
                    },
                )

            self.hs.datastores.persist_events._persist_event_auth_chain_txn(
                txn,
                [
                    FakeEvent(event_id, room_id, auth_graph[event_id])
                    for event_id in auth_graph
                ],
            )

        self.get_success(self.store.db_pool.runInteraction("insert", insert_event,))

        # Now actually test that various combinations give the right result:

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"c"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c", "e", "f"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a", "c"}, {"b"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a", "c"}, {"b", "c"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"d"}])
        )
        self.assertSetEqual(difference, {"a", "b", "d", "e"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"c"}, {"d"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c", "d", "e", "f"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"e"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}])
        )
        self.assertSetEqual(difference, set())

    def test_auth_difference_partial_cover(self):
        """Test that we correctly handle rooms where not all events have a chain
        cover calculated. This can happen due to a downgrade/upgrade.
        """

        room_id = "@ROOM:local"

        # The silly auth graph we use to test the auth difference algorithm,
        # where the top are the most recent events.
        #
        #   A   B
        #    \ /
        #  D  E
        #  \  |
        #   ` F   C
        #     |  /|
        #     G ´ |
        #     | \ |
        #     H   I
        #     |   |
        #     K   J

        auth_graph = {
            "a": ["e"],
            "b": ["e"],
            "c": ["g", "i"],
            "d": ["f"],
            "e": ["f"],
            "f": ["g"],
            "g": ["h", "i"],
            "h": ["k"],
            "i": ["j"],
            "k": [],
            "j": [],
        }

        depth_map = {
            "a": 7,
            "b": 7,
            "c": 4,
            "d": 6,
            "e": 6,
            "f": 5,
            "g": 3,
            "h": 2,
            "i": 2,
            "k": 1,
            "j": 1,
        }

        # We rudely fiddle with the appropriate tables directly, as that's much
        # easier than constructing events properly.

        def insert_event(txn):
            # First insert the room and mark it has having a chain cover.
            self.store.db_pool.simple_insert_txn(
                txn,
                "rooms",
                {
                    "room_id": room_id,
                    "creator": "room_creator_user_id",
                    "is_public": True,
                    "room_version": "6",
                    "has_auth_chain_index": True,
                },
            )

            stream_ordering = 0

            for event_id in auth_graph:
                stream_ordering += 1
                depth = depth_map[event_id]

                self.store.db_pool.simple_insert_txn(
                    txn,
                    table="events",
                    values={
                        "event_id": event_id,
                        "room_id": room_id,
                        "depth": depth,
                        "topological_ordering": depth,
                        "type": "m.test",
                        "processed": True,
                        "outlier": False,
                        "stream_ordering": stream_ordering,
                    },
                )

            # Insert all events apart from 'B'
            self.hs.datastores.persist_events._persist_event_auth_chain_txn(
                txn,
                [
                    FakeEvent(event_id, room_id, auth_graph[event_id])
                    for event_id in auth_graph
                    if event_id != "b"
                ],
            )

            # Now we insert the event 'B' without a chain cover, by temporarily
            # pretending the room doesn't have a chain cover.

            self.store.db_pool.simple_update_txn(
                txn,
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"has_auth_chain_index": False},
            )

            self.hs.datastores.persist_events._persist_event_auth_chain_txn(
                txn, [FakeEvent("b", room_id, auth_graph["b"])],
            )

            self.store.db_pool.simple_update_txn(
                txn,
                table="rooms",
                keyvalues={"room_id": room_id},
                updatevalues={"has_auth_chain_index": True},
            )

        self.get_success(self.store.db_pool.runInteraction("insert", insert_event,))

        # Now actually test that various combinations give the right result:

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"c"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c", "e", "f"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a", "c"}, {"b"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a", "c"}, {"b", "c"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"d"}])
        )
        self.assertSetEqual(difference, {"a", "b", "d", "e"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"c"}, {"d"}])
        )
        self.assertSetEqual(difference, {"a", "b", "c", "d", "e", "f"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}, {"b"}, {"e"}])
        )
        self.assertSetEqual(difference, {"a", "b"})

        difference = self.get_success(
            self.store.get_auth_chain_difference(room_id, [{"a"}])
        )
        self.assertSetEqual(difference, set())


@attr.s
class FakeEvent:
    event_id = attr.ib()
    room_id = attr.ib()
    auth_events = attr.ib()

    type = "foo"
    state_key = "foo"

    internal_metadata = _EventInternalMetadata({})

    def auth_event_ids(self):
        return self.auth_events

    def is_state(self):
        return True
