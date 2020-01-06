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

from twisted.internet import defer

import tests.unittest
import tests.utils


class EventFederationWorkerStoreTestCase(tests.unittest.TestCase):
    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver(self.addCleanup)
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
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
            yield self.store.db.runInteraction("insert", insert_event, i)

        # this should get the last ten
        r = yield self.store.get_prev_events_for_room(room_id)
        self.assertEqual(10, len(r))
        for i in range(0, 10):
            self.assertEqual("$event_%i:local" % (19 - i), r[i])

    @defer.inlineCallbacks
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
            yield self.store.db.runInteraction("insert", insert_event, i, room1)
            yield self.store.db.runInteraction("insert", insert_event, i, room2)
            yield self.store.db.runInteraction("insert", insert_event, i, room3)

        # Test simple case
        r = yield self.store.get_rooms_with_many_extremities(5, 5, [])
        self.assertEqual(len(r), 3)

        # Does filter work?

        r = yield self.store.get_rooms_with_many_extremities(5, 5, [room1])
        self.assertTrue(room2 in r)
        self.assertTrue(room3 in r)
        self.assertEqual(len(r), 2)

        r = yield self.store.get_rooms_with_many_extremities(5, 5, [room1, room2])
        self.assertEqual(r, [room3])

        # Does filter and limit work?

        r = yield self.store.get_rooms_with_many_extremities(5, 1, [room1])
        self.assertTrue(r == [room2] or r == [room3])
