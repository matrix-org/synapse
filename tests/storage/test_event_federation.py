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
        room_id = '@ROOM:local'

        # add a bunch of events and hashes to act as forward extremities
        def insert_event(txn, i):
            event_id = '$event_%i:local' % i

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
                    'INSERT INTO event_forward_extremities (room_id, event_id) '
                    'VALUES (?, ?)'
                ),
                (room_id, event_id),
            )

            txn.execute(
                (
                    'INSERT INTO event_reference_hashes '
                    '(event_id, algorithm, hash) '
                    "VALUES (?, 'sha256', ?)"
                ),
                (event_id, b'ffff'),
            )

        for i in range(0, 11):
            yield self.store.runInteraction("insert", insert_event, i)

        # this should get the last five and five others
        r = yield self.store.get_prev_events_for_room(room_id)
        self.assertEqual(10, len(r))
        for i in range(0, 5):
            el = r[i]
            depth = el[2]
            self.assertEqual(10 - i, depth)

        for i in range(5, 5):
            el = r[i]
            depth = el[2]
            self.assertLessEqual(5, depth)
