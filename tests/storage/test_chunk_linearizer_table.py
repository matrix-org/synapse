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

from twisted.internet import defer

import random
import tests.unittest
import tests.utils

from synapse.storage.chunk_ordered_table import ChunkDBOrderedListStore


class ChunkLinearizerStoreTestCase(tests.unittest.TestCase):
    """Tests to ensure that the ordering and rebalancing functions of
    ChunkDBOrderedListStore work as expected.
    """

    def __init__(self, *args, **kwargs):
        super(ChunkLinearizerStoreTestCase, self).__init__(*args, **kwargs)

    @defer.inlineCallbacks
    def setUp(self):
        hs = yield tests.utils.setup_test_homeserver()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def test_simple_insert_fetch(self):
        room_id = "foo_room1"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock, 1, 100,
            )

            table.add_node("A")
            table.insert_after("B", "A")
            table.insert_before("C", "A")

            sql = """
                SELECT chunk_id FROM chunk_linearized
                WHERE room_id = ?
                ORDER BY ordering ASC
            """
            txn.execute(sql, (room_id,))

            ordered = [r for r, in txn]

            self.assertEqual(["C", "A", "B"], ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_many_insert_fetch(self):
        room_id = "foo_room2"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock, 1, 20,
            )

            nodes = [(i, "node_%d" % (i,)) for i in xrange(1, 1000)]
            expected = [n for _, n in nodes]

            already_inserted = []

            random.shuffle(nodes)
            while nodes:
                i, node_id = nodes.pop()
                if not already_inserted:
                    table.add_node(node_id)
                else:
                    for j, target_id in already_inserted:
                        if j > i:
                            break

                    if j < i:
                        table.insert_after(node_id, target_id)
                    else:
                        table.insert_before(node_id, target_id)

                already_inserted.append((i, node_id))
                already_inserted.sort()

            sql = """
                SELECT chunk_id FROM chunk_linearized
                WHERE room_id = ?
                ORDER BY ordering ASC
            """
            txn.execute(sql, (room_id,))

            ordered = [r for r, in txn]

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_prepend_and_append(self):
        room_id = "foo_room3"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock, 1, 20,
            )

            table.add_node("a")

            expected = ["a"]

            for i in xrange(1, 1000):
                node_id = "node_id_before_%d" % i
                table.insert_before(node_id, expected[0])
                expected.insert(0, node_id)

            for i in xrange(1, 1000):
                node_id = "node_id_after_%d" % i
                table.insert_after(node_id, expected[-1])
                expected.append(node_id)

            sql = """
                SELECT chunk_id FROM chunk_linearized
                WHERE room_id = ?
                ORDER BY ordering ASC
            """
            txn.execute(sql, (room_id,))

            ordered = [r for r, in txn]

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_worst_case(self):
        room_id = "foo_room3"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock, 1, 100,
            )

            table.add_node("a")

            prev_node = "a"

            expected_prefix = ["a"]
            expected_suffix = []

            for i in xrange(1, 100):
                node_id = "node_id_%d" % i
                if i % 2 == 0:
                    table.insert_before(node_id, prev_node)
                    expected_prefix.append(node_id)
                else:
                    table.insert_after(node_id, prev_node)
                    expected_suffix.append(node_id)
                prev_node = node_id

            sql = """
                SELECT chunk_id FROM chunk_linearized
                WHERE room_id = ?
                ORDER BY ordering ASC
            """
            txn.execute(sql, (room_id,))

            ordered = [r for r, in txn]

            expected = expected_prefix + list(reversed(expected_suffix))

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)
