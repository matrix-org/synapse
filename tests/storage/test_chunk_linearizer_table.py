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

import itertools
import random
import tests.unittest
import tests.utils

from fractions import Fraction

from synapse.storage.chunk_ordered_table import (
    ChunkDBOrderedListStore, find_farey_terms, get_fraction_in_range,
)


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
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 100,
            )

            table.add_node("A")
            table._insert_after("B", "A")
            table._insert_before("C", "A")
            table._insert_after("D", "A")

            sql = """
                SELECT chunk_id, numerator, denominator FROM chunk_linearized
                WHERE room_id = ?
            """
            txn.execute(sql, (room_id,))

            ordered = sorted([(Fraction(n, d), r) for r, n, d in txn])
            ordered = [c for _, c in ordered]

            self.assertEqual(["C", "A", "D", "B"], ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_many_insert_fetch(self):
        room_id = "foo_room2"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 100,
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
                        table._insert_after(node_id, target_id)
                    else:
                        table._insert_before(node_id, target_id)

                already_inserted.append((i, node_id))
                already_inserted.sort()

            sql = """
                SELECT chunk_id, numerator, denominator FROM chunk_linearized
                WHERE room_id = ?
            """
            txn.execute(sql, (room_id,))

            ordered = sorted([(Fraction(n, d), r) for r, n, d in txn])
            ordered = [c for _, c in ordered]

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_prepend_and_append(self):
        room_id = "foo_room3"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 1000,
            )

            table.add_node("a")

            expected = ["a"]

            for i in xrange(1, 1000):
                node_id = "node_id_before_%d" % i
                table._insert_before(node_id, expected[0])
                expected.insert(0, node_id)

            for i in xrange(1, 1000):
                node_id = "node_id_after_%d" % i
                table._insert_after(node_id, expected[-1])
                expected.append(node_id)

            sql = """
                SELECT chunk_id, numerator, denominator FROM chunk_linearized
                WHERE room_id = ?
            """
            txn.execute(sql, (room_id,))

            ordered = sorted([(Fraction(n, d), r) for r, n, d in txn])
            ordered = [c for _, c in ordered]

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_worst_case(self):
        room_id = "foo_room3"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 100,
            )

            table.add_node("a")

            prev_node = "a"

            expected_prefix = ["a"]
            expected_suffix = []

            for i in xrange(1, 100):
                node_id = "node_id_%d" % i
                if i % 2 == 0:
                    table._insert_before(node_id, prev_node)
                    expected_prefix.append(node_id)
                else:
                    table._insert_after(node_id, prev_node)
                    expected_suffix.append(node_id)
                prev_node = node_id

            sql = """
                SELECT chunk_id, numerator, denominator FROM chunk_linearized
                WHERE room_id = ?
            """
            txn.execute(sql, (room_id,))

            ordered = sorted([(Fraction(n, d), r) for r, n, d in txn])
            ordered = [c for _, c in ordered]

            expected = expected_prefix + list(reversed(expected_suffix))

            self.assertEqual(expected, ordered)

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_get_edges_to(self):
        room_id = "foo_room4"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 100,
            )

            table.add_node("A")
            table._insert_after("B", "A")
            table._add_edge_to_graph("A", "B")
            table._insert_before("C", "A")
            table._add_edge_to_graph("C", "A")

            nodes = table.get_nodes_with_edges_from("A")
            self.assertEqual([n for _, n in nodes], ["B"])

            nodes = table.get_nodes_with_edges_to("A")
            self.assertEqual([n for _, n in nodes], ["C"])

        yield self.store.runInteraction("test", test_txn)

    @defer.inlineCallbacks
    def test_get_next_and_prev(self):
        room_id = "foo_room5"

        def test_txn(txn):
            table = ChunkDBOrderedListStore(
                txn, room_id, self.clock,
                self.store.database_engine,
                5, 100,
            )

            table.add_node("A")
            table._insert_after("B", "A")
            table._insert_before("C", "A")

            self.assertEqual(table.get_next("A"), "B")
            self.assertEqual(table.get_prev("A"), "C")

        yield self.store.runInteraction("test", test_txn)

    def test_find_farey_terms(self):
        def _test(min_frac, max_denom):
            """"Calls `find_farey_terms` with given values and checks they
            are neighbours in the Farey Sequence.
            """

            a, b, c, d = find_farey_terms(min_frac, max_denom)

            p = Fraction(a, b)
            q = Fraction(c, d)

            assert min_frac < p < q

            for x, y in _pairwise(_farey_generator(max_denom)):
                if min_frac < x < y:
                    self.assertEqual(x, p)
                    self.assertEqual(y, q)
                    break

        _test(Fraction(5, 3), 12)
        _test(Fraction(1, 3), 12)
        _test(Fraction(1, 2), 9)
        _test(Fraction(1, 2), 10)
        _test(Fraction(1, 2), 15)

    def test_get_fraction_in_range(self):
        def _test(x, y):
            assert x < get_fraction_in_range(x, y) < y

        _test(Fraction(1, 2), Fraction(2, 3))
        _test(Fraction(1, 2), Fraction(3, 2))
        _test(Fraction(5, 203), Fraction(6, 204))


def _farey_generator(n):
    """Generates Farey sequence of order `n`.

    Note that this doesn't terminate.

    Taken from https://en.wikipedia.org/wiki/Farey_sequence#Next_term
    """

    a, b, c, d = 0, 1, 1, n

    yield Fraction(a, b)

    while True:
        k = int((n + b) / d)
        a, b, c, d = c, d, (k * c - a), (k * d - b)
        yield Fraction(a, b)


def _pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = itertools.tee(iterable)
    next(b, None)
    return itertools.izip(a, b)
