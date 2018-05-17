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

import math
import logging

from synapse.storage._base import SQLBaseStore
from synapse.util.katriel_bodlaender import OrderedListStore
from synapse.util.metrics import Measure

import synapse.metrics

metrics = synapse.metrics.get_metrics_for(__name__)
rebalance_counter = metrics.register_counter("rebalances")


logger = logging.getLogger(__name__)


class ChunkDBOrderedListStore(OrderedListStore):
    """Used as the list store for room chunks, efficiently maintaining them in
    topological order on updates.

    A room chunk is a connected portion of the room events DAG. As such it
    inherits a DAG, i.e. if an event in one chunk references an event in a
    second chunk, then we say that the first chunk references the second, and
    thus forming a DAG.

    The class is designed for use inside transactions and so takes a
    transaction object in the constructor. This means that it needs to be
    re-instantiated in each transaction, so all state needs to be stored
    in the database.

    Internally the ordering is implemented using floats, and the average is
    taken when a node is inserted between other nodes. To avoid precision
    errors a minimum difference between sucessive orderings is attempted to be
    kept; whenever the difference is too small we attempt to rebalance. See
    the `_rebalance` function for implementation details.

    Note that OrderedListStore orders nodes such that source of an edge
    comes before the target. This is counter intuitive when edges represent
    causality, so for the purposes of ordering algorithm we invert the edge
    directions, i.e. if chunk A has a prev chunk of B then we say that the
    edge is from B to A. This ensures that newer chunks get inserted at the
    end (rather than the start).

    Note: Calls to `add_node` and `add_edge` cannot overlap for the same room,
    and so callers should perform some form of per-room locking when using
    this class.

    Args:
        txn
        room_id (str)
        clock
        rebalance_digits (int): When a rebalance is triggered we rebalance
            in a range around the node, where the bounds are rounded to this
            number of digits.
        min_difference (int): A rebalance is triggered when the difference
            between two successive orderings is less than the reciprocal of
            this.
    """
    def __init__(self,
                 txn, room_id, clock,
                 rebalance_digits=3,
                 min_difference=1000000):
        self.txn = txn
        self.room_id = room_id
        self.clock = clock

        self.rebalance_digits = rebalance_digits
        self.min_difference = 1. / min_difference

    def is_before(self, a, b):
        """Implements OrderedListStore"""
        return self._get_order(a) < self._get_order(b)

    def get_prev(self, node_id):
        """Implements OrderedListStore"""
        order = self._get_order(node_id)

        sql = """
            SELECT chunk_id FROM chunk_linearized
            WHERE ordering < ? AND room_id = ?
            ORDER BY ordering DESC
            LIMIT 1
        """

        self.txn.execute(sql, (order, self.room_id,))

        row = self.txn.fetchone()
        if row:
            return row[0]
        return None

    def get_next(self, node_id):
        """Implements OrderedListStore"""
        order = self._get_order(node_id)

        sql = """
            SELECT chunk_id FROM chunk_linearized
            WHERE ordering > ? AND room_id = ?
            ORDER BY ordering ASC
            LIMIT 1
        """

        self.txn.execute(sql, (order, self.room_id,))

        row = self.txn.fetchone()
        if row:
            return row[0]
        return None

    def insert_before(self, node_id, target_id):
        """Implements OrderedListStore"""

        rebalance = False  # Set to true if we need to trigger a rebalance

        if target_id:
            target_order = self._get_order(target_id)
            before_id = self.get_prev(target_id)

            if before_id:
                before_order = self._get_order(before_id)
                new_order = (target_order + before_order) / 2.

                rebalance = math.fabs(target_order - before_order) < self.min_difference
            else:
                new_order = math.floor(target_order) - 1
        else:
            # If target_id is None then we insert at the end.
            self.txn.execute("""
                SELECT COALESCE(MAX(ordering), 0) + 1
                FROM chunk_linearized
                WHERE room_id = ?
            """, (self.room_id,))

            new_order, = self.txn.fetchone()

        self._insert(node_id, new_order)

        if rebalance:
            self._rebalance(node_id)

    def insert_after(self, node_id, target_id):
        """Implements OrderedListStore"""

        rebalance = False  # Set to true if we need to trigger a rebalance

        if target_id:
            target_order = self._get_order(target_id)
            after_id = self.get_next(target_id)
            if after_id:
                after_order = self._get_order(after_id)
                new_order = (target_order + after_order) / 2.

                rebalance = math.fabs(target_order - after_order) < self.min_difference
            else:
                new_order = math.ceil(target_order) + 1
        else:
            # If target_id is None then we insert at the start.
            self.txn.execute("""
                SELECT COALESCE(MIN(ordering), 0) - 1
                FROM chunk_linearized
                WHERE room_id = ?
            """, (self.room_id,))

            new_order, = self.txn.fetchone()

        self._insert(node_id, new_order)

        if rebalance:
            self._rebalance(node_id)

    def get_nodes_with_edges_to(self, node_id):
        """Implements OrderedListStore"""

        # Note that we use the inverse relation here
        sql = """
            SELECT l.ordering, l.chunk_id FROM chunk_graph AS g
            INNER JOIN chunk_linearized AS l ON g.prev_id = l.chunk_id
            WHERE g.chunk_id = ?
        """
        self.txn.execute(sql, (node_id,))
        return self.txn.fetchall()

    def get_nodes_with_edges_from(self, node_id):
        """Implements OrderedListStore"""

        # Note that we use the inverse relation here
        sql = """
            SELECT l.ordering, l.chunk_id FROM chunk_graph AS g
            INNER JOIN chunk_linearized AS l ON g.chunk_id = l.chunk_id
            WHERE g.prev_id = ?
        """
        self.txn.execute(sql, (node_id,))
        return self.txn.fetchall()

    def _delete_ordering(self, node_id):
        """Implements OrderedListStore"""

        SQLBaseStore._simple_delete_txn(
            self.txn,
            table="chunk_linearized",
            keyvalues={"chunk_id": node_id},
        )

    def _add_edge_to_graph(self, source_id, target_id):
        """Implements OrderedListStore"""

        # Note that we use the inverse relation
        SQLBaseStore._simple_insert_txn(
            self.txn,
            table="chunk_graph",
            values={"chunk_id": target_id, "prev_id": source_id}
        )

    def _insert(self, node_id, order):
        """Inserts the node with the given ordering.
        """
        SQLBaseStore._simple_insert_txn(
            self.txn,
            table="chunk_linearized",
            values={
                "chunk_id": node_id,
                "room_id": self.room_id,
                "ordering": order,
            }
        )

    def _get_order(self, node_id):
        """Get the ordering of the given node.
        """

        return SQLBaseStore._simple_select_one_onecol_txn(
            self.txn,
            table="chunk_linearized",
            keyvalues={"chunk_id": node_id},
            retcol="ordering"
        )

    def _rebalance(self, node_id):
        """Rebalances the list around the given node to ensure that the
        ordering floats don't get too small.

        This works by finding a range that includes the given node, and
        recalculating the ordering floats such that they're equidistant in
        that range.
        """

        logger.info("Rebalancing room %s, chunk %s", self.room_id, node_id)

        with Measure(self.clock, "chunk_rebalance"):
            # We pick the interval to try and minimise the number of decimal
            # places, i.e. we round to nearest float with `rebalance_digits` and
            # use that as the middle of the interval
            order = self._get_order(node_id)
            a = round(order, self.rebalance_digits)
            if order > a:
                min_order = a
                max_order = a + 10 ** -self.rebalance_digits
            else:
                min_order = a - 10 ** -self.rebalance_digits
                max_order = a

            # Now we get all the nodes in the range. We add the minimum difference
            # to the bounds to ensure that we don't accidentally move a node to be
            # within the minimum difference of a node outside the range.
            sql = """
                SELECT chunk_id FROM chunk_linearized
                WHERE ordering >= ? AND ordering <= ? AND room_id = ?
            """
            self.txn.execute(sql, (
                min_order - self.min_difference,
                max_order + self.min_difference,
                self.room_id,
            ))

            chunk_ids = [c for c, in self.txn]

            sql = """
                UPDATE chunk_linearized
                SET ordering = ?
                WHERE chunk_id = ?
            """

            step = (max_order - min_order) / len(chunk_ids)
            self.txn.executemany(
                sql,
                (
                    ((idx * step + min_order), chunk_id)
                    for idx, chunk_id in enumerate(chunk_ids)
                )
            )

            rebalance_counter.inc()
