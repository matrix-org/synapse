# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from ._base import SQLBaseStore, Table, JoinHelper

from synapse.util.logutils import log_function

from collections import namedtuple

import logging

logger = logging.getLogger(__name__)


class PduStore(SQLBaseStore):
    """A collection of queries for handling PDUs.
    """

    def get_pdu(self, pdu_id, origin):
        """Given a pdu_id and origin, get a PDU.

        Args:
            txn
            pdu_id (str)
            origin (str)

        Returns:
            PduTuple: If the pdu does not exist in the database, returns None
        """

        return self._db_pool.runInteraction(
            self._get_pdu_tuple, pdu_id, origin
        )

    def _get_pdu_tuple(self, txn, pdu_id, origin):
        res = self._get_pdu_tuples(txn, [(pdu_id, origin)])
        return res[0] if res else None

    def _get_pdu_tuples(self, txn, pdu_id_tuples):
        results = []
        for pdu_id, origin in pdu_id_tuples:
            txn.execute(
                PduEdgesTable.select_statement("pdu_id = ? AND origin = ?"),
                (pdu_id, origin)
            )

            edges = [
                (r.prev_pdu_id, r.prev_origin)
                for r in PduEdgesTable.decode_results(txn.fetchall())
            ]

            query = (
                "SELECT %(fields)s FROM %(pdus)s as p "
                "LEFT JOIN %(state)s as s "
                "ON p.pdu_id = s.pdu_id AND p.origin = s.origin "
                "WHERE p.pdu_id = ? AND p.origin = ? "
            ) % {
                "fields": _pdu_state_joiner.get_fields(
                    PdusTable="p", StatePdusTable="s"),
                "pdus": PdusTable.table_name,
                "state": StatePdusTable.table_name,
            }

            txn.execute(query, (pdu_id, origin))

            row = txn.fetchone()
            if row:
                results.append(PduTuple(PduEntry(*row), edges))

        return results

    def get_current_state_for_context(self, context):
        """Get a list of PDUs that represent the current state for a given
        context

        Args:
            context (str)

        Returns:
            list: A list of PduTuples
        """

        return self._db_pool.runInteraction(
            self._get_current_state_for_context,
            context
        )

    def _get_current_state_for_context(self, txn, context):
        query = (
            "SELECT pdu_id, origin FROM %s WHERE context = ?"
            % CurrentStateTable.table_name
        )

        logger.debug("get_current_state %s, Args=%s", query, context)
        txn.execute(query, (context,))

        res = txn.fetchall()

        logger.debug("get_current_state %d results", len(res))

        return self._get_pdu_tuples(txn, res)

    def persist_pdu(self, prev_pdus, **cols):
        """Inserts a (non-state) PDU into the database.

        Args:
            txn,
            prev_pdus (list)
            **cols: The columns to insert into the PdusTable.
        """
        return self._db_pool.runInteraction(
            self._persist_pdu, prev_pdus, cols
        )

    def _persist_pdu(self, txn, prev_pdus, cols):
        entry = PdusTable.EntryType(
            **{k: cols.get(k, None) for k in PdusTable.fields}
        )

        txn.execute(PdusTable.insert_statement(), entry)

        self._handle_prev_pdus(
            txn, entry.outlier, entry.pdu_id, entry.origin,
            prev_pdus, entry.context
        )

    def mark_pdu_as_processed(self, pdu_id, pdu_origin):
        """Mark a received PDU as processed.

        Args:
            txn
            pdu_id (str)
            pdu_origin (str)
        """

        return self._db_pool.runInteraction(
            self._mark_as_processed, pdu_id, pdu_origin
        )

    def _mark_as_processed(self, txn, pdu_id, pdu_origin):
        txn.execute("UPDATE %s SET have_processed = 1" % PdusTable.table_name)

    def get_all_pdus_from_context(self, context):
        """Get a list of all PDUs for a given context."""
        return self._db_pool.runInteraction(
            self._get_all_pdus_from_context, context,
        )

    def _get_all_pdus_from_context(self, txn, context):
        query = (
            "SELECT pdu_id, origin FROM %s "
            "WHERE context = ?"
        ) % PdusTable.table_name

        txn.execute(query, (context,))

        return self._get_pdu_tuples(txn, txn.fetchall())

    def get_pagination(self, context, pdu_list, limit):
        """Get a list of Pdus for a given topic that occured before (and
        including) the pdus in pdu_list. Return a list of max size `limit`.

        Args:
            txn
            context (str)
            pdu_list (list)
            limit (int)

        Return:
            list: A list of PduTuples
        """
        return self._db_pool.runInteraction(
            self._get_paginate, context, pdu_list, limit
        )

    def _get_paginate(self, txn, context, pdu_list, limit):
        logger.debug(
            "paginate: %s, %s, %s",
            context, repr(pdu_list), limit
        )

        # We seed the pdu_results with the things from the pdu_list.
        pdu_results = pdu_list

        front = pdu_list

        query = (
            "SELECT prev_pdu_id, prev_origin FROM %(edges_table)s "
            "WHERE context = ? AND pdu_id = ? AND origin = ? "
            "LIMIT ?"
        ) % {
            "edges_table": PduEdgesTable.table_name,
        }

        # We iterate through all pdu_ids in `front` to select their previous
        # pdus. These are dumped in `new_front`. We continue until we reach the
        # limit *or* new_front is empty (i.e., we've run out of things to
        # select
        while front and len(pdu_results) < limit:

            new_front = []
            for pdu_id, origin in front:
                logger.debug(
                    "_paginate_interaction: i=%s, o=%s",
                    pdu_id, origin
                )

                txn.execute(
                    query,
                    (context, pdu_id, origin, limit - len(pdu_results))
                )

                for row in txn.fetchall():
                    logger.debug(
                        "_paginate_interaction: got i=%s, o=%s",
                        *row
                    )
                    new_front.append(row)

            front = new_front
            pdu_results += new_front

        # We also want to update the `prev_pdus` attributes before returning.
        return self._get_pdu_tuples(txn, pdu_results)

    def get_min_depth_for_context(self, context):
        """Get the current minimum depth for a context

        Args:
            txn
            context (str)
        """
        return self._db_pool.runInteraction(
            self._get_min_depth_for_context, context
        )

    def _get_min_depth_for_context(self, txn, context):
        return self._get_min_depth_interaction(txn, context)

    def _get_min_depth_interaction(self, txn, context):
        txn.execute(
            "SELECT min_depth FROM %s WHERE context = ?"
            % ContextDepthTable.table_name,
            (context,)
        )

        row = txn.fetchone()

        return row[0] if row else None

    def update_min_depth_for_context(self, context, depth):
        """Update the minimum `depth` of the given context, which is the line
        where we stop paginating backwards on.

        Args:
            context (str)
            depth (int)
        """
        return self._db_pool.runInteraction(
            self._update_min_depth_for_context, context, depth
        )

    def _update_min_depth_for_context(self, txn, context, depth):
        min_depth = self._get_min_depth_interaction(txn, context)

        do_insert = depth < min_depth if min_depth else True

        if do_insert:
            txn.execute(
                "INSERT OR REPLACE INTO %s (context, min_depth) "
                "VALUES (?,?)" % ContextDepthTable.table_name,
                (context, depth)
            )

    def get_latest_pdus_in_context(self, context):
        """Get's a list of the most current pdus for a given context. This is
        used when we are sending a Pdu and need to fill out the `prev_pdus`
        key

        Args:
            txn
            context
        """
        return self._db_pool.runInteraction(
            self._get_latest_pdus_in_context, context
        )

    def _get_latest_pdus_in_context(self, txn, context):
        query = (
            "SELECT p.pdu_id, p.origin, p.depth FROM %(pdus)s as p "
            "INNER JOIN %(forward)s as f ON p.pdu_id = f.pdu_id "
            "AND f.origin = p.origin "
            "WHERE f.context = ?"
        ) % {
            "pdus": PdusTable.table_name,
            "forward": PduForwardExtremitiesTable.table_name,
        }

        logger.debug("get_prev query: %s", query)

        txn.execute(
            query,
            (context, )
        )

        results = txn.fetchall()

        return [(row[0], row[1], row[2]) for row in results]

    def get_oldest_pdus_in_context(self, context):
        """Get a list of Pdus that we paginated beyond yet (and haven't seen).
        This list is used when we want to paginate backwards and is the list we
        send to the remote server.

        Args:
            txn
            context (str)

        Returns:
            list: A list of PduIdTuple.
        """
        return self._db_pool.runInteraction(
            self._get_oldest_pdus_in_context, context
        )

    def _get_oldest_pdus_in_context(self, txn, context):
        txn.execute(
            "SELECT pdu_id, origin FROM %(back)s WHERE context = ?"
            % {"back": PduBackwardExtremitiesTable.table_name, },
            (context,)
        )
        return [PduIdTuple(i, o) for i, o in txn.fetchall()]

    def is_pdu_new(self, pdu_id, origin, context, depth):
        """For a given Pdu, try and figure out if it's 'new', i.e., if it's
        not something we got randomly from the past, for example when we
        request the current state of the room that will probably return a bunch
        of pdus from before we joined.

        Args:
            txn
            pdu_id (str)
            origin (str)
            context (str)
            depth (int)

        Returns:
            bool
        """

        return self._db_pool.runInteraction(
            self._is_pdu_new,
            pdu_id=pdu_id,
            origin=origin,
            context=context,
            depth=depth
        )

    def _is_pdu_new(self, txn, pdu_id, origin, context, depth):
        # If depth > min depth in back table, then we classify it as new.
        # OR if there is nothing in the back table, then it kinda needs to
        # be a new thing.
        query = (
            "SELECT min(p.depth) FROM %(edges)s as e "
            "INNER JOIN %(back)s as b "
            "ON e.prev_pdu_id = b.pdu_id AND e.prev_origin = b.origin "
            "INNER JOIN %(pdus)s as p "
            "ON e.pdu_id = p.pdu_id AND p.origin = e.origin "
            "WHERE p.context = ?"
        ) % {
            "pdus": PdusTable.table_name,
            "edges": PduEdgesTable.table_name,
            "back": PduBackwardExtremitiesTable.table_name,
        }

        txn.execute(query, (context,))

        min_depth, = txn.fetchone()

        if not min_depth or depth > int(min_depth):
            logger.debug(
                "is_new true: id=%s, o=%s, d=%s min_depth=%s",
                pdu_id, origin, depth, min_depth
            )
            return True

        # If this pdu is in the forwards table, then it also is a new one
        query = (
            "SELECT * FROM %(forward)s WHERE pdu_id = ? AND origin = ?"
        ) % {
            "forward": PduForwardExtremitiesTable.table_name,
        }

        txn.execute(query, (pdu_id, origin))

        # Did we get anything?
        if txn.fetchall():
            logger.debug(
                "is_new true: id=%s, o=%s, d=%s was forward",
                pdu_id, origin, depth
            )
            return True

        logger.debug(
            "is_new false: id=%s, o=%s, d=%s",
            pdu_id, origin, depth
        )

        # FINE THEN. It's probably old.
        return False

    @staticmethod
    @log_function
    def _handle_prev_pdus(txn, outlier, pdu_id, origin, prev_pdus,
                          context):
        txn.executemany(
            PduEdgesTable.insert_statement(),
            [(pdu_id, origin, p[0], p[1], context) for p in prev_pdus]
        )

        # Update the extremities table if this is not an outlier.
        if not outlier:

            # First, we delete the new one from the forwards extremities table.
            query = (
                "DELETE FROM %s WHERE pdu_id = ? AND origin = ?"
                % PduForwardExtremitiesTable.table_name
            )
            txn.executemany(query, prev_pdus)

            # We only insert as a forward extremety the new pdu if there are no
            # other pdus that reference it as a prev pdu
            query = (
                "INSERT INTO %(table)s (pdu_id, origin, context) "
                "SELECT ?, ?, ? WHERE NOT EXISTS ("
                "SELECT 1 FROM %(pdu_edges)s WHERE "
                "prev_pdu_id = ? AND prev_origin = ?"
                ")"
            ) % {
                "table": PduForwardExtremitiesTable.table_name,
                "pdu_edges": PduEdgesTable.table_name
            }

            logger.debug("query: %s", query)

            txn.execute(query, (pdu_id, origin, context, pdu_id, origin))

            # Insert all the prev_pdus as a backwards thing, they'll get
            # deleted in a second if they're incorrect anyway.
            txn.executemany(
                PduBackwardExtremitiesTable.insert_statement(),
                [(i, o, context) for i, o in prev_pdus]
            )

            # Also delete from the backwards extremities table all ones that
            # reference pdus that we have already seen
            query = (
                "DELETE FROM %(pdu_back)s WHERE EXISTS ("
                "SELECT 1 FROM %(pdus)s AS pdus "
                "WHERE "
                "%(pdu_back)s.pdu_id = pdus.pdu_id "
                "AND %(pdu_back)s.origin = pdus.origin "
                "AND not pdus.outlier "
                ")"
            ) % {
                "pdu_back": PduBackwardExtremitiesTable.table_name,
                "pdus": PdusTable.table_name,
            }
            txn.execute(query)


class StatePduStore(SQLBaseStore):
    """A collection of queries for handling state PDUs.
    """

    def persist_state(self, prev_pdus, **cols):
        """Inserts a state PDU into the database

        Args:
            txn,
            prev_pdus (list)
            **cols: The columns to insert into the PdusTable and StatePdusTable
        """

        return self._db_pool.runInteraction(
            self._persist_state, prev_pdus, cols
        )

    def _persist_state(self, txn, prev_pdus, cols):
        pdu_entry = PdusTable.EntryType(
            **{k: cols.get(k, None) for k in PdusTable.fields}
        )
        state_entry = StatePdusTable.EntryType(
            **{k: cols.get(k, None) for k in StatePdusTable.fields}
        )

        logger.debug("Inserting pdu: %s", repr(pdu_entry))
        logger.debug("Inserting state: %s", repr(state_entry))

        txn.execute(PdusTable.insert_statement(), pdu_entry)
        txn.execute(StatePdusTable.insert_statement(), state_entry)

        self._handle_prev_pdus(
            txn,
            pdu_entry.outlier, pdu_entry.pdu_id, pdu_entry.origin, prev_pdus,
            pdu_entry.context
        )

    def get_unresolved_state_tree(self, new_state_pdu):
        return self._db_pool.runInteraction(
            self._get_unresolved_state_tree, new_state_pdu
        )

    @log_function
    def _get_unresolved_state_tree(self, txn, new_pdu):
        current = self._get_current_interaction(
            txn,
            new_pdu.context, new_pdu.pdu_type, new_pdu.state_key
        )

        ReturnType = namedtuple(
            "StateReturnType", ["new_branch", "current_branch"]
        )
        return_value = ReturnType([new_pdu], [])

        if not current:
            logger.debug("get_unresolved_state_tree No current state.")
            return return_value

        return_value.current_branch.append(current)

        enum_branches = self._enumerate_state_branches(
            txn, new_pdu, current
        )

        for branch, prev_state, state in enum_branches:
            if state:
                return_value[branch].append(state)
            else:
                break

        return return_value

    def update_current_state(self, pdu_id, origin, context, pdu_type,
                             state_key):
        return self._db_pool.runInteraction(
            self._update_current_state,
            pdu_id, origin, context, pdu_type, state_key
        )

    def _update_current_state(self, txn, pdu_id, origin, context, pdu_type,
                              state_key):
        query = (
            "INSERT OR REPLACE INTO %(curr)s (%(fields)s) VALUES (%(qs)s)"
        ) % {
            "curr": CurrentStateTable.table_name,
            "fields": CurrentStateTable.get_fields_string(),
            "qs": ", ".join(["?"] * len(CurrentStateTable.fields))
        }

        query_args = CurrentStateTable.EntryType(
            pdu_id=pdu_id,
            origin=origin,
            context=context,
            pdu_type=pdu_type,
            state_key=state_key
        )

        txn.execute(query, query_args)

    def get_current_state(self, context, pdu_type, state_key):
        """For a given context, pdu_type, state_key 3-tuple, return what is
        currently considered the current state.

        Args:
            txn
            context (str)
            pdu_type (str)
            state_key (str)

        Returns:
            PduEntry
        """

        return self._db_pool.runInteraction(
            self._get_current_state, context, pdu_type, state_key
        )

    def _get_current_state(self, txn, context, pdu_type, state_key):
        return self._get_current_interaction(txn, context, pdu_type, state_key)

    def _get_current_interaction(self, txn, context, pdu_type, state_key):
        logger.debug(
            "_get_current_interaction %s %s %s",
            context, pdu_type, state_key
        )

        fields = _pdu_state_joiner.get_fields(
            PdusTable="p", StatePdusTable="s")

        current_query = (
            "SELECT %(fields)s FROM %(state)s as s "
            "INNER JOIN %(pdus)s as p "
            "ON s.pdu_id = p.pdu_id AND s.origin = p.origin "
            "INNER JOIN %(curr)s as c "
            "ON s.pdu_id = c.pdu_id AND s.origin = c.origin "
            "WHERE s.context = ? AND s.pdu_type = ? AND s.state_key = ? "
        ) % {
            "fields": fields,
            "curr": CurrentStateTable.table_name,
            "state": StatePdusTable.table_name,
            "pdus": PdusTable.table_name,
        }

        txn.execute(
            current_query,
            (context, pdu_type, state_key)
        )

        row = txn.fetchone()

        result = PduEntry(*row) if row else None

        if not result:
            logger.debug("_get_current_interaction not found")
        else:
            logger.debug(
                "_get_current_interaction found %s %s",
                result.pdu_id, result.origin
            )

        return result

    def get_next_missing_pdu(self, new_pdu):
        """When we get a new state pdu we need to check whether we need to do
        any conflict resolution, if we do then we need to check if we need
        to go back and request some more state pdus that we haven't seen yet.

        Args:
            txn
            new_pdu

        Returns:
            PduIdTuple: A pdu that we are missing, or None if we have all the
                pdus required to do the conflict resolution.
        """
        return self._db_pool.runInteraction(
            self._get_next_missing_pdu, new_pdu
        )

    def _get_next_missing_pdu(self, txn, new_pdu):
        logger.debug(
            "get_next_missing_pdu %s %s",
            new_pdu.pdu_id, new_pdu.origin
        )

        current = self._get_current_interaction(
            txn,
            new_pdu.context, new_pdu.pdu_type, new_pdu.state_key
        )

        if (not current or not current.prev_state_id
                or not current.prev_state_origin):
            return None

        # Oh look, it's a straight clobber, so wooooo almost no-op.
        if (new_pdu.prev_state_id == current.pdu_id
                and new_pdu.prev_state_origin == current.origin):
            return None

        enum_branches = self._enumerate_state_branches(txn, new_pdu, current)
        for branch, prev_state, state in enum_branches:
            if not state:
                return PduIdTuple(
                    prev_state.prev_state_id,
                    prev_state.prev_state_origin
                )

        return None

    def handle_new_state(self, new_pdu):
        """Actually perform conflict resolution on the new_pdu on the
        assumption we have all the pdus required to perform it.

        Args:
            new_pdu

        Returns:
            bool: True if the new_pdu clobbered the current state, False if not
        """
        return self._db_pool.runInteraction(
            self._handle_new_state, new_pdu
        )

    def _handle_new_state(self, txn, new_pdu):
        logger.debug(
            "handle_new_state %s %s",
            new_pdu.pdu_id, new_pdu.origin
        )

        current = self._get_current_interaction(
            txn,
            new_pdu.context, new_pdu.pdu_type, new_pdu.state_key
        )

        is_current = False

        if (not current or not current.prev_state_id
                or not current.prev_state_origin):
            # Oh, we don't have any state for this yet.
            is_current = True
        elif (current.pdu_id == new_pdu.prev_state_id
                and current.origin == new_pdu.prev_state_origin):
            # Oh! A direct clobber. Just do it.
            is_current = True
        else:
            ##
            # Ok, now loop through until we get to a common ancestor.
            max_new = int(new_pdu.power_level)
            max_current = int(current.power_level)

            enum_branches = self._enumerate_state_branches(
                txn, new_pdu, current
            )
            for branch, prev_state, state in enum_branches:
                if not state:
                    raise RuntimeError(
                        "Could not find state_pdu %s %s" %
                        (
                            prev_state.prev_state_id,
                            prev_state.prev_state_origin
                        )
                    )

                if branch == 0:
                    max_new = max(int(state.depth), max_new)
                else:
                    max_current = max(int(state.depth), max_current)

            is_current = max_new > max_current

        if is_current:
            logger.debug("handle_new_state make current")

            # Right, this is a new thing, so woo, just insert it.
            txn.execute(
                "INSERT OR REPLACE INTO %(curr)s (%(fields)s) VALUES (%(qs)s)"
                % {
                    "curr": CurrentStateTable.table_name,
                    "fields": CurrentStateTable.get_fields_string(),
                    "qs": ", ".join(["?"] * len(CurrentStateTable.fields))
                },
                CurrentStateTable.EntryType(
                    *(new_pdu.__dict__[k] for k in CurrentStateTable.fields)
                )
            )
        else:
            logger.debug("handle_new_state not current")

        logger.debug("handle_new_state done")

        return is_current

    @classmethod
    @log_function
    def _enumerate_state_branches(cls, txn, pdu_a, pdu_b):
        branch_a = pdu_a
        branch_b = pdu_b

        get_query = (
            "SELECT %(fields)s FROM %(pdus)s as p "
            "LEFT JOIN %(state)s as s "
            "ON p.pdu_id = s.pdu_id AND p.origin = s.origin "
            "WHERE p.pdu_id = ? AND p.origin = ? "
        ) % {
            "fields": _pdu_state_joiner.get_fields(
                PdusTable="p", StatePdusTable="s"),
            "pdus": PdusTable.table_name,
            "state": StatePdusTable.table_name,
        }

        while True:
            if (branch_a.pdu_id == branch_b.pdu_id
                    and branch_a.origin == branch_b.origin):
                # Woo! We found a common ancestor
                logger.debug("_enumerate_state_branches Found common ancestor")
                break

            do_branch_a = (
                hasattr(branch_a, "prev_state_id") and
                branch_a.prev_state_id
            )

            do_branch_b = (
                hasattr(branch_b, "prev_state_id") and
                branch_b.prev_state_id
            )

            logger.debug(
                "do_branch_a=%s, do_branch_b=%s",
                do_branch_a, do_branch_b
            )

            if do_branch_a and do_branch_b:
                do_branch_a = int(branch_a.depth) > int(branch_b.depth)

            if do_branch_a:
                pdu_tuple = PduIdTuple(
                    branch_a.prev_state_id,
                    branch_a.prev_state_origin
                )

                logger.debug("getting branch_a prev %s", pdu_tuple)
                txn.execute(get_query, pdu_tuple)

                prev_branch = branch_a

                res = txn.fetchone()
                branch_a = PduEntry(*res) if res else None

                logger.debug("branch_a=%s", branch_a)

                yield (0, prev_branch, branch_a)

                if not branch_a:
                    break
            elif do_branch_b:
                pdu_tuple = PduIdTuple(
                    branch_b.prev_state_id,
                    branch_b.prev_state_origin
                )
                txn.execute(get_query, pdu_tuple)

                logger.debug("getting branch_b prev %s", pdu_tuple)

                prev_branch = branch_b

                res = txn.fetchone()
                branch_b = PduEntry(*res) if res else None

                logger.debug("branch_b=%s", branch_b)

                yield (1, prev_branch, branch_b)

                if not branch_b:
                    break
            else:
                break


class PdusTable(Table):
    table_name = "pdus"

    fields = [
        "pdu_id",
        "origin",
        "context",
        "pdu_type",
        "ts",
        "depth",
        "is_state",
        "content_json",
        "unrecognized_keys",
        "outlier",
        "have_processed",
    ]

    EntryType = namedtuple("PdusEntry", fields)


class PduDestinationsTable(Table):
    table_name = "pdu_destinations"

    fields = [
        "pdu_id",
        "origin",
        "destination",
        "delivered_ts",
    ]

    EntryType = namedtuple("PduDestinationsEntry", fields)


class PduEdgesTable(Table):
    table_name = "pdu_edges"

    fields = [
        "pdu_id",
        "origin",
        "prev_pdu_id",
        "prev_origin",
        "context"
    ]

    EntryType = namedtuple("PduEdgesEntry", fields)


class PduForwardExtremitiesTable(Table):
    table_name = "pdu_forward_extremities"

    fields = [
        "pdu_id",
        "origin",
        "context",
    ]

    EntryType = namedtuple("PduForwardExtremitiesEntry", fields)


class PduBackwardExtremitiesTable(Table):
    table_name = "pdu_backward_extremities"

    fields = [
        "pdu_id",
        "origin",
        "context",
    ]

    EntryType = namedtuple("PduBackwardExtremitiesEntry", fields)


class ContextDepthTable(Table):
    table_name = "context_depth"

    fields = [
        "context",
        "min_depth",
    ]

    EntryType = namedtuple("ContextDepthEntry", fields)


class StatePdusTable(Table):
    table_name = "state_pdus"

    fields = [
        "pdu_id",
        "origin",
        "context",
        "pdu_type",
        "state_key",
        "power_level",
        "prev_state_id",
        "prev_state_origin",
    ]

    EntryType = namedtuple("StatePdusEntry", fields)


class CurrentStateTable(Table):
    table_name = "current_state"

    fields = [
        "pdu_id",
        "origin",
        "context",
        "pdu_type",
        "state_key",
    ]

    EntryType = namedtuple("CurrentStateEntry", fields)

_pdu_state_joiner = JoinHelper(PdusTable, StatePdusTable)


# TODO: These should probably be put somewhere more sensible
PduIdTuple = namedtuple("PduIdTuple", ("pdu_id", "origin"))

PduEntry = _pdu_state_joiner.EntryType
""" We are always interested in the join of the PdusTable and StatePdusTable,
rather than just the PdusTable.

This does not include a prev_pdus key.
"""

PduTuple = namedtuple(
    "PduTuple",
    ("pdu_entry", "prev_pdu_list")
)
""" This is a tuple of a `PduEntry` and a list of `PduIdTuple` that represent
the `prev_pdus` key of a PDU.
"""
