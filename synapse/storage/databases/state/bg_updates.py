# Copyright 2014-2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Dict, List, Mapping, Optional, Tuple, Union

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.engines import PostgresEngine
from synapse.storage.state import StateFilter
from synapse.types import MutableStateMap, StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


MAX_STATE_DELTA_HOPS = 100


class StateGroupBackgroundUpdateStore(SQLBaseStore):
    """Defines functions related to state groups needed to run the state background
    updates.
    """

    def _count_state_group_hops_txn(
        self, txn: LoggingTransaction, state_group: int
    ) -> int:
        """Given a state group, count how many hops there are in the tree.

        This is used to ensure the delta chains don't get too long.
        """
        if isinstance(self.database_engine, PostgresEngine):
            sql = """
                WITH RECURSIVE state(state_group) AS (
                    VALUES(?::bigint)
                    UNION ALL
                    SELECT prev_state_group FROM state_group_edges e, state s
                    WHERE s.state_group = e.state_group
                )
                SELECT count(*) FROM state;
            """

            txn.execute(sql, (state_group,))
            row = txn.fetchone()
            if row and row[0]:
                return row[0]
            else:
                return 0
        else:
            # We don't use WITH RECURSIVE on sqlite3 as there are distributions
            # that ship with an sqlite3 version that doesn't support it (e.g. wheezy)
            next_group: Optional[int] = state_group
            count = 0

            while next_group:
                next_group = self.db_pool.simple_select_one_onecol_txn(
                    txn,
                    table="state_group_edges",
                    keyvalues={"state_group": next_group},
                    retcol="prev_state_group",
                    allow_none=True,
                )
                if next_group:
                    count += 1

            return count

    def _get_state_groups_from_groups_txn(
        self,
        txn: LoggingTransaction,
        groups: List[int],
        state_filter: Optional[StateFilter] = None,
    ) -> Mapping[int, StateMap[str]]:
        state_filter = state_filter or StateFilter.all()

        results: Dict[int, MutableStateMap[str]] = {group: {} for group in groups}

        where_clause, where_args = state_filter.make_sql_filter_clause()

        # Unless the filter clause is empty, we're going to append it after an
        # existing where clause
        if where_clause:
            where_clause = " AND (%s)" % (where_clause,)

        if isinstance(self.database_engine, PostgresEngine):
            # Temporarily disable sequential scans in this transaction. This is
            # a temporary hack until we can add the right indices in
            txn.execute("SET LOCAL enable_seqscan=off")

            # The below query walks the state_group tree so that the "state"
            # table includes all state_groups in the tree. It then joins
            # against `state_groups_state` to fetch the latest state.
            # It assumes that previous state groups are always numerically
            # lesser.
            # The PARTITION is used to get the event_id in the greatest state
            # group for the given type, state_key.
            # This may return multiple rows per (type, state_key), but last_value
            # should be the same.
            sql = """
                WITH RECURSIVE state(state_group) AS (
                    VALUES(?::bigint)
                    UNION ALL
                    SELECT prev_state_group FROM state_group_edges e, state s
                    WHERE s.state_group = e.state_group
                )
                SELECT DISTINCT ON (type, state_key)
                    type, state_key, event_id
                FROM state_groups_state
                WHERE state_group IN (
                    SELECT state_group FROM state
                ) %s
                ORDER BY type, state_key, state_group DESC
            """

            for group in groups:
                args: List[Union[int, str]] = [group]
                args.extend(where_args)

                txn.execute(sql % (where_clause,), args)
                for row in txn:
                    typ, state_key, event_id = row
                    key = (typ, state_key)
                    results[group][key] = event_id
        else:
            max_entries_returned = state_filter.max_entries_returned()

            # We don't use WITH RECURSIVE on sqlite3 as there are distributions
            # that ship with an sqlite3 version that doesn't support it (e.g. wheezy)
            for group in groups:
                next_group: Optional[int] = group

                while next_group:
                    # We did this before by getting the list of group ids, and
                    # then passing that list to sqlite to get latest event for
                    # each (type, state_key). However, that was terribly slow
                    # without the right indices (which we can't add until
                    # after we finish deduping state, which requires this func)
                    args = [next_group]
                    args.extend(where_args)

                    txn.execute(
                        "SELECT type, state_key, event_id FROM state_groups_state"
                        " WHERE state_group = ? " + where_clause,
                        args,
                    )
                    results[group].update(
                        ((typ, state_key), event_id)
                        for typ, state_key, event_id in txn
                        if (typ, state_key) not in results[group]
                    )

                    # If the number of entries in the (type,state_key)->event_id dict
                    # matches the number of (type,state_keys) types we were searching
                    # for, then we must have found them all, so no need to go walk
                    # further down the tree... UNLESS our types filter contained
                    # wildcards (i.e. Nones) in which case we have to do an exhaustive
                    # search
                    if (
                        max_entries_returned is not None
                        and len(results[group]) == max_entries_returned
                    ):
                        break

                    next_group = self.db_pool.simple_select_one_onecol_txn(
                        txn,
                        table="state_group_edges",
                        keyvalues={"state_group": next_group},
                        retcol="prev_state_group",
                        allow_none=True,
                    )

        # The results shouldn't be considered mutable.
        return results


class StateBackgroundUpdateStore(StateGroupBackgroundUpdateStore):

    STATE_GROUP_DEDUPLICATION_UPDATE_NAME = "state_group_state_deduplication"
    STATE_GROUP_INDEX_UPDATE_NAME = "state_group_state_type_index"
    STATE_GROUPS_ROOM_INDEX_UPDATE_NAME = "state_groups_room_id_idx"
    STATE_GROUP_EDGES_UNIQUE_INDEX_UPDATE_NAME = "state_group_edges_unique_idx"

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)
        self.db_pool.updates.register_background_update_handler(
            self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME,
            self._background_deduplicate_state,
        )
        self.db_pool.updates.register_background_update_handler(
            self.STATE_GROUP_INDEX_UPDATE_NAME, self._background_index_state
        )
        self.db_pool.updates.register_background_index_update(
            self.STATE_GROUPS_ROOM_INDEX_UPDATE_NAME,
            index_name="state_groups_room_id_idx",
            table="state_groups",
            columns=["room_id"],
        )

        # `state_group_edges` can cause severe performance issues if duplicate
        # rows are introduced, which can accidentally be done by well-meaning
        # server admins when trying to restore a database dump, etc.
        # See https://github.com/matrix-org/synapse/issues/11779.
        # Introduce a unique index to guard against that.
        self.db_pool.updates.register_background_index_update(
            self.STATE_GROUP_EDGES_UNIQUE_INDEX_UPDATE_NAME,
            index_name="state_group_edges_unique_idx",
            table="state_group_edges",
            columns=["state_group", "prev_state_group"],
            unique=True,
            # The old index was on (state_group) and was not unique.
            replaces_index="state_group_edges_idx",
        )

    async def _background_deduplicate_state(
        self, progress: dict, batch_size: int
    ) -> int:
        """This background update will slowly deduplicate state by reencoding
        them as deltas.
        """
        last_state_group = progress.get("last_state_group", 0)
        rows_inserted = progress.get("rows_inserted", 0)
        max_group = progress.get("max_group", None)

        BATCH_SIZE_SCALE_FACTOR = 100

        batch_size = max(1, int(batch_size / BATCH_SIZE_SCALE_FACTOR))

        if max_group is None:
            rows = await self.db_pool.execute(
                "_background_deduplicate_state",
                None,
                "SELECT coalesce(max(id), 0) FROM state_groups",
            )
            max_group = rows[0][0]

        def reindex_txn(txn: LoggingTransaction) -> Tuple[bool, int]:
            new_last_state_group = last_state_group
            for count in range(batch_size):
                txn.execute(
                    "SELECT id, room_id FROM state_groups"
                    " WHERE ? < id AND id <= ?"
                    " ORDER BY id ASC"
                    " LIMIT 1",
                    (new_last_state_group, max_group),
                )
                row = txn.fetchone()
                if row:
                    state_group, room_id = row

                if not row or not state_group:
                    return True, count

                txn.execute(
                    "SELECT state_group FROM state_group_edges"
                    " WHERE state_group = ?",
                    (state_group,),
                )

                # If we reach a point where we've already started inserting
                # edges we should stop.
                if txn.fetchall():
                    return True, count

                txn.execute(
                    "SELECT coalesce(max(id), 0) FROM state_groups"
                    " WHERE id < ? AND room_id = ?",
                    (state_group, room_id),
                )
                # There will be a result due to the coalesce.
                (prev_group,) = txn.fetchone()  # type: ignore
                new_last_state_group = state_group

                if prev_group:
                    potential_hops = self._count_state_group_hops_txn(txn, prev_group)
                    if potential_hops >= MAX_STATE_DELTA_HOPS:
                        # We want to ensure chains are at most this long,#
                        # otherwise read performance degrades.
                        continue

                    prev_state_by_group = self._get_state_groups_from_groups_txn(
                        txn, [prev_group]
                    )
                    prev_state = prev_state_by_group[prev_group]

                    curr_state_by_group = self._get_state_groups_from_groups_txn(
                        txn, [state_group]
                    )
                    curr_state = curr_state_by_group[state_group]

                    if not set(prev_state.keys()) - set(curr_state.keys()):
                        # We can only do a delta if the current has a strict super set
                        # of keys

                        delta_state = {
                            key: value
                            for key, value in curr_state.items()
                            if prev_state.get(key, None) != value
                        }

                        self.db_pool.simple_delete_txn(
                            txn,
                            table="state_group_edges",
                            keyvalues={"state_group": state_group},
                        )

                        self.db_pool.simple_insert_txn(
                            txn,
                            table="state_group_edges",
                            values={
                                "state_group": state_group,
                                "prev_state_group": prev_group,
                            },
                        )

                        self.db_pool.simple_delete_txn(
                            txn,
                            table="state_groups_state",
                            keyvalues={"state_group": state_group},
                        )

                        self.db_pool.simple_insert_many_txn(
                            txn,
                            table="state_groups_state",
                            keys=(
                                "state_group",
                                "room_id",
                                "type",
                                "state_key",
                                "event_id",
                            ),
                            values=[
                                (state_group, room_id, key[0], key[1], state_id)
                                for key, state_id in delta_state.items()
                            ],
                        )

            progress = {
                "last_state_group": state_group,
                "rows_inserted": rows_inserted + batch_size,
                "max_group": max_group,
            }

            self.db_pool.updates._background_update_progress_txn(
                txn, self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME, progress
            )

            return False, batch_size

        finished, result = await self.db_pool.runInteraction(
            self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME, reindex_txn
        )

        if finished:
            await self.db_pool.updates._end_background_update(
                self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME
            )

        return result * BATCH_SIZE_SCALE_FACTOR

    async def _background_index_state(self, progress: dict, batch_size: int) -> int:
        def reindex_txn(conn: LoggingDatabaseConnection) -> None:
            conn.rollback()
            if isinstance(self.database_engine, PostgresEngine):
                # postgres insists on autocommit for the index
                conn.set_session(autocommit=True)
                try:
                    txn = conn.cursor()
                    txn.execute(
                        "CREATE INDEX CONCURRENTLY state_groups_state_type_idx"
                        " ON state_groups_state(state_group, type, state_key)"
                    )
                    txn.execute("DROP INDEX IF EXISTS state_groups_state_id")
                finally:
                    conn.set_session(autocommit=False)
            else:
                txn = conn.cursor()
                txn.execute(
                    "CREATE INDEX state_groups_state_type_idx"
                    " ON state_groups_state(state_group, type, state_key)"
                )
                txn.execute("DROP INDEX IF EXISTS state_groups_state_id")

        await self.db_pool.runWithConnection(reindex_txn)

        await self.db_pool.updates._end_background_update(
            self.STATE_GROUP_INDEX_UPDATE_NAME
        )

        return 1
