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
from synapse.types import MutableStateMap, StateMap
from synapse.types.state import StateFilter
from synapse.util.caches import intern_string

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

        if isinstance(self.database_engine, PostgresEngine):
            # Temporarily disable sequential scans in this transaction. This is
            # a temporary hack until we can add the right indices in
            txn.execute("SET LOCAL enable_seqscan=off")

        # The below query walks the state_group tree so that the "state"
        # table includes all state_groups in the tree. It then joins
        # against `state_groups_state` to fetch the latest state.
        # It assumes that previous state groups are always numerically
        # lesser.
        sql = """
            WITH RECURSIVE sgs(state_group) AS (
                VALUES(CAST(? AS bigint))
                UNION ALL
                SELECT prev_state_group FROM state_group_edges e, sgs s
                WHERE s.state_group = e.state_group
            )
            %s
        """

        overall_select_query_args: List[Union[int, str]] = []

        # This is an optimization to create a select clause per-condition. This
        # makes the query planner a lot smarter on what rows should pull out in the
        # first place and we end up with something that takes 10x less time to get a
        # result.
        use_condition_optimization = (
            not state_filter.include_others and not state_filter.is_full()
        )
        state_filter_condition_combos: List[Tuple[str, Optional[str]]] = []
        # We only need to caclculate this list if we're using the condition optimization
        if use_condition_optimization:
            for etype, state_keys in state_filter.types.items():
                if state_keys is None:
                    state_filter_condition_combos.append((etype, None))
                else:
                    for state_key in state_keys:
                        state_filter_condition_combos.append((etype, state_key))
        # And here is the optimization itself. We don't want to do the optimization
        # if there are too many individual conditions. 10 is an arbitrary number
        # with no testing behind it but we do know that we specifically made this
        # optimization for when we grab the necessary state out for
        # `filter_events_for_client` which just uses 2 conditions
        # (`EventTypes.RoomHistoryVisibility` and `EventTypes.Member`).
        if use_condition_optimization and len(state_filter_condition_combos) < 10:
            select_clause_list: List[str] = []
            for etype, skey in state_filter_condition_combos:
                if skey is None:
                    where_clause = "(type = ?)"
                    overall_select_query_args.extend([etype])
                else:
                    where_clause = "(type = ? AND state_key = ?)"
                    overall_select_query_args.extend([etype, skey])

                # Small helper function to wrap the union clause in parenthesis if we're
                # using postgres. This is because SQLite doesn't allow `LIMIT`/`ORDER`
                # clauses in the union subquery but postgres does as long as they are
                # wrapped in parenthesis which this function handles the complexity of
                # handling.
                def wrap_union_if_postgres(
                    union_clause: str, extra_order_or_limit_clause: str = ""
                ) -> str:
                    if isinstance(self.database_engine, PostgresEngine):
                        return f"""({union_clause} {extra_order_or_limit_clause})"""

                    return union_clause

                # We could use `SELECT DISTINCT ON` here to align with the query below
                # but that isn't compatible with SQLite and we can get away with `LIMIT
                # 1` here instead because the `WHERE` clause will only ever match and
                # target one event; and is simpler anyway. And it's better to use
                # something that's simpler and compatible with both Database engines.
                select_clause_list.append(
                    wrap_union_if_postgres(
                        # We only select `state_group` here for use in the `ORDER`
                        # clause later after the `UNION`
                        f"""
                        SELECT type, state_key, event_id, state_group
                        FROM state_groups_state
                        INNER JOIN sgs USING (state_group)
                        WHERE {where_clause}
                        """,
                        # The `LIMIT` is an extra nicety that saves us from having to
                        # ferry a bunch of duplicate state pairs back from the database
                        # since we only need the one with the greatest state_group (most
                        # recent). Since this only applies to postgres, we do have to be
                        # careful to take care of the duplicate pairs in the downstream
                        # code when running with SQLite.
                        "LIMIT 1",
                    )
                )

            overall_select_clause = (
                " UNION ".join(select_clause_list)
                # We `ORDER` after the union results because it's compatible with both
                # Postgres and SQLite. And we need the rows to by ordered by
                # `state_group` in both cases so the greatest state_group pairs are
                # first and we only care about the first distinct (type, state_key) pair later on.
                + " ORDER BY type, state_key, state_group DESC"
            )
        else:
            where_clause, where_args = state_filter.make_sql_filter_clause()
            # Unless the filter clause is empty, we're going to append it after an
            # existing where clause
            if where_clause:
                where_clause = " AND (%s)" % (where_clause,)

            overall_select_query_args.extend(where_args)

            if isinstance(self.database_engine, PostgresEngine):
                overall_select_clause = f"""
                    SELECT DISTINCT ON (type, state_key)
                        type, state_key, event_id
                    FROM state_groups_state
                    WHERE state_group IN (
                        SELECT state_group FROM sgs
                    ) {where_clause}
                    ORDER BY type, state_key, state_group DESC
                """
            else:
                # SQLite doesn't support `SELECT DISTINCT ON`, so we have to just get
                # some potential duplicate (type, state_key) pairs and then only use the
                # first of each kind we see.
                overall_select_clause = f"""
                    SELECT type, state_key, event_id
                    FROM state_groups_state
                    WHERE state_group IN (
                        SELECT state_group FROM sgs
                    ) {where_clause}
                    ORDER BY type, state_key, state_group DESC
                """

        for group in groups:
            args: List[Union[int, str]] = [group]
            args.extend(overall_select_query_args)

            txn.execute(sql % (overall_select_clause,), args)
            for row in txn:
                # The `*_` rest syntax is to ignore the `state_group` column which we
                # only select in the optimized case
                typ, state_key, event_id, *_ = row
                key = (intern_string(typ), intern_string(state_key))
                # Deal with the potential duplicate (type, state_key) pairs from the
                # SQLite specific query above. We only want to use the first row which
                # is from the greatest state group (most-recent) because that is that
                # applicable state in that state group.
                if key not in results[group]:
                    results[group][key] = event_id

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
