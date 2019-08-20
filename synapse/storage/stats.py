# -*- coding: utf-8 -*-
# Copyright 2018, 2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from threading import Lock

from twisted.internet import defer

from synapse.storage.state_deltas import StateDeltasStore
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)

# these fields track absolutes (e.g. total number of rooms on the server)
ABSOLUTE_STATS_FIELDS = {
    "room": (
        "current_state_events",
        "joined_members",
        "invited_members",
        "left_members",
        "banned_members",
        "total_events",
    ),
    "user": ("public_rooms", "private_rooms"),
}

# these fields are per-timeslice and so should be reset to 0 upon a new slice
PER_SLICE_FIELDS = {"room": (), "user": ()}

TYPE_TO_TABLE = {"room": ("room_stats", "room_id"), "user": ("user_stats", "user_id")}


class OldCollectionRequired(Exception):
    """ Signal that we need to collect old stats rows and retry. """

    pass


class StatsStore(StateDeltasStore):
    def __init__(self, db_conn, hs):
        super(StatsStore, self).__init__(db_conn, hs)

        self.server_name = hs.hostname
        self.clock = self.hs.get_clock()
        self.stats_enabled = hs.config.stats_enabled
        self.stats_bucket_size = hs.config.stats_bucket_size

        self.stats_delta_processing_lock = Lock()

        self.register_noop_background_update("populate_stats_createtables")
        self.register_noop_background_update("populate_stats_process_rooms")
        self.register_noop_background_update("populate_stats_cleanup")

    def quantise_stats_time(self, ts):
        """
        Quantises a timestamp to be a multiple of the bucket size.

        Args:
            ts: the timestamp to quantise, in seconds since the Unix Epoch

        Returns:
            a timestamp which
              - is divisible by the bucket size;
              - is no later than `ts`; and
              - is the largest such timestamp.
        """
        return (ts // self.stats_bucket_size) * self.stats_bucket_size

    def get_stats_positions(self, for_initial_processor=False):
        """
        Returns the stats processor positions.

        Args:
            for_initial_processor (bool, optional): If true, returns the position
                promised by the latest stats regeneration, rather than the current
                incremental processor's position.
                Otherwise (if false), return the incremental processor's position.

        Returns (dict):
            Dict containing :-
                state_delta_stream_id: stream_id of last-processed state delta
                total_events_min_stream_ordering: stream_ordering of latest-processed
                    backfilled event, in the context of total_events counting.
                total_events_max_stream_ordering: stream_ordering of latest-processed
                    non-backfilled event, in the context of total_events counting.
        """
        return self._simple_select_one(
            table="stats_incremental_position",
            keyvalues={"is_background_contract": for_initial_processor},
            retcols=(
                "state_delta_stream_id",
                "total_events_min_stream_ordering",
                "total_events_max_stream_ordering",
            ),
            desc="stats_incremental_position",
        )

    def _get_stats_positions_txn(self, txn, for_initial_processor=False):
        """
        See L{get_stats_positions}.

        Args:
             txn (cursor): Database cursor
        """
        return self._simple_select_one_txn(
            txn=txn,
            table="stats_incremental_position",
            keyvalues={"is_background_contract": for_initial_processor},
            retcols=(
                "state_delta_stream_id",
                "total_events_min_stream_ordering",
                "total_events_max_stream_ordering",
            ),
        )

    def update_stats_positions(self, positions, for_initial_processor=False):
        """
        Updates the stats processor positions.

        Args:
            positions: See L{get_stats_positions}
            for_initial_processor: See L{get_stats_positions}
        """
        if positions is None:
            positions = {
                "state_delta_stream_id": None,
                "total_events_min_stream_ordering": None,
                "total_events_max_stream_ordering": None,
            }
        return self._simple_update_one(
            table="stats_incremental_position",
            keyvalues={"is_background_contract": for_initial_processor},
            updatevalues=positions,
            desc="update_stats_incremental_position",
        )

    def _update_stats_positions_txn(self, txn, positions, for_initial_processor=False):
        """
        See L{update_stats_positions}
        """
        if positions is None:
            positions = {
                "state_delta_stream_id": None,
                "total_events_min_stream_ordering": None,
                "total_events_max_stream_ordering": None,
            }
        return self._simple_update_one_txn(
            txn,
            table="stats_incremental_position",
            keyvalues={"is_background_contract": for_initial_processor},
            updatevalues=positions,
        )

    def update_room_state(self, room_id, fields):
        """
        Args:
            room_id (str)
            fields (dict[str:Any])
        """

        # For whatever reason some of the fields may contain null bytes, which
        # postgres isn't a fan of, so we replace those fields with null.
        for col in (
            "join_rules",
            "history_visibility",
            "encryption",
            "name",
            "topic",
            "avatar",
            "canonical_alias",
        ):
            field = fields.get(col)
            if field and "\0" in field:
                fields[col] = None

        return self._simple_upsert(
            table="room_state",
            keyvalues={"room_id": room_id},
            values=fields,
            desc="update_room_state",
        )

    @cached()
    def get_earliest_token_for_stats(self, stats_type, id):
        """
        Fetch the "earliest token". This is used by the room stats delta
        processor to ignore deltas that have been processed between the
        start of the background task and any particular room's stats
        being calculated.

        Returns:
            Deferred[int]
        """
        table, id_col = TYPE_TO_TABLE[stats_type]

        return self._simple_select_one_onecol(
            "%s_current" % (table,),
            {id_col: id},
            retcol="completed_delta_stream_id",
            allow_none=True,
        )

    def _collect_old_txn(self, txn, stats_type, limit=500):
        """
        See {collect_old}. Runs only a small batch, specified by limit.

        Returns (bool):
            True iff there is possibly more to do (i.e. this needs re-running),
            False otherwise.

        """
        # we do them in batches to prevent concurrent updates from
        # messing us over with lots of retries

        now = self.hs.get_reactor().seconds()
        quantised_ts = self.quantise_stats_time(now)
        table, id_col = TYPE_TO_TABLE[stats_type]

        fields = ", ".join(
            field
            for field in chain(
                ABSOLUTE_STATS_FIELDS[stats_type], PER_SLICE_FIELDS[stats_type]
            )
        )

        # `end_ts IS NOT NULL` is for partial index optimisation
        if isinstance(self.database_engine, Sqlite3Engine):
            # SQLite doesn't support SELECT FOR UPDATE
            sql = (
                "SELECT %s FROM %s_current"
                " WHERE end_ts <= ? AND end_ts IS NOT NULL"
                " LIMIT %d"
            ) % (id_col, table, limit)
        else:
            sql = (
                "SELECT %s FROM %s_current"
                " WHERE end_ts <= ? AND end_ts IS NOT NULL"
                " LIMIT %d FOR UPDATE"
            ) % (id_col, table, limit)
        txn.execute(sql, (quantised_ts,))
        maybe_more = txn.rowcount == limit
        updates = txn.fetchall()

        sql = (
            "INSERT INTO %s_historical (%s, %s, bucket_size, end_ts)"
            " SELECT %s, %s, end_ts - start_ts AS bucket_size, end_ts"
            " FROM %s_current WHERE %s = ?"
        ) % (table, id_col, fields, id_col, fields, table, id_col)
        txn.executemany(sql, updates)

        sql = ("UPDATE %s_current SET start_ts = NULL, end_ts = NULL WHERE %s = ?") % (
            table,
            id_col,
        )
        txn.executemany(sql, updates)

        return maybe_more

    @defer.inlineCallbacks
    def collect_old(self, stats_type):
        """
        Run 'old collection' on current stats rows.

        Old collection is the process of copying dirty (updated) stats rows
        from the current table to the historical table, when those rows have
        finished their stats time slice.
        Collected rows are then cleared of their dirty status.

        Args:
            stats_type: "room" or "user" – the type of stats to run old collection
                on.

        """
        while True:
            maybe_more = yield self.runInteraction(
                "stats_collect_old", self._collect_old_txn, stats_type
            )
            if not maybe_more:
                return None

    @defer.inlineCallbacks
    def update_stats_delta(
        self, ts, stats_type, stats_id, fields, complete_with_stream_id=None
    ):
        """
        Updates the statistics for a subject, with a delta (difference/relative
        change).

        Args:
            ts (int): timestamp of the change
            stats_type (str): "room" or "user" – the kind of subject
            stats_id (str): the subject's ID (room ID or user ID)
            fields (dict[str, int]): Deltas of stats values.
            complete_with_stream_id (int, optional):
                If supplied, converts an incomplete row into a complete row,
                with the supplied stream_id marked as the stream_id where the
                row was completed.
        """

        while True:
            try:
                res = yield self.runInteraction(
                    "update_stats_delta",
                    self._update_stats_delta_txn,
                    ts,
                    stats_type,
                    stats_id,
                    fields,
                    complete_with_stream_id=complete_with_stream_id,
                )
                return res
            except OldCollectionRequired:
                # retry after collecting old rows
                yield self.collect_old(stats_type)

    def _update_stats_delta_txn(
        self,
        txn,
        ts,
        stats_type,
        stats_id,
        fields,
        complete_with_stream_id=None,
        absolute_fields=None,
    ):
        """
        See L{update_stats_delta}
        Additional Args:
            absolute_fields (dict[str, int]): Absolute stats values (i.e. not deltas).
        """
        table, id_col = TYPE_TO_TABLE[stats_type]

        quantised_ts = self.quantise_stats_time(int(ts))
        end_ts = quantised_ts + self.stats_bucket_size

        field_sqls = ["%s = %s + ?" % (field, field) for field in fields.keys()]
        field_values = list(fields.values())

        if absolute_fields is not None:
            field_sqls += ["%s = ?" % (field,) for field in absolute_fields.keys()]
            field_values += list(absolute_fields.values())

        if complete_with_stream_id is not None:
            field_sqls.append("completed_delta_stream_id = ?")
            field_values.append(complete_with_stream_id)

        sql = (
            "UPDATE %s_current SET end_ts = ?, %s"
            " WHERE (end_ts IS NOT NULL AND (end_ts >= ? OR completed_delta_stream_id IS NULL))"
            " AND %s = ?"
        ) % (table, ", ".join(field_sqls), id_col)

        qargs = [end_ts] + list(field_values) + [end_ts, stats_id]

        txn.execute(sql, qargs)

        if txn.rowcount > 0:
            # success.
            return

        # if we're here, it's because we didn't succeed in updating a stats
        # row. Why? Let's find out…

        current_row = self._simple_select_one_txn(
            txn,
            table + "_current",
            {id_col: stats_id},
            ("end_ts", "completed_delta_stream_id"),
            allow_none=True,
        )

        if current_row is None:
            # we need to insert a row! (insert a dirty, incomplete row)
            insertee = {
                id_col: stats_id,
                "end_ts": end_ts,
                "start_ts": ts,
                "completed_delta_stream_id": complete_with_stream_id,
            }

            # we assume that, by default, blank fields should be zero.
            for field_name in ABSOLUTE_STATS_FIELDS[stats_type]:
                insertee[field_name] = 0

            for field_name in PER_SLICE_FIELDS[stats_type]:
                insertee[field_name] = 0

            for (field, value) in fields.items():
                insertee[field] = value

            if absolute_fields is not None:
                for (field, value) in absolute_fields.items():
                    insertee[field] = value

            self._simple_insert_txn(txn, table + "_current", insertee)

        elif current_row["end_ts"] is None:
            # update the row, including start_ts
            sql = (
                "UPDATE %s_current SET start_ts = ?, end_ts = ?, %s"
                " WHERE end_ts IS NULL AND %s = ?"
            ) % (table, ", ".join(field_sqls), id_col)

            qargs = (
                [end_ts - self.stats_bucket_size, end_ts]
                + list(field_values)
                + [stats_id]
            )

            txn.execute(sql, qargs)
            if txn.rowcount == 0:
                raise RuntimeError(
                    "Should be impossible: No rows updated"
                    " but all conditions are known to be met."
                )

        elif current_row["end_ts"] < end_ts:
            # we need to perform old collection first
            raise OldCollectionRequired()
