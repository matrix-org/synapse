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
from itertools import chain

from twisted.internet.defer import DeferredLock

from synapse.storage import PostgresEngine
from synapse.storage.state_deltas import StateDeltasStore
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)

# these fields track absolutes (e.g. total number of rooms on the server)
# You can think of these as Prometheus Gauges.
# You can draw these stats on a line graph.
# Example: number of users in a room
ABSOLUTE_STATS_FIELDS = {
    "room": (
        "current_state_events",
        "joined_members",
        "invited_members",
        "left_members",
        "banned_members",
        "total_events",
        "total_event_bytes",
    ),
    "user": ("public_rooms", "private_rooms"),
}

# these fields are per-timeslice and so should be reset to 0 upon a new slice
# You can draw these stats on a histogram.
# Example: number of events sent locally during a time slice
PER_SLICE_FIELDS = {"room": (), "user": ()}

TYPE_TO_TABLE = {"room": ("room_stats", "room_id"), "user": ("user_stats", "user_id")}


class StatsStore(StateDeltasStore):
    def __init__(self, db_conn, hs):
        super(StatsStore, self).__init__(db_conn, hs)

        self.server_name = hs.hostname
        self.clock = self.hs.get_clock()
        self.stats_enabled = hs.config.stats_enabled
        self.stats_bucket_size = hs.config.stats_bucket_size

        self.stats_delta_processing_lock = DeferredLock()

        self.register_noop_background_update("populate_stats_createtables")
        self.register_noop_background_update("populate_stats_process_rooms")
        self.register_noop_background_update("populate_stats_cleanup")

    def quantise_stats_time(self, ts):
        """
        Quantises a timestamp to be a multiple of the bucket size.

        Args:
            ts (int): the timestamp to quantise, in milliseconds since the Unix
                Epoch

        Returns:
            int: a timestamp which
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
            table="room_stats_state",
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

        return self.runInteraction(
            "update_stats_delta",
            self._update_stats_delta_txn,
            ts,
            stats_type,
            stats_id,
            fields,
            complete_with_stream_id=complete_with_stream_id,
        )

    def _update_stats_delta_txn(
        self,
        txn,
        ts,
        stats_type,
        stats_id,
        fields,
        complete_with_stream_id=None,
        absolute_field_overrides=None,
    ):
        """
        See L{update_stats_delta}
        Additional Args:
            absolute_field_overrides (dict[str, int]): Current stats values
                (i.e. not deltas) of absolute fields.
                Does not work with per-slice fields.
        """

        if absolute_field_overrides is None:
            absolute_field_overrides = {}

        table, id_col = TYPE_TO_TABLE[stats_type]

        quantised_ts = self.quantise_stats_time(int(ts))
        end_ts = quantised_ts + self.stats_bucket_size

        abs_field_names = ABSOLUTE_STATS_FIELDS[stats_type]
        slice_field_names = PER_SLICE_FIELDS[stats_type]
        for field in chain(fields.keys(), absolute_field_overrides.keys()):
            if field not in abs_field_names and field not in slice_field_names:
                # guard against potential SQL injection dodginess
                raise ValueError(
                    "%s is not a recognised field"
                    " for stats type %s" % (field, stats_type)
                )

        # only absolute stats fields are tracked in the `_current` stats tables,
        # so those are the only ones that we process deltas for when
        # we upsert against the `_current` table.

        # This calculates the deltas (`field = field + ?` values)
        # for absolute fields,
        # * defaulting to 0 if not specified
        #     (required for the INSERT part of upserting to work)
        # * omitting overrides specified in `absolute_field_overrides`
        deltas_of_absolute_fields = {
            key: fields.get(key, 0)
            for key in abs_field_names
            if key not in absolute_field_overrides
        }

        if complete_with_stream_id is not None:
            absolute_field_overrides = absolute_field_overrides.copy()
            absolute_field_overrides[
                "completed_delta_stream_id"
            ] = complete_with_stream_id

        # first upsert the `_current` table
        self._upsert_with_additive_relatives_txn(
            txn=txn,
            table=table + "_current",
            keyvalues={id_col: stats_id},
            absolutes=absolute_field_overrides,
            additive_relatives=deltas_of_absolute_fields,
        )

        if self.has_completed_background_updates():
            # TODO want to check specifically for stats regenerator, not all
            #   background updates…
            # then upsert the `_historical` table.
            # we don't support absolute_fields for per-slice fields as it makes
            # no sense.
            per_slice_additive_relatives = {
                key: fields.get(key, 0) for key in slice_field_names
            }
            self._upsert_copy_from_table_with_additive_relatives_txn(
                txn=txn,
                into_table=table + "_historical",
                keyvalues={id_col: stats_id},
                extra_dst_insvalues={"bucket_size": self.stats_bucket_size},
                extra_dst_keyvalues={"end_ts": end_ts},
                additive_relatives=per_slice_additive_relatives,
                src_table=table + "_current",
                copy_columns=abs_field_names,
                additional_where=" AND completed_delta_stream_id IS NOT NULL",
            )

    def _upsert_with_additive_relatives_txn(
        self, txn, table, keyvalues, absolutes, additive_relatives
    ):
        """Used to update values in the stats tables.

        Args:
            txn: Transaction
            table (str): Table name
            keyvalues (dict[str, any]): Row-identifying key values
            absolutes (dict[str, any]): Absolute (set) fields
            additive_relatives (dict[str, int]): Fields that will be added onto
                if existing row present.
        """
        if self.database_engine.can_native_upsert:
            absolute_updates = [
                "%(field)s = EXCLUDED.%(field)s" % {"field": field}
                for field in absolutes.keys()
            ]

            relative_updates = [
                "%(field)s = EXCLUDED.%(field)s + %(table)s.%(field)s"
                % {"table": table, "field": field}
                for field in additive_relatives.keys()
            ]

            insert_cols = []
            qargs = []

            for (key, val) in chain(
                keyvalues.items(), absolutes.items(), additive_relatives.items()
            ):
                insert_cols.append(key)
                qargs.append(val)

            sql = """
                INSERT INTO %(table)s (%(insert_cols_cs)s)
                VALUES (%(insert_vals_qs)s)
                ON CONFLICT (%(key_columns)s) DO UPDATE SET %(updates)s
            """ % {
                "table": table,
                "insert_cols_cs": ", ".join(insert_cols),
                "insert_vals_qs": ", ".join(
                    ["?"] * (len(keyvalues) + len(absolutes) + len(additive_relatives))
                ),
                "key_columns": ", ".join(keyvalues),
                "updates": ", ".join(chain(absolute_updates, relative_updates)),
            }

            txn.execute(sql, qargs)
        else:
            self.database_engine.lock_table(txn, table)
            retcols = list(chain(absolutes.keys(), additive_relatives.keys()))
            current_row = self._simple_select_one_txn(
                txn, table, keyvalues, retcols, allow_none=True
            )
            if current_row is None:
                merged_dict = {**keyvalues, **absolutes, **additive_relatives}
                self._simple_insert_txn(txn, table, merged_dict)
            else:
                for (key, val) in additive_relatives.items():
                    current_row[key] += val
                current_row.update(absolutes)
                self._simple_update_one_txn(txn, table, keyvalues, current_row)

    def _upsert_copy_from_table_with_additive_relatives_txn(
        self,
        txn,
        into_table,
        keyvalues,
        extra_dst_keyvalues,
        extra_dst_insvalues,
        additive_relatives,
        src_table,
        copy_columns,
        additional_where="",
    ):
        """
        Args:
             txn: Transaction
             into_table (str): The destination table to UPSERT the row into
             keyvalues (dict[str, any]): Row-identifying key values
             extra_dst_keyvalues (dict[str, any]): Additional keyvalues
                for `into_table`.
             extra_dst_insvalues (dict[str, any]): Additional values to insert
                on new row creation for `into_table`.
             additive_relatives (dict[str, any]): Fields that will be added onto
                if existing row present. (Must be disjoint from copy_columns.)
             src_table (str): The source table to copy from
             copy_columns (iterable[str]): The list of columns to copy
             additional_where (str): Additional SQL for where (prefix with AND
                if using).
        """
        if self.database_engine.can_native_upsert:
            ins_columns = chain(
                keyvalues,
                copy_columns,
                additive_relatives,
                extra_dst_keyvalues,
                extra_dst_insvalues,
            )
            sel_exprs = chain(
                keyvalues,
                copy_columns,
                (
                    "?"
                    for _ in chain(
                        additive_relatives, extra_dst_keyvalues, extra_dst_insvalues
                    )
                ),
            )
            keyvalues_where = ("%s = ?" % f for f in keyvalues)

            sets_cc = ("%s = EXCLUDED.%s" % (f, f) for f in copy_columns)
            sets_ar = (
                "%s = EXCLUDED.%s + %s.%s" % (f, f, into_table, f)
                for f in additive_relatives
            )

            sql = """
                INSERT INTO %(into_table)s (%(ins_columns)s)
                SELECT %(sel_exprs)s
                FROM %(src_table)s
                WHERE %(keyvalues_where)s %(additional_where)s
                ON CONFLICT (%(keyvalues)s)
                DO UPDATE SET %(sets)s
            """ % {
                "into_table": into_table,
                "ins_columns": ", ".join(ins_columns),
                "sel_exprs": ", ".join(sel_exprs),
                "keyvalues_where": " AND ".join(keyvalues_where),
                "src_table": src_table,
                "keyvalues": ", ".join(
                    chain(keyvalues.keys(), extra_dst_keyvalues.keys())
                ),
                "sets": ", ".join(chain(sets_cc, sets_ar)),
                "additional_where": additional_where,
            }

            qargs = list(
                chain(
                    additive_relatives.values(),
                    extra_dst_keyvalues.values(),
                    extra_dst_insvalues.values(),
                    keyvalues.values(),
                )
            )
            txn.execute(sql, qargs)
        else:
            self.database_engine.lock_table(txn, into_table)
            src_row = self._simple_select_one_txn(
                txn, src_table, keyvalues, copy_columns
            )
            dest_current_row = self._simple_select_one_txn(
                txn,
                into_table,
                keyvalues,
                retcols=list(chain(additive_relatives.keys(), copy_columns)),
                allow_none=True,
            )

            if dest_current_row is None:
                merged_dict = {
                    **keyvalues,
                    **extra_dst_keyvalues,
                    **extra_dst_insvalues,
                    **src_row,
                    **additive_relatives,
                }
                self._simple_insert_txn(txn, into_table, merged_dict)
            else:
                for (key, val) in additive_relatives.items():
                    src_row[key] = dest_current_row[key] + val
                self._simple_update_txn(txn, into_table, keyvalues, src_row)

    def incremental_update_room_total_events_and_bytes(self, in_positions):
        """
        Counts the number of events and total event bytes per-room and then adds
        these to the respective total_events and total_event_bytes room counts.

        Args:
            in_positions (dict): Positions,
                as retrieved from L{get_stats_positions}.

        Returns (Deferred[tuple[dict, bool]]):
            First element (dict):
                The new positions. Note that this is for reference only –
                the new positions WILL be committed by this function.
            Second element (bool):
                true iff there was a change to the positions, false otherwise
        """

        def incremental_update_total_events_and_bytes_txn(txn):
            positions = in_positions.copy()

            max_pos = self.get_room_max_stream_ordering()
            min_pos = self.get_room_min_stream_ordering()
            self.update_total_event_and_bytes_count_between_txn(
                txn,
                low_pos=positions["total_events_max_stream_ordering"],
                high_pos=max_pos,
            )

            self.update_total_event_and_bytes_count_between_txn(
                txn,
                low_pos=min_pos,
                high_pos=positions["total_events_min_stream_ordering"],
            )

            if (
                positions["total_events_max_stream_ordering"] != max_pos
                or positions["total_events_min_stream_ordering"] != min_pos
            ):
                positions["total_events_max_stream_ordering"] = max_pos
                positions["total_events_min_stream_ordering"] = min_pos

                self._update_stats_positions_txn(txn, positions)

                return positions, True
            else:
                return positions, False

        return self.runInteraction(
            "stats_incremental_total_events_and_bytes",
            incremental_update_total_events_and_bytes_txn,
        )

    def update_total_event_and_bytes_count_between_txn(self, txn, low_pos, high_pos):
        """
        Updates the total_events and total_event_bytes counts for rooms,
            in a range of stream_orderings.

        Inclusivity of low_pos and high_pos is dependent upon their signs.
        This makes it intuitive to use this function for both backfilled
        and non-backfilled events.

        Examples:
        (low, high) → (kind)
        (3, 7) → 3 < … <= 7 (normal-filled; low already processed before)
        (-4, -2) → -4 <= … < -2 (backfilled; high already processed before)
        (-7, 7) → -7 <= … <= 7 (both)

        Args:
            txn: Database transaction.
            low_pos: Low stream ordering
            high_pos: High stream ordering
        """

        if low_pos >= high_pos:
            # nothing to do here.
            return

        now = self.hs.clock.time_msec()

        # we choose comparators based on the signs
        low_comparator = "<=" if low_pos < 0 else "<"
        high_comparator = "<" if high_pos < 0 else "<="

        if isinstance(self.database_engine, PostgresEngine):
            new_bytes_expression = "OCTET_LENGTH(json)"
        else:
            new_bytes_expression = "LENGTH(CAST(json AS BLOB))"

        sql = """
            SELECT room_id, COUNT(*) AS new_events, SUM(%s) AS new_bytes
            FROM events INNER JOIN event_json USING (event_id)
            WHERE ? %s stream_ordering AND stream_ordering %s ?
            GROUP BY room_id
        """ % (
            low_comparator,
            high_comparator,
            new_bytes_expression,
        )

        txn.execute(sql, (low_pos, high_pos))

        for room_id, new_events, new_bytes in txn.fetchall():
            self._update_stats_delta_txn(
                txn,
                now,
                "room",
                room_id,
                {"total_events": new_events, "total_event_bytes": new_bytes},
            )
