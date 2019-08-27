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

from synapse.storage.state_deltas import StateDeltasStore

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

        self.register_noop_background_update("populate_stats_createtables")
        self.register_noop_background_update("populate_stats_process_rooms")
        self.register_noop_background_update("populate_stats_cleanup")

    def quantise_stats_time(self, ts):
        """
        Quantises a timestamp to be a multiple of the bucket size.

        Args:
            ts (int): the timestamp to quantise, in seconds since the Unix Epoch

        Returns:
            int: a timestamp which
              - is divisible by the bucket size;
              - is no later than `ts`; and
              - is the largest such timestamp.
        """
        return (ts // self.stats_bucket_size) * self.stats_bucket_size

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
            qargs = [table]

            for (key, val) in chain(
                keyvalues.items(), absolutes.items(), additive_relatives.items()
            ):
                insert_cols.append(key)
                qargs.append(val)

            sql = """
                INSERT INTO %(table)s (%(insert_cols_cs)s)
                VALUES (%(insert_vals_qs)s)
                ON CONFLICT DO UPDATE SET %(updates)s
            """ % {
                "table": table,
                "insert_cols_cs": ", ".join(insert_cols),
                "insert_vals_qs": ", ".join(
                    ["?"] * (len(keyvalues) + len(absolutes) + len(additive_relatives))
                ),
                "updates": ", ".join(chain(absolute_updates, relative_updates)),
            }

            txn.execute(sql, qargs)
        else:
            self.database_engine.lock_table(txn, table)
            retcols = chain(absolutes.keys(), additive_relatives.keys())
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
             additive_relatives (dict[str, any]): Fields that will be added onto
                if existing row present. (Must be disjoint from copy_columns.)
             src_table (str): The source table to copy from
             copy_columns (iterable[str]): The list of columns to copy
             additional_where (str): Additional SQL for where (prefix with AND
                if using).
        """
        if self.database_engine.can_native_upsert:
            ins_columns = chain(
                keyvalues, copy_columns, additive_relatives, extra_dst_keyvalues
            )
            sel_exprs = chain(
                keyvalues,
                copy_columns,
                ("?" for _ in chain(additive_relatives, extra_dst_keyvalues)),
            )
            keyvalues_where = ("%s = ?" % f for f in keyvalues)

            sets_cc = ("%s = EXCLUDED.%s" % (f, f) for f in copy_columns)
            sets_ar = (
                "%s = EXCLUDED.%s + %s.%s" % (f, f, into_table, f) for f in copy_columns
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

            qargs = chain(additive_relatives.values(), keyvalues.values())
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
                chain(additive_relatives.keys(), copy_columns),
                allow_none=True,
            )

            if dest_current_row is None:
                merged_dict = {**keyvalues, **src_row, **additive_relatives}
                self._simple_insert_txn(txn, into_table, merged_dict)
            else:
                for (key, val) in additive_relatives.items():
                    src_row[key] = dest_current_row[key] + val
                self._simple_update_txn(txn, into_table, keyvalues, src_row)

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
            absolute_fields (dict[str, int]): Absolute current stats values
                (i.e. not deltas). Does not work with per-slice fields.
        """
        table, id_col = TYPE_TO_TABLE[stats_type]

        quantised_ts = self.quantise_stats_time(int(ts))
        end_ts = quantised_ts + self.stats_bucket_size

        abs_field_names = ABSOLUTE_STATS_FIELDS[stats_type]
        slice_field_names = PER_SLICE_FIELDS[stats_type]
        for field in chain(fields.keys(), absolute_fields.keys()):
            if field not in abs_field_names and field not in slice_field_names:
                # guard against potential SQL injection dodginess
                raise ValueError(
                    "%s is not a recognised field"
                    " for stats type %s" % (field, stats_type)
                )

        # only absolute stats fields are tracked in the `_current` stats tables,
        # so those are the only ones that we process deltas for when
        # we upsert against the `_current` table.
        additive_relatives = {
            key: fields.get(key, 0)
            for key in abs_field_names
            if key not in absolute_fields
        }

        if absolute_fields is None:
            absolute_fields = {}
        elif complete_with_stream_id is not None:
            absolute_fields = absolute_fields.copy()
            absolute_fields["completed_delta_stream_id"] = complete_with_stream_id

        # first upsert the `_current` table
        self._upsert_with_additive_relatives_txn(
            txn=txn,
            table=table + "_current",
            keyvalues={id_col: stats_id},
            absolutes=absolute_fields,
            additive_relatives=additive_relatives,
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
                extra_dst_keyvalues={
                    "end_ts": end_ts,
                    "bucket_size": self.stats_bucket_size,
                },
                additive_relatives=per_slice_additive_relatives,
                src_table=table + "_current",
                copy_columns=abs_field_names,
                additional_where=" AND completed_delta_stream_id IS NOT NULL",
            )
