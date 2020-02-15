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

from twisted.internet import defer
from twisted.internet.defer import DeferredLock

from synapse.api.constants import EventTypes, Membership
from synapse.storage.data_stores.main.state_deltas import StateDeltasStore
from synapse.storage.database import Database
from synapse.storage.engines import PostgresEngine
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
        "local_users_in_room",
    ),
    "user": ("joined_rooms",),
}

# these fields are per-timeslice and so should be reset to 0 upon a new slice
# You can draw these stats on a histogram.
# Example: number of events sent locally during a time slice
PER_SLICE_FIELDS = {
    "room": ("total_events", "total_event_bytes"),
    "user": ("invites_sent", "rooms_created", "total_events", "total_event_bytes"),
}

TYPE_TO_TABLE = {"room": ("room_stats", "room_id"), "user": ("user_stats", "user_id")}

# these are the tables (& ID columns) which contain our actual subjects
TYPE_TO_ORIGIN_TABLE = {"room": ("rooms", "room_id"), "user": ("users", "name")}


class StatsStore(StateDeltasStore):
    def __init__(self, database: Database, db_conn, hs):
        super(StatsStore, self).__init__(database, db_conn, hs)

        self.server_name = hs.hostname
        self.clock = self.hs.get_clock()
        self.stats_enabled = hs.config.stats_enabled
        self.stats_bucket_size = hs.config.stats_bucket_size

        self.stats_delta_processing_lock = DeferredLock()

        self.db.updates.register_background_update_handler(
            "populate_stats_process_rooms", self._populate_stats_process_rooms
        )
        self.db.updates.register_background_update_handler(
            "populate_stats_process_users", self._populate_stats_process_users
        )
        # we no longer need to perform clean-up, but we will give ourselves
        # the potential to reintroduce it in the future – so documentation
        # will still encourage the use of this no-op handler.
        self.db.updates.register_noop_background_update("populate_stats_cleanup")
        self.db.updates.register_noop_background_update("populate_stats_prepare")

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

    @defer.inlineCallbacks
    def _populate_stats_process_users(self, progress, batch_size):
        """
        This is a background update which regenerates statistics for users.
        """
        if not self.stats_enabled:
            yield self.db.updates._end_background_update("populate_stats_process_users")
            return 1

        last_user_id = progress.get("last_user_id", "")

        def _get_next_batch(txn):
            sql = """
                    SELECT DISTINCT name FROM users
                    WHERE name > ?
                    ORDER BY name ASC
                    LIMIT ?
                """
            txn.execute(sql, (last_user_id, batch_size))
            return [r for r, in txn]

        users_to_work_on = yield self.db.runInteraction(
            "_populate_stats_process_users", _get_next_batch
        )

        # No more rooms -- complete the transaction.
        if not users_to_work_on:
            yield self.db.updates._end_background_update("populate_stats_process_users")
            return 1

        for user_id in users_to_work_on:
            yield self._calculate_and_set_initial_state_for_user(user_id)
            progress["last_user_id"] = user_id

        yield self.db.runInteraction(
            "populate_stats_process_users",
            self.db.updates._background_update_progress_txn,
            "populate_stats_process_users",
            progress,
        )

        return len(users_to_work_on)

    @defer.inlineCallbacks
    def _populate_stats_process_rooms(self, progress, batch_size):
        """
        This is a background update which regenerates statistics for rooms.
        """
        if not self.stats_enabled:
            yield self.db.updates._end_background_update("populate_stats_process_rooms")
            return 1

        last_room_id = progress.get("last_room_id", "")

        def _get_next_batch(txn):
            sql = """
                    SELECT DISTINCT room_id FROM current_state_events
                    WHERE room_id > ?
                    ORDER BY room_id ASC
                    LIMIT ?
                """
            txn.execute(sql, (last_room_id, batch_size))
            return [r for r, in txn]

        rooms_to_work_on = yield self.db.runInteraction(
            "populate_stats_rooms_get_batch", _get_next_batch
        )

        # No more rooms -- complete the transaction.
        if not rooms_to_work_on:
            yield self.db.updates._end_background_update("populate_stats_process_rooms")
            return 1

        for room_id in rooms_to_work_on:
            yield self._calculate_and_set_initial_state_for_room(room_id)
            progress["last_room_id"] = room_id

        yield self.db.runInteraction(
            "_populate_stats_process_rooms",
            self.db.updates._background_update_progress_txn,
            "populate_stats_process_rooms",
            progress,
        )

        return len(rooms_to_work_on)

    def get_stats_positions(self):
        """
        Returns the stats processor positions.
        """
        return self.db.simple_select_one_onecol(
            table="stats_incremental_position",
            keyvalues={},
            retcol="stream_id",
            desc="stats_incremental_position",
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

        return self.db.simple_upsert(
            table="room_stats_state",
            keyvalues={"room_id": room_id},
            values=fields,
            desc="update_room_state",
        )

    def get_statistics_for_subject(self, stats_type, stats_id, start, size=100):
        """
        Get statistics for a given subject.

        Args:
            stats_type (str): The type of subject
            stats_id (str): The ID of the subject (e.g. room_id or user_id)
            start (int): Pagination start. Number of entries, not timestamp.
            size (int): How many entries to return.

        Returns:
            Deferred[list[dict]], where the dict has the keys of
            ABSOLUTE_STATS_FIELDS[stats_type],  and "bucket_size" and "end_ts".
        """
        return self.db.runInteraction(
            "get_statistics_for_subject",
            self._get_statistics_for_subject_txn,
            stats_type,
            stats_id,
            start,
            size,
        )

    def _get_statistics_for_subject_txn(
        self, txn, stats_type, stats_id, start, size=100
    ):
        """
        Transaction-bound version of L{get_statistics_for_subject}.
        """

        table, id_col = TYPE_TO_TABLE[stats_type]
        selected_columns = list(
            ABSOLUTE_STATS_FIELDS[stats_type] + PER_SLICE_FIELDS[stats_type]
        )

        slice_list = self.db.simple_select_list_paginate_txn(
            txn,
            table + "_historical",
            "end_ts",
            start,
            size,
            retcols=selected_columns + ["bucket_size", "end_ts"],
            keyvalues={id_col: stats_id},
            order_direction="DESC",
        )

        return slice_list

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

        return self.db.simple_select_one_onecol(
            "%s_current" % (table,),
            keyvalues={id_col: id},
            retcol="completed_delta_stream_id",
            allow_none=True,
        )

    def bulk_update_stats_delta(self, ts, updates, stream_id):
        """Bulk update stats tables for a given stream_id and updates the stats
        incremental position.

        Args:
            ts (int): Current timestamp in ms
            updates(dict[str, dict[str, dict[str, Counter]]]): The updates to
                commit as a mapping stats_type -> stats_id -> field -> delta.
            stream_id (int): Current position.

        Returns:
            Deferred
        """

        def _bulk_update_stats_delta_txn(txn):
            for stats_type, stats_updates in updates.items():
                for stats_id, fields in stats_updates.items():
                    logger.debug(
                        "Updating %s stats for %s: %s", stats_type, stats_id, fields
                    )
                    self._update_stats_delta_txn(
                        txn,
                        ts=ts,
                        stats_type=stats_type,
                        stats_id=stats_id,
                        fields=fields,
                        complete_with_stream_id=stream_id,
                    )

            self.db.simple_update_one_txn(
                txn,
                table="stats_incremental_position",
                keyvalues={},
                updatevalues={"stream_id": stream_id},
            )

        return self.db.runInteraction(
            "bulk_update_stats_delta", _bulk_update_stats_delta_txn
        )

    def update_stats_delta(
        self,
        ts,
        stats_type,
        stats_id,
        fields,
        complete_with_stream_id,
        absolute_field_overrides=None,
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
            absolute_field_overrides (dict[str, int]): Current stats values
                (i.e. not deltas) of absolute fields.
                Does not work with per-slice fields.
        """

        return self.db.runInteraction(
            "update_stats_delta",
            self._update_stats_delta_txn,
            ts,
            stats_type,
            stats_id,
            fields,
            complete_with_stream_id=complete_with_stream_id,
            absolute_field_overrides=absolute_field_overrides,
        )

    def _update_stats_delta_txn(
        self,
        txn,
        ts,
        stats_type,
        stats_id,
        fields,
        complete_with_stream_id,
        absolute_field_overrides=None,
    ):
        if absolute_field_overrides is None:
            absolute_field_overrides = {}

        table, id_col = TYPE_TO_TABLE[stats_type]

        quantised_ts = self.quantise_stats_time(int(ts))
        end_ts = quantised_ts + self.stats_bucket_size

        # Lets be paranoid and check that all the given field names are known
        abs_field_names = ABSOLUTE_STATS_FIELDS[stats_type]
        slice_field_names = PER_SLICE_FIELDS[stats_type]
        for field in chain(fields.keys(), absolute_field_overrides.keys()):
            if field not in abs_field_names and field not in slice_field_names:
                # guard against potential SQL injection dodginess
                raise ValueError(
                    "%s is not a recognised field"
                    " for stats type %s" % (field, stats_type)
                )

        # Per slice fields do not get added to the _current table

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

        # Keep the delta stream ID field up to date
        absolute_field_overrides = absolute_field_overrides.copy()
        absolute_field_overrides["completed_delta_stream_id"] = complete_with_stream_id

        # first upsert the `_current` table
        self._upsert_with_additive_relatives_txn(
            txn=txn,
            table=table + "_current",
            keyvalues={id_col: stats_id},
            absolutes=absolute_field_overrides,
            additive_relatives=deltas_of_absolute_fields,
        )

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
        )

    def _upsert_with_additive_relatives_txn(
        self, txn, table, keyvalues, absolutes, additive_relatives
    ):
        """Used to update values in the stats tables.

        This is basically a slightly convoluted upsert that *adds* to any
        existing rows.

        Args:
            txn
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
            current_row = self.db.simple_select_one_txn(
                txn, table, keyvalues, retcols, allow_none=True
            )
            if current_row is None:
                merged_dict = {**keyvalues, **absolutes, **additive_relatives}
                self.db.simple_insert_txn(txn, table, merged_dict)
            else:
                for (key, val) in additive_relatives.items():
                    current_row[key] += val
                current_row.update(absolutes)
                self.db.simple_update_one_txn(txn, table, keyvalues, current_row)

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
    ):
        """Updates the historic stats table with latest updates.

        This involves copying "absolute" fields from the `_current` table, and
        adding relative fields to any existing values.

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
                WHERE %(keyvalues_where)s
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
            src_row = self.db.simple_select_one_txn(
                txn, src_table, keyvalues, copy_columns
            )
            all_dest_keyvalues = {**keyvalues, **extra_dst_keyvalues}
            dest_current_row = self.db.simple_select_one_txn(
                txn,
                into_table,
                keyvalues=all_dest_keyvalues,
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
                self.db.simple_insert_txn(txn, into_table, merged_dict)
            else:
                for (key, val) in additive_relatives.items():
                    src_row[key] = dest_current_row[key] + val
                self.db.simple_update_txn(txn, into_table, all_dest_keyvalues, src_row)

    def get_changes_room_total_events_and_bytes(self, min_pos, max_pos):
        """Fetches the counts of events in the given range of stream IDs.

        Args:
            min_pos (int)
            max_pos (int)

        Returns:
            Deferred[dict[str, dict[str, int]]]: Mapping of room ID to field
            changes.
        """

        return self.db.runInteraction(
            "stats_incremental_total_events_and_bytes",
            self.get_changes_room_total_events_and_bytes_txn,
            min_pos,
            max_pos,
        )

    def get_changes_room_total_events_and_bytes_txn(self, txn, low_pos, high_pos):
        """Gets the total_events and total_event_bytes counts for rooms and
        senders, in a range of stream_orderings (including backfilled events).

        Args:
            txn
            low_pos (int): Low stream ordering
            high_pos (int): High stream ordering

        Returns:
            tuple[dict[str, dict[str, int]], dict[str, dict[str, int]]]: The
            room and user deltas for total_events/total_event_bytes in the
            format of `stats_id` -> fields
        """

        if low_pos >= high_pos:
            # nothing to do here.
            return {}, {}

        if isinstance(self.database_engine, PostgresEngine):
            new_bytes_expression = "OCTET_LENGTH(json)"
        else:
            new_bytes_expression = "LENGTH(CAST(json AS BLOB))"

        sql = """
            SELECT events.room_id, COUNT(*) AS new_events, SUM(%s) AS new_bytes
            FROM events INNER JOIN event_json USING (event_id)
            WHERE (? < stream_ordering AND stream_ordering <= ?)
                OR (? <= stream_ordering AND stream_ordering <= ?)
            GROUP BY events.room_id
        """ % (
            new_bytes_expression,
        )

        txn.execute(sql, (low_pos, high_pos, -high_pos, -low_pos))

        room_deltas = {
            room_id: {"total_events": new_events, "total_event_bytes": new_bytes}
            for room_id, new_events, new_bytes in txn
        }

        sql = """
            SELECT events.sender, COUNT(*) AS new_events, SUM(%s) AS new_bytes
            FROM events INNER JOIN event_json USING (event_id)
            WHERE (? < stream_ordering AND stream_ordering <= ?)
                OR (? <= stream_ordering AND stream_ordering <= ?)
            GROUP BY events.sender
        """ % (
            new_bytes_expression,
        )

        txn.execute(sql, (low_pos, high_pos, -high_pos, -low_pos))

        user_deltas = {
            user_id: {"total_events": new_events, "total_event_bytes": new_bytes}
            for user_id, new_events, new_bytes in txn
            if self.hs.is_mine_id(user_id)
        }

        return room_deltas, user_deltas

    @defer.inlineCallbacks
    def _calculate_and_set_initial_state_for_room(self, room_id):
        """Calculate and insert an entry into room_stats_current.

        Args:
            room_id (str)

        Returns:
            Deferred[tuple[dict, dict, int]]: A tuple of room state, membership
            counts and stream position.
        """

        def _fetch_current_state_stats(txn):
            pos = self.get_room_max_stream_ordering()

            rows = self.db.simple_select_many_txn(
                txn,
                table="current_state_events",
                column="type",
                iterable=[
                    EventTypes.Create,
                    EventTypes.JoinRules,
                    EventTypes.RoomHistoryVisibility,
                    EventTypes.RoomEncryption,
                    EventTypes.Name,
                    EventTypes.Topic,
                    EventTypes.RoomAvatar,
                    EventTypes.CanonicalAlias,
                ],
                keyvalues={"room_id": room_id, "state_key": ""},
                retcols=["event_id"],
            )

            event_ids = [row["event_id"] for row in rows]

            txn.execute(
                """
                    SELECT membership, count(*) FROM current_state_events
                    WHERE room_id = ? AND type = 'm.room.member'
                    GROUP BY membership
                """,
                (room_id,),
            )
            membership_counts = {membership: cnt for membership, cnt in txn}

            txn.execute(
                """
                    SELECT COALESCE(count(*), 0) FROM current_state_events
                    WHERE room_id = ?
                """,
                (room_id,),
            )

            (current_state_events_count,) = txn.fetchone()

            users_in_room = self.get_users_in_room_txn(txn, room_id)

            return (
                event_ids,
                membership_counts,
                current_state_events_count,
                users_in_room,
                pos,
            )

        (
            event_ids,
            membership_counts,
            current_state_events_count,
            users_in_room,
            pos,
        ) = yield self.db.runInteraction(
            "get_initial_state_for_room", _fetch_current_state_stats
        )

        state_event_map = yield self.get_events(event_ids, get_prev_content=False)

        room_state = {
            "join_rules": None,
            "history_visibility": None,
            "encryption": None,
            "name": None,
            "topic": None,
            "avatar": None,
            "canonical_alias": None,
            "is_federatable": True,
        }

        for event in state_event_map.values():
            if event.type == EventTypes.JoinRules:
                room_state["join_rules"] = event.content.get("join_rule")
            elif event.type == EventTypes.RoomHistoryVisibility:
                room_state["history_visibility"] = event.content.get(
                    "history_visibility"
                )
            elif event.type == EventTypes.RoomEncryption:
                room_state["encryption"] = event.content.get("algorithm")
            elif event.type == EventTypes.Name:
                room_state["name"] = event.content.get("name")
            elif event.type == EventTypes.Topic:
                room_state["topic"] = event.content.get("topic")
            elif event.type == EventTypes.RoomAvatar:
                room_state["avatar"] = event.content.get("url")
            elif event.type == EventTypes.CanonicalAlias:
                room_state["canonical_alias"] = event.content.get("alias")
            elif event.type == EventTypes.Create:
                room_state["is_federatable"] = (
                    event.content.get("m.federate", True) is True
                )

        yield self.update_room_state(room_id, room_state)

        local_users_in_room = [u for u in users_in_room if self.hs.is_mine_id(u)]

        yield self.update_stats_delta(
            ts=self.clock.time_msec(),
            stats_type="room",
            stats_id=room_id,
            fields={},
            complete_with_stream_id=pos,
            absolute_field_overrides={
                "current_state_events": current_state_events_count,
                "joined_members": membership_counts.get(Membership.JOIN, 0),
                "invited_members": membership_counts.get(Membership.INVITE, 0),
                "left_members": membership_counts.get(Membership.LEAVE, 0),
                "banned_members": membership_counts.get(Membership.BAN, 0),
                "local_users_in_room": len(local_users_in_room),
            },
        )

    @defer.inlineCallbacks
    def _calculate_and_set_initial_state_for_user(self, user_id):
        def _calculate_and_set_initial_state_for_user_txn(txn):
            pos = self._get_max_stream_id_in_current_state_deltas_txn(txn)

            txn.execute(
                """
                SELECT COUNT(distinct room_id) FROM current_state_events
                    WHERE type = 'm.room.member' AND state_key = ?
                        AND membership = 'join'
                """,
                (user_id,),
            )
            (count,) = txn.fetchone()
            return count, pos

        joined_rooms, pos = yield self.db.runInteraction(
            "calculate_and_set_initial_state_for_user",
            _calculate_and_set_initial_state_for_user_txn,
        )

        yield self.update_stats_delta(
            ts=self.clock.time_msec(),
            stats_type="user",
            stats_id=user_id,
            fields={},
            complete_with_stream_id=pos,
            absolute_field_overrides={"joined_rooms": joined_rooms},
        )
