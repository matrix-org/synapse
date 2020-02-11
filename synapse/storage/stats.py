# -*- coding: utf-8 -*-
# Copyright 2018, 2019 New Vector Ltd
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

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.storage.prepare_database import get_statements
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
        "state_events",
    ),
    "user": ("public_rooms", "private_rooms"),
}

TYPE_TO_ROOM = {"room": ("room_stats", "room_id"), "user": ("user_stats", "user_id")}

TEMP_TABLE = "_temp_populate_stats"


class StatsStore(StateDeltasStore):
    def __init__(self, db_conn, hs):
        super(StatsStore, self).__init__(db_conn, hs)

        self.server_name = hs.hostname
        self.clock = self.hs.get_clock()
        self.stats_enabled = hs.config.stats_enabled
        self.stats_bucket_size = hs.config.stats_bucket_size

        self.register_background_update_handler(
            "populate_stats_createtables", self._populate_stats_createtables
        )
        self.register_background_update_handler(
            "populate_stats_process_rooms", self._populate_stats_process_rooms
        )
        self.register_background_update_handler(
            "populate_stats_cleanup", self._populate_stats_cleanup
        )

    @defer.inlineCallbacks
    def _populate_stats_createtables(self, progress, batch_size):

        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_createtables")
            defer.returnValue(1)

        # Get all the rooms that we want to process.
        def _make_staging_area(txn):
            # Create the temporary tables
            stmts = get_statements(
                """
                -- We just recreate the table, we'll be reinserting the
                -- correct entries again later anyway.
                DROP TABLE IF EXISTS {temp}_rooms;

                CREATE TABLE IF NOT EXISTS {temp}_rooms(
                    room_id TEXT NOT NULL,
                    events BIGINT NOT NULL
                );

                CREATE INDEX {temp}_rooms_events
                    ON {temp}_rooms(events);
                CREATE INDEX {temp}_rooms_id
                    ON {temp}_rooms(room_id);
            """.format(
                    temp=TEMP_TABLE
                ).splitlines()
            )

            for statement in stmts:
                txn.execute(statement)

            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_position(position TEXT NOT NULL)"
            )
            txn.execute(sql)

            # Get rooms we want to process from the database, only adding
            # those that we haven't (i.e. those not in room_stats_earliest_token)
            sql = """
                INSERT INTO %s_rooms (room_id, events)
                SELECT c.room_id, count(*) FROM current_state_events AS c
                LEFT JOIN room_stats_earliest_token AS t USING (room_id)
                WHERE t.room_id IS NULL
                GROUP BY c.room_id
            """ % (
                TEMP_TABLE,
            )
            txn.execute(sql)

        new_pos = yield self.get_max_stream_id_in_current_state_deltas()
        yield self.runInteraction("populate_stats_temp_build", _make_staging_area)
        yield self._simple_insert(TEMP_TABLE + "_position", {"position": new_pos})
        self.get_earliest_token_for_room_stats.invalidate_all()

        yield self._end_background_update("populate_stats_createtables")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_stats_cleanup(self, progress, batch_size):
        """
        Update the user directory stream position, then clean up the old tables.
        """
        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_cleanup")
            defer.returnValue(1)

        position = yield self._simple_select_one_onecol(
            TEMP_TABLE + "_position", None, "position"
        )
        yield self.update_stats_stream_pos(position)

        def _delete_staging_area(txn):
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_rooms")
            txn.execute("DROP TABLE IF EXISTS " + TEMP_TABLE + "_position")

        yield self.runInteraction("populate_stats_cleanup", _delete_staging_area)

        yield self._end_background_update("populate_stats_cleanup")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_stats_process_rooms(self, progress, batch_size):

        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_process_rooms")
            defer.returnValue(1)

        # If we don't have progress filed, delete everything.
        if not progress:
            yield self.delete_all_stats()

        def _get_next_batch(txn):
            # Only fetch 250 rooms, so we don't fetch too many at once, even
            # if those 250 rooms have less than batch_size state events.
            sql = """
                SELECT room_id, events FROM %s_rooms
                ORDER BY events DESC
                LIMIT 250
            """ % (
                TEMP_TABLE,
            )
            txn.execute(sql)
            rooms_to_work_on = txn.fetchall()

            if not rooms_to_work_on:
                return None

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            txn.execute("SELECT COUNT(*) FROM " + TEMP_TABLE + "_rooms")
            progress["remaining"] = txn.fetchone()[0]

            return rooms_to_work_on

        rooms_to_work_on = yield self.runInteraction(
            "populate_stats_temp_read", _get_next_batch
        )

        # No more rooms -- complete the transaction.
        if not rooms_to_work_on:
            yield self._end_background_update("populate_stats_process_rooms")
            defer.returnValue(1)

        logger.info(
            "Processing the next %d rooms of %d remaining",
            len(rooms_to_work_on),
            progress["remaining"],
        )

        # Number of state events we've processed by going through each room
        processed_event_count = 0

        for room_id, event_count in rooms_to_work_on:

            current_state_ids = yield self.get_current_state_ids(room_id)

            join_rules_id = current_state_ids.get((EventTypes.JoinRules, ""))
            history_visibility_id = current_state_ids.get(
                (EventTypes.RoomHistoryVisibility, "")
            )
            encryption_id = current_state_ids.get((EventTypes.RoomEncryption, ""))
            name_id = current_state_ids.get((EventTypes.Name, ""))
            topic_id = current_state_ids.get((EventTypes.Topic, ""))
            avatar_id = current_state_ids.get((EventTypes.RoomAvatar, ""))
            canonical_alias_id = current_state_ids.get((EventTypes.CanonicalAlias, ""))

            state_events = yield self.get_events(
                [
                    join_rules_id,
                    history_visibility_id,
                    encryption_id,
                    name_id,
                    topic_id,
                    avatar_id,
                    canonical_alias_id,
                ]
            )

            def _get_or_none(event_id, arg):
                event = state_events.get(event_id)
                if event:
                    return event.content.get(arg)
                return None

            yield self.update_room_state(
                room_id,
                {
                    "join_rules": _get_or_none(join_rules_id, "join_rule"),
                    "history_visibility": _get_or_none(
                        history_visibility_id, "history_visibility"
                    ),
                    "encryption": _get_or_none(encryption_id, "algorithm"),
                    "name": _get_or_none(name_id, "name"),
                    "topic": _get_or_none(topic_id, "topic"),
                    "avatar": _get_or_none(avatar_id, "url"),
                    "canonical_alias": _get_or_none(canonical_alias_id, "alias"),
                },
            )

            now = self.hs.get_reactor().seconds()

            # quantise time to the nearest bucket
            now = (now // self.stats_bucket_size) * self.stats_bucket_size

            def _fetch_data(txn):

                # Get the current token of the room
                current_token = self._get_max_stream_id_in_current_state_deltas_txn(txn)

                current_state_events = len(current_state_ids)

                membership_counts = self._get_user_counts_in_room_txn(txn, room_id)

                total_state_events = self._get_total_state_event_counts_txn(
                    txn, room_id
                )

                self._update_stats_txn(
                    txn,
                    "room",
                    room_id,
                    now,
                    {
                        "bucket_size": self.stats_bucket_size,
                        "current_state_events": current_state_events,
                        "joined_members": membership_counts.get(Membership.JOIN, 0),
                        "invited_members": membership_counts.get(Membership.INVITE, 0),
                        "left_members": membership_counts.get(Membership.LEAVE, 0),
                        "banned_members": membership_counts.get(Membership.BAN, 0),
                        "state_events": total_state_events,
                    },
                )
                self._simple_insert_txn(
                    txn,
                    "room_stats_earliest_token",
                    {"room_id": room_id, "token": current_token},
                )

                # We've finished a room. Delete it from the table.
                self._simple_delete_one_txn(
                    txn, TEMP_TABLE + "_rooms", {"room_id": room_id}
                )

            yield self.runInteraction("update_room_stats", _fetch_data)

            # Update the remaining counter.
            progress["remaining"] -= 1
            yield self.runInteraction(
                "populate_stats",
                self._background_update_progress_txn,
                "populate_stats_process_rooms",
                progress,
            )

            processed_event_count += event_count

            if processed_event_count > batch_size:
                # Don't process any more rooms, we've hit our batch size.
                defer.returnValue(processed_event_count)

        defer.returnValue(processed_event_count)

    def delete_all_stats(self):
        """
        Delete all statistics records.
        """

        def _delete_all_stats_txn(txn):
            txn.execute("DELETE FROM room_state")
            txn.execute("DELETE FROM room_stats")
            txn.execute("DELETE FROM room_stats_earliest_token")
            txn.execute("DELETE FROM user_stats")

        return self.runInteraction("delete_all_stats", _delete_all_stats_txn)

    def get_stats_stream_pos(self):
        return self._simple_select_one_onecol(
            table="stats_stream_pos",
            keyvalues={},
            retcol="stream_id",
            desc="stats_stream_pos",
        )

    def update_stats_stream_pos(self, stream_id):
        return self._simple_update_one(
            table="stats_stream_pos",
            keyvalues={},
            updatevalues={"stream_id": stream_id},
            desc="update_stats_stream_pos",
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

    def get_deltas_for_room(self, room_id, start, size=100):
        """
        Get statistics deltas for a given room.

        Args:
            room_id (str)
            start (int): Pagination start. Number of entries, not timestamp.
            size (int): How many entries to return.

        Returns:
            Deferred[list[dict]], where the dict has the keys of
            ABSOLUTE_STATS_FIELDS["room"] and "ts".
        """
        return self._simple_select_list_paginate(
            "room_stats",
            {"room_id": room_id},
            "ts",
            start,
            size,
            retcols=(list(ABSOLUTE_STATS_FIELDS["room"]) + ["ts"]),
            order_direction="DESC",
        )

    def get_all_room_state(self):
        return self._simple_select_list(
            "room_state", None, retcols=("name", "topic", "canonical_alias")
        )

    @cached()
    def get_earliest_token_for_room_stats(self, room_id):
        """
        Fetch the "earliest token". This is used by the room stats delta
        processor to ignore deltas that have been processed between the
        start of the background task and any particular room's stats
        being calculated.

        Returns:
            Deferred[int]
        """
        return self._simple_select_one_onecol(
            "room_stats_earliest_token",
            {"room_id": room_id},
            retcol="token",
            allow_none=True,
        )

    def update_stats(self, stats_type, stats_id, ts, fields):
        table, id_col = TYPE_TO_ROOM[stats_type]
        return self._simple_upsert(
            table=table,
            keyvalues={id_col: stats_id, "ts": ts},
            values=fields,
            desc="update_stats",
        )

    def _update_stats_txn(self, txn, stats_type, stats_id, ts, fields):
        table, id_col = TYPE_TO_ROOM[stats_type]
        return self._simple_upsert_txn(
            txn, table=table, keyvalues={id_col: stats_id, "ts": ts}, values=fields
        )

    def update_stats_delta(self, ts, stats_type, stats_id, field, value):
        def _update_stats_delta(txn):
            table, id_col = TYPE_TO_ROOM[stats_type]

            sql = (
                "SELECT * FROM %s"
                " WHERE %s=? and ts=("
                "  SELECT MAX(ts) FROM %s"
                "  WHERE %s=?"
                ")"
            ) % (table, id_col, table, id_col)
            txn.execute(sql, (stats_id, stats_id))
            rows = self.cursor_to_dict(txn)
            if len(rows) == 0:
                # silently skip as we don't have anything to apply a delta to yet.
                # this tries to minimise any race between the initial sync and
                # subsequent deltas arriving.
                return

            current_ts = ts
            latest_ts = rows[0]["ts"]
            if current_ts < latest_ts:
                # This one is in the past, but we're just encountering it now.
                # Mark it as part of the current bucket.
                current_ts = latest_ts
            elif ts != latest_ts:
                # we have to copy our absolute counters over to the new entry.
                values = {
                    key: rows[0][key] for key in ABSOLUTE_STATS_FIELDS[stats_type]
                }
                values[id_col] = stats_id
                values["ts"] = ts
                values["bucket_size"] = self.stats_bucket_size

                self._simple_insert_txn(txn, table=table, values=values)

            # actually update the new value
            if stats_type in ABSOLUTE_STATS_FIELDS[stats_type]:
                self._simple_update_txn(
                    txn,
                    table=table,
                    keyvalues={id_col: stats_id, "ts": current_ts},
                    updatevalues={field: value},
                )
            else:
                sql = ("UPDATE %s SET %s=%s+? WHERE %s=? AND ts=?") % (
                    table,
                    field,
                    field,
                    id_col,
                )
                txn.execute(sql, (value, stats_id, current_ts))

        return self.runInteraction("update_stats_delta", _update_stats_delta)
