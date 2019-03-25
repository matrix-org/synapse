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
from synapse.api.constants import EventTypes, Membership

from twisted.internet import defer
from synapse.storage.state_deltas import StateDeltasStore

logger = logging.getLogger(__name__)

# these fields track relative numbers (e.g. number of events sent in this timeslice)
RELATIVE_STATS_FIELDS = {"room": ("sent_events"), "user": ("sent_events")}

# these fields track rather than absolutes (e.g. total number of rooms on the server)
ABSOLUTE_STATS_FIELDS = {
    "room": (
        "current_state_events",
        "joined_members",
        "invited_members",
        "left_members",
        "banned_members",
        "state_events",
        "local_events",
        "remote_events",
    ),
    "user": (
        "local_events",
        "public_rooms",
        "private_rooms",
        "sent_file_count",
        "sent_file_size",
    ),
}

TEMP_TABLE = "_temp_populate_stats"


class StatsStore(StateDeltasStore):
    def __init__(self, db_conn, hs):
        super(StatsStore, self).__init__(db_conn, hs)

        self.server_name = hs.hostname
        self.clock = self.hs.get_clock()
        self.stats_enable = hs.config.stats_enable
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

        if not self.stats_enable:
            yield self._end_background_update("populate_stats_createtables")
            defer.returnValue(1)

        # Get all the rooms that we want to process.
        def _make_staging_area(txn):
            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_rooms(room_id TEXT NOT NULL, events BIGINT NOT NULL)"
            )
            txn.execute(sql)

            sql = (
                "CREATE TABLE IF NOT EXISTS "
                + TEMP_TABLE
                + "_position(position TEXT NOT NULL)"
            )
            txn.execute(sql)

            # Get rooms we want to process from the database
            sql = """
                SELECT room_id, count(*) FROM current_state_events
                GROUP BY room_id
            """
            txn.execute(sql)
            rooms = [{"room_id": x[0], "events": x[1]} for x in txn.fetchall()]
            self._simple_insert_many_txn(txn, TEMP_TABLE + "_rooms", rooms)
            del rooms

        new_pos = yield self.get_max_stream_id_in_current_state_deltas()
        yield self.runInteraction("populate_stats_temp_build", _make_staging_area)
        yield self._simple_insert(TEMP_TABLE + "_position", {"position": new_pos})

        yield self._end_background_update("populate_stats_createtables")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_stats_cleanup(self, progress, batch_size):
        """
        Update the user directory stream position, then clean up the old tables.
        """
        if not self.stats_enable:
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

        if not self.stats_enable:
            yield self._end_background_update("populate_stats_process_rooms")
            defer.returnValue(1)

        # If we don't have progress filed, delete everything.
        if not progress:
            yield self.delete_all_stats()

        def _get_next_batch(txn):
            sql = """
                SELECT room_id FROM %s
                ORDER BY events DESC
                LIMIT %s
            """ % (
                TEMP_TABLE + "_rooms",
                str(batch_size),
            )
            txn.execute(sql)
            rooms_to_work_on = txn.fetchall()

            if not rooms_to_work_on:
                return None

            rooms_to_work_on = [x[0] for x in rooms_to_work_on]

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
            "Processing the next %d rooms of %d remaining"
            % (len(rooms_to_work_on), progress["remaining"])
        )

        for room_id in rooms_to_work_on:

            current_state_ids = yield self.get_current_state_ids(room_id)

            join_rules = yield self.get_event(
                current_state_ids.get((EventTypes.JoinRules, "")), allow_none=True
            )
            history_visibility = yield self.get_event(
                current_state_ids.get((EventTypes.RoomHistoryVisibility, "")),
                allow_none=True,
            )
            encryption = yield self.get_event(
                current_state_ids.get((EventTypes.RoomEncryption, "")), allow_none=True
            )
            name = yield self.get_event(
                current_state_ids.get((EventTypes.Name, "")), allow_none=True
            )
            topic = yield self.get_event(
                current_state_ids.get((EventTypes.Topic, "")), allow_none=True
            )
            avatar = yield self.get_event(
                current_state_ids.get((EventTypes.RoomAvatar, "")), allow_none=True
            )
            canonical_alias = yield self.get_event(
                current_state_ids.get((EventTypes.CanonicalAlias, "")), allow_none=True
            )

            def _or_none(x, arg):
                if x:
                    return x.content.get(arg)
                return None

            yield self.update_room_state(
                room_id,
                {
                    "join_rules": _or_none(join_rules, "join_rule"),
                    "history_visibility": _or_none(
                        history_visibility, "history_visibility"
                    ),
                    "encryption": _or_none(encryption, "algorithm"),
                    "name": _or_none(name, "name"),
                    "topic": _or_none(topic, "topic"),
                    "avatar": _or_none(avatar, "url"),
                    "canonical_alias": _or_none(canonical_alias, "alias"),
                },
            )

            now = self.clock.time_msec()

            # quantise time to the nearest bucket
            now = (
                int(now / (self.stats_bucket_size * 1000))
                * self.stats_bucket_size
                * 1000
            )

            current_state_events = len(current_state_ids)
            joined_members = yield self.get_user_count_in_room(room_id, Membership.JOIN)
            invited_members = yield self.get_user_count_in_room(
                room_id, Membership.INVITE
            )
            left_members = yield self.get_user_count_in_room(room_id, Membership.LEAVE)
            banned_members = yield self.get_user_count_in_room(room_id, Membership.BAN)
            state_events = yield self.get_state_event_counts(room_id)
            (local_events, remote_events) = yield self.get_event_counts(
                room_id, self.server_name
            )

            yield self.update_stats(
                "room",
                room_id,
                now,
                {
                    "bucket_size": self.stats_bucket_size,
                    "current_state_events": current_state_events,
                    "joined_members": joined_members,
                    "invited_members": invited_members,
                    "left_members": left_members,
                    "banned_members": banned_members,
                    "state_events": state_events,
                    "local_events": local_events,
                    "remote_events": remote_events,
                    "sent_events": local_events + remote_events,
                },
            )

            # We've finished a room. Delete it from the table.
            yield self._simple_delete_one(TEMP_TABLE + "_rooms", {"room_id": room_id})
            # Update the remaining counter.
            progress["remaining"] -= 1
            yield self.runInteraction(
                "populate_stats",
                self._background_update_progress_txn,
                "populate_stats_process_rooms",
                progress,
            )

        defer.returnValue(len(rooms_to_work_on))

    def delete_all_stats(self):
        """
        Delete all statistics records.
        """
        def _delete_all_stats_txn(txn):
            txn.execute("DELETE FROM room_state")
            txn.execute("DELETE FROM room_stats")
            txn.execute("DELETE FROM user_stats")

        return self.runInteraction(
            "delete_all_stats", _delete_all_stats_txn
        )

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
        return self._simple_upsert(
            table="room_state",
            keyvalues={"room_id": room_id},
            values=fields,
            desc="update_room_state",
        )

    def get_all_room_state(self):
        return self._simple_select_list(
            "room_state", None, retcols=("name", "topic", "canonical_alias")
        )

    def update_stats(self, stats_type, stats_id, ts, fields):
        return self._simple_upsert(
            table=("%s_stats" % stats_type),
            keyvalues={("%s_id" % stats_type): stats_id, "ts": ts},
            values=fields,
            desc="update_stats",
        )

    def update_stats_delta(self, ts, bucket_size, stats_type, stats_id, field, value):
        def _update_stats_delta(txn):
            table = "%s_stats" % stats_type
            id_col = "%s_id" % stats_type

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

            values = {key: rows[0][key] for key in ABSOLUTE_STATS_FIELDS[stats_type]}
            values[id_col] = stats_id
            values["ts"] = ts
            values["bucket_size"] = bucket_size

            latest_ts = rows[0]["ts"]
            if ts != latest_ts:
                # we have to copy our absolute counters over to the new entry.
                self._simple_insert_txn(txn, table=table, values=values)

            # actually update the new value
            if stats_type in ABSOLUTE_STATS_FIELDS[stats_type]:
                self._simple_update_txn(
                    txn,
                    table=table,
                    keyvalues={id_col: stats_id, "ts": ts},
                    updatevalues={field: value},
                )
            else:
                sql = ("UPDATE %s " " SET %s=%s+?" " WHERE %s=? AND ts=?") % (
                    table,
                    field,
                    field,
                    id_col,
                )
                txn.execute(sql, (value, stats_id, ts))

        return self.runInteraction("update_stats_delta", _update_stats_delta)
