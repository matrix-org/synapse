# -*- coding: utf-8 -*-
# Copyright 2018 Vector Creations Ltd
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

from .state_deltas import StateDeltasStore

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


class StatsStore(StateDeltasStore):
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

    def update_stats(self, stats_type, stats_id, ts, fields):
        return self._simple_upsert(
            table=("%s_stats" % stats_type),
            keyvalues={("%s_id" % stats_type): stats_id, "ts": ts},
            updatevalues=fields,
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
