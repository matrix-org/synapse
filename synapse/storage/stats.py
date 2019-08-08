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
from threading import Lock

from twisted.internet import defer
from twisted.internet.defer import ensureDeferred

from synapse.api.constants import EventTypes, Membership
from synapse.storage.engines import Sqlite3Engine
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
        "total_events",  # TODO review this list
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

        self.register_background_update_handler(
            "populate_stats_prepare", self._populate_stats_prepare
        )
        self.register_background_update_handler(
            "populate_stats_process_rooms", self._populate_stats_process_rooms
        )
        self.register_background_update_handler(
            "populate_stats_process_users", self._populate_stats_process_users
        )
        self.register_background_update_handler(
            "populate_stats_cleanup", self._populate_stats_cleanup
        )

    def quantise_stats_time(self, ts):
        return (ts // self.stats_bucket_size) * self.stats_bucket_size

    async def _unwedge_incremental_processor(self, forced_promise):
        """
        Make a promise about what this initial background count will handle,
        so that we can allow the incremental processor to start doing things
        right away – 'unwedging' it.
        """

        if forced_promise is None:
            promised_stats_delta_pos = (
                await self.get_max_stream_id_in_current_state_deltas()
            )

            promised_max = self.get_room_max_stream_ordering()
            promised_min = self.get_room_min_stream_ordering()

            promised_positions = {
                "state_delta_stream_id": promised_stats_delta_pos,
                "total_events_min_stream_ordering": promised_min,
                "total_events_max_stream_ordering": promised_max,
            }
        else:
            promised_positions = forced_promise

        # this stores it for our reference later
        await self.update_stats_positions(
            promised_positions, for_initial_processor=True
        )

        # this unwedges the incremental processor
        await self.update_stats_positions(
            promised_positions, for_initial_processor=False
        )

    @defer.inlineCallbacks
    def _populate_stats_prepare(self, progress, batch_size):

        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_prepare")
            defer.returnValue(1)

        def _wedge_incremental_processor(txn):
            """
            Wedge the incremental processor (by setting its positions to NULL),
            and return its previous positions – atomically.
            """

            with self.stats_delta_processing_lock:
                old = self._get_stats_positions_txn(txn, for_initial_processor=False)
                self._update_stats_positions_txn(txn, None, for_initial_processor=False)

            return old

        def _make_skeletons(txn):
            """
            Get all the rooms and users that we want to process, and create
            'skeletons' (incomplete _stats_current rows) for them, if they do
            not already have a row.
            """

            if isinstance(self.database_engine, Sqlite3Engine):
                sqls = """
                    INSERT OR IGNORE INTO room_stats_current (room_id)
                    SELECT room_id FROM rooms;

                    INSERT OR IGNORE INTO user_stats_current (user_id)
                    SELECT name AS user_id FROM users;
                """
            else:
                sqls = """
                    INSERT INTO room_stats_current (room_id)
                    SELECT room_id FROM rooms
                    ON CONFLICT DO NOTHING;

                    INSERT INTO user_stats_current (user_id)
                    SELECT name AS user_id FROM users
                    ON CONFLICT DO NOTHING;
                """

            for statement in get_statements(sqls.splitlines()):
                txn.execute(statement)

        def _delete_dirty_skeletons(txn):
            sqls = """
                DELETE FROM room_stats_current
                WHERE completed_delta_stream_id IS NULL;

                DELETE FROM user_stats_current
                WHERE completed_delta_stream_id IS NULL;
            """

            for statement in get_statements(sqls.splitlines()):
                txn.execute(statement)

        # first wedge the incremental processor and reset our promise
        old_positions = yield self.runInteraction(
            "populate_stats_wedge", _wedge_incremental_processor
        )

        if None in old_positions.values():
            old_positions = None

        # with the incremental processor wedged, we delete dirty skeleton rows
        # since we don't want to double-count them.
        yield self.runInteraction(
            "populate_stats_delete_dirty_skeletons", _delete_dirty_skeletons
        )

        yield ensureDeferred(self._unwedge_incremental_processor(old_positions))

        yield self.runInteraction("populate_stats_make_skeletons", _make_skeletons)
        self.get_earliest_token_for_stats.invalidate_all()

        yield self._end_background_update("populate_stats_prepare")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_stats_cleanup(self, progress, batch_size):
        # TODO is there really no clean-up to be done?

        # TODO if not self.stats_enabled ….
        yield self._end_background_update("populate_stats_cleanup")
        defer.returnValue(1)

    @defer.inlineCallbacks
    def _populate_stats_process_users(self, progress, batch_size):
        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_process_users")
            defer.returnValue(1)

        def _get_next_batch(txn):
            # Only fetch 250 users, so we don't fetch too many at once, even
            # if those 250 users have less than batch_size state events.
            sql = """
                SELECT user_id FROM user_stats_current
                WHERE completed_delta_stream_id IS NULL
                LIMIT 250
            """
            txn.execute(sql)
            users_to_work_on = txn.fetchall()

            if not users_to_work_on:
                return None

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_current"
                " WHERE completed_delta_stream_id IS NULL"
            )
            progress["remaining"] = txn.fetchone()[0]

            return users_to_work_on

        users_to_work_on = yield self.runInteraction(
            "populate_stats_users_get_batch", _get_next_batch
        )

        # No more users -- complete the transaction.
        if not users_to_work_on:
            yield self._end_background_update("populate_stats_process_users")
            defer.returnValue(1)

        logger.info(
            "Processing the next %d users of %d remaining",
            len(users_to_work_on),
            progress["remaining"],
        )

        processed_membership_count = 0

        promised_positions = yield self.get_stats_positions(for_initial_processor=True)

        if None in promised_positions:
            logger.error(
                "There is a None in promised_positions;"
                " dependency task must not have been run."
                " promised_positions: %s",
                promised_positions,
            )
            yield self._end_background_update("populate_stats_process_users")
            defer.returnValue(1)

        for user_id in users_to_work_on:
            now = self.hs.get_reactor().seconds()

            def _process_user(txn):
                # Get the current token
                current_token = self._get_max_stream_id_in_current_state_deltas_txn(txn)

                sql = """
                    SELECT
                        (
                            join_rules = 'public'
                            OR history_visibility = 'world_readable'
                        ) AS is_public,
                        COUNT(*) AS count
                    FROM room_memberships
                    JOIN room_state USING (room_id)
                    WHERE
                        user_id = ? AND membership = 'join'
                    GROUP BY is_public
                """
                txn.execute(sql, (user_id,))
                room_counts_by_publicness = dict(txn.fetchall())

                try:
                    self._update_stats_delta_txn(
                        txn,
                        now,
                        "user",
                        user_id,
                        {},
                        complete_with_stream_id=current_token,
                        absolute_fields={
                            # these are counted absolutely because it is
                            # more difficult to count them from the promised time,
                            # because counting them now can use the quick lookup
                            # tables.
                            "public_rooms": room_counts_by_publicness.get(True, 0),
                            "private_rooms": room_counts_by_publicness.get(False, 0),
                        },
                    )
                    # TODO CHECK: actually want to **overwrite** some of these!
                except OldCollectionRequired:
                    # this can't (shouldn't) actually happen
                    # since we only run the background update for incomplete rows
                    # and incomplete rows can never be old.
                    # However, if it does, the most graceful handling is just to
                    # ignore it – and carry on processing other users.
                    logger.error(
                        "Supposedly Impossible: OldCollectionRequired in initial"
                        " background update, for user ID %s",
                        user_id,
                        exc_info=True,
                    )
                    pass

                # we use this count for rate-limiting
                return sum(room_counts_by_publicness.values())

            processed_membership_count += yield self.runInteraction(
                "update_user_stats", _process_user
            )

            # Update the remaining counter.
            progress["remaining"] -= 1

            if processed_membership_count > batch_size:
                # Don't process any more users, we've hit our batch size.
                defer.returnValue(processed_membership_count)

        yield self.runInteraction(
            "populate_stats",
            self._background_update_progress_txn,
            "populate_stats_process_users",
            progress,
        )

        defer.returnValue(processed_membership_count)

    @defer.inlineCallbacks
    def _populate_stats_process_rooms(self, progress, batch_size):
        if not self.stats_enabled:
            yield self._end_background_update("populate_stats_process_rooms")
            defer.returnValue(1)

        def _get_next_batch(txn):
            # Only fetch 250 rooms, so we don't fetch too many at once, even
            # if those 250 rooms have less than batch_size state events.
            sql = """
                SELECT room_id FROM room_stats_current
                WHERE completed_delta_stream_id IS NULL
                LIMIT 250
            """
            txn.execute(sql)
            rooms_to_work_on = txn.fetchall()

            if not rooms_to_work_on:
                return None

            # Get how many are left to process, so we can give status on how
            # far we are in processing
            txn.execute(
                "SELECT COUNT(*) FROM room_stats_current"
                " WHERE completed_delta_stream_id IS NULL"
            )
            progress["remaining"] = txn.fetchone()[0]

            return rooms_to_work_on

        rooms_to_work_on = yield self.runInteraction(
            "populate_stats_rooms_get_batch", _get_next_batch
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

        promised_positions = yield self.get_stats_positions(for_initial_processor=True)

        if None in promised_positions:
            logger.error(
                "There is a None in promised_positions;"
                " dependency task must not have been run."
                " promised_positions: %s",
                promised_positions,
            )
            yield self._end_background_update("populate_stats_process_rooms")
            defer.returnValue(1)

        for room_id in rooms_to_work_on:
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

            def _fetch_data(txn):
                # Get the current token of the room
                current_token = self._get_max_stream_id_in_current_state_deltas_txn(txn)

                current_state_events = len(current_state_ids)

                membership_counts = self._get_user_counts_in_room_txn(txn, room_id)

                room_total_event_count = self._count_events_in_room_txn(
                    txn,
                    room_id,
                    promised_positions["total_events_min_stream_ordering"],
                    promised_positions["total_events_max_stream_ordering"],
                )

                try:
                    self._update_stats_delta_txn(
                        txn,
                        now,
                        "room",
                        room_id,
                        {"total_events": room_total_event_count},
                        complete_with_stream_id=current_token,
                        absolute_fields={
                            # these are counted absolutely because it is
                            # more difficult to count them from the promised time,
                            # because counting them now can use the quick lookup
                            # tables.
                            "current_state_events": current_state_events,
                            "joined_members": membership_counts.get(Membership.JOIN, 0),
                            "invited_members": membership_counts.get(
                                Membership.INVITE, 0
                            ),
                            "left_members": membership_counts.get(Membership.LEAVE, 0),
                            "banned_members": membership_counts.get(Membership.BAN, 0),
                        },
                    )
                    # TODO CHECK: actually want to **overwrite** some of these!
                except OldCollectionRequired:
                    # this can't (shouldn't) actually happen
                    # since we only run the background update for incomplete rows
                    # and incomplete rows can never be old.
                    # However, if it does, the most graceful handling is just to
                    # ignore it – and carry on processing other rooms.
                    logger.error(
                        "Supposedly Impossible: OldCollectionRequired in initial"
                        " background update, for room ID %s",
                        room_id,
                        exc_info=True,
                    )
                    pass

                # we use this count for rate-limiting
                return room_total_event_count

            room_event_count = yield self.runInteraction(
                "update_room_stats", _fetch_data
            )

            # Update the remaining counter.
            progress["remaining"] -= 1

            processed_event_count += room_event_count

            if processed_event_count > batch_size:
                # Don't process any more rooms, we've hit our batch size.
                defer.returnValue(processed_event_count)

        yield self.runInteraction(
            "populate_stats",
            self._background_update_progress_txn,
            "populate_stats_process_rooms",
            progress,
        )

        defer.returnValue(processed_event_count)

    def update_total_event_count_between_txn(self, txn, low_pos, high_pos):
        """
        Updates the total_events counts for rooms
        Args:
            txn: Database transaction. It is assumed that you will have one,
                since you probably want to update pointers at the same time.
            low_pos: The old stream position (stream position of the last event
                that was already handled.)
            high_pos: The new stream position (stream position of the new last
                event to handle.)
        """

        if low_pos >= high_pos:
            # nothing to do here.
            return

        now = self.hs.get_reactor().seconds()

        # we choose comparators based on the signs
        low_comparator = "<=" if low_pos < 0 else "<"
        high_comparator = "<" if high_pos < 0 else "<="

        # so, examples:
        # 3, 7 → 3 < … <= 7 (normal-filled)
        # -4, -2 → -4 <= … < -2 (backfilled)
        # -7, 7 → -7 <= … <= 7 (both)

        sql = """
            SELECT room_id, COUNT(*) AS new_events
            FROM events
            WHERE ? %s stream_ordering AND stream_ordering %s ?
            GROUP BY room_id
        """ % (
            low_comparator,
            high_comparator,
        )

        txn.execute(sql, (low_pos, high_pos))

        for room_id, new_events in txn.fetchall():
            while True:
                try:
                    self._update_stats_delta_txn(
                        txn, now, "room", room_id, {"total_events": new_events}
                    )
                    break
                except OldCollectionRequired:
                    self._collect_old_txn(txn, "room")
                    continue

    def _count_events_in_room_txn(self, txn, room_id, low_token, high_token):
        sql = """
            SELECT COUNT(*) AS num_events
            FROM events
            WHERE room_id = ?
                AND ? <= stream_ordering
                AND stream_ordering <= ?
        """
        txn.execute(sql, (room_id, low_token, high_token))
        return txn.fetchone()[0]

    def delete_all_stats(self):
        """
        Delete all statistics records.
        TODO obsolete?
        """

        def _delete_all_stats_txn(txn):
            txn.execute("DELETE FROM room_state")
            txn.execute("DELETE FROM room_stats")
            txn.execute("DELETE FROM room_stats_earliest_token")
            txn.execute("DELETE FROM user_stats")

        return self.runInteraction("delete_all_stats", _delete_all_stats_txn)

    def get_stats_positions(self, for_initial_processor=False):
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
        return self.runInteraction(
            "get_statistics_for_subject",
            self._get_statistics_for_subject_txn,
            stats_type,
            stats_id,
            start,
            size,
        )

    # TODO fix and account for _current.
    def _get_statistics_for_subject_txn(
        self, txn, stats_type, stats_id, start, size=100
    ):

        table, id_col = TYPE_TO_TABLE[stats_type]
        selected_columns = list(
            ABSOLUTE_STATS_FIELDS[stats_type] + PER_SLICE_FIELDS[stats_type]
        )

        slice_list = self._simple_select_list_paginate_txn(
            txn,
            table + "_historical",
            {id_col: stats_id},
            "end_ts",
            start,
            size,
            retcols=selected_columns + ["bucket_size", "end_ts"],
            order_direction="DESC",
        )

        if len(slice_list) < size:
            # also fetch the current row
            current = self._simple_select_one_txn(
                txn,
                table + "_current",
                {id_col: stats_id},
                retcols=selected_columns + ["start_ts", "end_ts"],
                allow_none=True,
            )

            if current is not None and current["end_ts"] is not None:
                # it is dirty, so contains new information, so should be included
                current["bucket_size"] = current["end_ts"] - current["start_ts"]
                del current["start_ts"]
                return [current] + slice_list
        return slice_list

    def get_all_room_state(self):
        return self._simple_select_list(
            "room_state", None, retcols=("name", "topic", "canonical_alias")
        )

    def get_room_state(self, room_id):
        return self._simple_select_one(
            "room_state",
            {"room_id": room_id},
            retcols=(
                "name",
                "topic",
                "canonical_alias",
                "avatar",
                "join_rules",
                "history_visibility",
            ),
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

    def update_stats(self, stats_type, stats_id, ts, fields):
        table, id_col = TYPE_TO_TABLE[stats_type]
        return self._simple_upsert(
            table=table,
            keyvalues={id_col: stats_id, "ts": ts},
            values=fields,
            desc="update_stats",
        )

    def _update_stats_txn(self, txn, stats_type, stats_id, ts, fields):
        table, id_col = TYPE_TO_TABLE[stats_type]
        return self._simple_upsert_txn(
            txn, table=table, keyvalues={id_col: stats_id, "ts": ts}, values=fields
        )

    def _collect_old_txn(self, txn, stats_type, limit=500):
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

        sql = ("SELECT %s FROM %s_current WHERE end_ts <= ? LIMIT %d FOR UPDATE") % (
            id_col,
            table,
            limit,
        )
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

    async def collect_old(self, stats_type):
        while True:
            maybe_more = await self.runInteraction(
                "stats_collect_old", self._collect_old_txn, stats_type
            )
            if not maybe_more:
                return

    async def update_stats_delta(
        self, ts, stats_type, stats_id, fields, complete_with_stream_id=None
    ):
        """

        Args:
            ts (int):
            stats_type (str):
            stats_id (str):
            fields (dict[str, int]): Deltas of stats values.
            complete_with_stream_id (int, optional):

        Returns:

        """

        while True:
            try:
                return await self.runInteraction(
                    "update_stats_delta",
                    self._update_stats_delta_txn,
                    ts,
                    stats_type,
                    stats_id,
                    fields,
                    complete_with_stream_id=complete_with_stream_id,
                )
            except OldCollectionRequired:
                # retry after collecting old rows
                await self.collect_old(stats_type)

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
                "start_ts": ts,  # TODO or do we use qts?
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

    def incremental_update_total_events(self, in_positions):
        def incremental_update_total_events_txn(txn):
            positions = in_positions.copy()

            max_pos = self.get_room_max_stream_ordering()
            min_pos = self.get_room_min_stream_ordering()
            self.update_total_event_count_between_txn(
                txn,
                low_pos=positions["total_events_max_stream_ordering"],
                high_pos=max_pos,
            )

            self.update_total_event_count_between_txn(
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

            return positions

        return self.runInteraction(
            "stats_incremental_total_events", incremental_update_total_events_txn
        )
