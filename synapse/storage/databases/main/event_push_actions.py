# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from typing import Dict, List, Optional, Tuple, Union

import attr

from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)


DEFAULT_NOTIF_ACTION = ["notify", {"set_tweak": "highlight", "value": False}]
DEFAULT_HIGHLIGHT_ACTION = [
    "notify",
    {"set_tweak": "sound", "value": "default"},
    {"set_tweak": "highlight"},
]


def _serialize_action(actions, is_highlight):
    """Custom serializer for actions. This allows us to "compress" common actions.

    We use the fact that most users have the same actions for notifs (and for
    highlights).
    We store these default actions as the empty string rather than the full JSON.
    Since the empty string isn't valid JSON there is no risk of this clashing with
    any real JSON actions
    """
    if is_highlight:
        if actions == DEFAULT_HIGHLIGHT_ACTION:
            return ""  # We use empty string as the column is non-NULL
    else:
        if actions == DEFAULT_NOTIF_ACTION:
            return ""
    return json_encoder.encode(actions)


def _deserialize_action(actions, is_highlight):
    """Custom deserializer for actions. This allows us to "compress" common actions"""
    if actions:
        return db_to_json(actions)

    if is_highlight:
        return DEFAULT_HIGHLIGHT_ACTION
    else:
        return DEFAULT_NOTIF_ACTION


class EventPushActionsWorkerStore(SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        # These get correctly set by _find_stream_orderings_for_times_txn
        self.stream_ordering_month_ago = None
        self.stream_ordering_day_ago = None

        cur = db_conn.cursor(txn_name="_find_stream_orderings_for_times_txn")
        self._find_stream_orderings_for_times_txn(cur)
        cur.close()

        self.find_stream_orderings_looping_call = self._clock.looping_call(
            self._find_stream_orderings_for_times, 10 * 60 * 1000
        )

        self._rotate_delay = 3
        self._rotate_count = 10000
        self._doing_notif_rotation = False
        if hs.config.run_background_tasks:
            self._rotate_notif_loop = self._clock.looping_call(
                self._rotate_notifs, 30 * 60 * 1000
            )

    @cached(num_args=3, tree=True, max_entries=5000)
    async def get_unread_event_push_actions_by_room_for_user(
        self,
        room_id: str,
        user_id: str,
        last_read_event_id: Optional[str],
    ) -> Dict[str, int]:
        """Get the notification count, the highlight count and the unread message count
        for a given user in a given room after the given read receipt.

        Note that this function assumes the user to be a current member of the room,
        since it's either called by the sync handler to handle joined room entries, or by
        the HTTP pusher to calculate the badge of unread joined rooms.

        Args:
            room_id: The room to retrieve the counts in.
            user_id: The user to retrieve the counts for.
            last_read_event_id: The event associated with the latest read receipt for
                this user in this room. None if no receipt for this user in this room.

        Returns
            A dict containing the counts mentioned earlier in this docstring,
            respectively under the keys "notify_count", "highlight_count" and
            "unread_count".
        """
        return await self.db_pool.runInteraction(
            "get_unread_event_push_actions_by_room",
            self._get_unread_counts_by_receipt_txn,
            room_id,
            user_id,
            last_read_event_id,
        )

    def _get_unread_counts_by_receipt_txn(
        self,
        txn,
        room_id,
        user_id,
        last_read_event_id,
    ):
        stream_ordering = None

        if last_read_event_id is not None:
            stream_ordering = self.get_stream_id_for_event_txn(
                txn,
                last_read_event_id,
                allow_none=True,
            )

        if stream_ordering is None:
            # Either last_read_event_id is None, or it's an event we don't have (e.g.
            # because it's been purged), in which case retrieve the stream ordering for
            # the latest membership event from this user in this room (which we assume is
            # a join).
            event_id = self.db_pool.simple_select_one_onecol_txn(
                txn=txn,
                table="local_current_membership",
                keyvalues={"room_id": room_id, "user_id": user_id},
                retcol="event_id",
            )

            stream_ordering = self.get_stream_id_for_event_txn(txn, event_id)

        return self._get_unread_counts_by_pos_txn(
            txn, room_id, user_id, stream_ordering
        )

    def _get_unread_counts_by_pos_txn(self, txn, room_id, user_id, stream_ordering):
        sql = (
            "SELECT"
            "   COUNT(CASE WHEN notif = 1 THEN 1 END),"
            "   COUNT(CASE WHEN highlight = 1 THEN 1 END),"
            "   COUNT(CASE WHEN unread = 1 THEN 1 END)"
            " FROM event_push_actions ea"
            " WHERE user_id = ?"
            "   AND room_id = ?"
            "   AND stream_ordering > ?"
        )

        txn.execute(sql, (user_id, room_id, stream_ordering))
        row = txn.fetchone()

        (notif_count, highlight_count, unread_count) = (0, 0, 0)

        if row:
            (notif_count, highlight_count, unread_count) = row

        txn.execute(
            """
                SELECT notif_count, unread_count FROM event_push_summary
                WHERE room_id = ? AND user_id = ? AND stream_ordering > ?
            """,
            (room_id, user_id, stream_ordering),
        )
        row = txn.fetchone()

        if row:
            notif_count += row[0]

            if row[1] is not None:
                # The unread_count column of event_push_summary is NULLable, so we need
                # to make sure we don't try increasing the unread counts if it's NULL
                # for this row.
                unread_count += row[1]

        return {
            "notify_count": notif_count,
            "unread_count": unread_count,
            "highlight_count": highlight_count,
        }

    async def get_push_action_users_in_range(
        self, min_stream_ordering, max_stream_ordering
    ):
        def f(txn):
            sql = (
                "SELECT DISTINCT(user_id) FROM event_push_actions WHERE"
                " stream_ordering >= ? AND stream_ordering <= ? AND notif = 1"
            )
            txn.execute(sql, (min_stream_ordering, max_stream_ordering))
            return [r[0] for r in txn]

        ret = await self.db_pool.runInteraction("get_push_action_users_in_range", f)
        return ret

    async def get_unread_push_actions_for_user_in_range_for_http(
        self,
        user_id: str,
        min_stream_ordering: int,
        max_stream_ordering: int,
        limit: int = 20,
    ) -> List[dict]:
        """Get a list of the most recent unread push actions for a given user,
        within the given stream ordering range. Called by the httppusher.

        Args:
            user_id: The user to fetch push actions for.
            min_stream_ordering: The exclusive lower bound on the
                stream ordering of event push actions to fetch.
            max_stream_ordering: The inclusive upper bound on the
                stream ordering of event push actions to fetch.
            limit: The maximum number of rows to return.
        Returns:
            A list of dicts with the keys "event_id", "room_id", "stream_ordering", "actions".
            The list will be ordered by ascending stream_ordering.
            The list will have between 0~limit entries.
        """
        # find rooms that have a read receipt in them and return the next
        # push actions
        def get_after_receipt(txn):
            # find rooms that have a read receipt in them and return the next
            # push actions
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions,"
                "   ep.highlight "
                " FROM ("
                "   SELECT room_id,"
                "       MAX(stream_ordering) as stream_ordering"
                "   FROM events"
                "   INNER JOIN receipts_linearized USING (room_id, event_id)"
                "   WHERE receipt_type = 'm.read' AND user_id = ?"
                "   GROUP BY room_id"
                ") AS rl,"
                " event_push_actions AS ep"
                " WHERE"
                "   ep.room_id = rl.room_id"
                "   AND ep.stream_ordering > rl.stream_ordering"
                "   AND ep.user_id = ?"
                "   AND ep.stream_ordering > ?"
                "   AND ep.stream_ordering <= ?"
                "   AND ep.notif = 1"
                " ORDER BY ep.stream_ordering ASC LIMIT ?"
            )
            args = [user_id, user_id, min_stream_ordering, max_stream_ordering, limit]
            txn.execute(sql, args)
            return txn.fetchall()

        after_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http_arr", get_after_receipt
        )

        # There are rooms with push actions in them but you don't have a read receipt in
        # them e.g. rooms you've been invited to, so get push actions for rooms which do
        # not have read receipts in them too.
        def get_no_receipt(txn):
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions,"
                "   ep.highlight "
                " FROM event_push_actions AS ep"
                " INNER JOIN events AS e USING (room_id, event_id)"
                " WHERE"
                "   ep.room_id NOT IN ("
                "     SELECT room_id FROM receipts_linearized"
                "       WHERE receipt_type = 'm.read' AND user_id = ?"
                "       GROUP BY room_id"
                "   )"
                "   AND ep.user_id = ?"
                "   AND ep.stream_ordering > ?"
                "   AND ep.stream_ordering <= ?"
                "   AND ep.notif = 1"
                " ORDER BY ep.stream_ordering ASC LIMIT ?"
            )
            args = [user_id, user_id, min_stream_ordering, max_stream_ordering, limit]
            txn.execute(sql, args)
            return txn.fetchall()

        no_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http_nrr", get_no_receipt
        )

        notifs = [
            {
                "event_id": row[0],
                "room_id": row[1],
                "stream_ordering": row[2],
                "actions": _deserialize_action(row[3], row[4]),
            }
            for row in after_read_receipt + no_read_receipt
        ]

        # Now sort it so it's ordered correctly, since currently it will
        # contain results from the first query, correctly ordered, followed
        # by results from the second query, but we want them all ordered
        # by stream_ordering, oldest first.
        notifs.sort(key=lambda r: r["stream_ordering"])

        # Take only up to the limit. We have to stop at the limit because
        # one of the subqueries may have hit the limit.
        return notifs[:limit]

    async def get_unread_push_actions_for_user_in_range_for_email(
        self,
        user_id: str,
        min_stream_ordering: int,
        max_stream_ordering: int,
        limit: int = 20,
    ) -> List[dict]:
        """Get a list of the most recent unread push actions for a given user,
        within the given stream ordering range. Called by the emailpusher

        Args:
            user_id: The user to fetch push actions for.
            min_stream_ordering: The exclusive lower bound on the
                stream ordering of event push actions to fetch.
            max_stream_ordering: The inclusive upper bound on the
                stream ordering of event push actions to fetch.
            limit: The maximum number of rows to return.
        Returns:
            A list of dicts with the keys "event_id", "room_id", "stream_ordering", "actions", "received_ts".
            The list will be ordered by descending received_ts.
            The list will have between 0~limit entries.
        """
        # find rooms that have a read receipt in them and return the most recent
        # push actions
        def get_after_receipt(txn):
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions,"
                "  ep.highlight, e.received_ts"
                " FROM ("
                "   SELECT room_id,"
                "       MAX(stream_ordering) as stream_ordering"
                "   FROM events"
                "   INNER JOIN receipts_linearized USING (room_id, event_id)"
                "   WHERE receipt_type = 'm.read' AND user_id = ?"
                "   GROUP BY room_id"
                ") AS rl,"
                " event_push_actions AS ep"
                " INNER JOIN events AS e USING (room_id, event_id)"
                " WHERE"
                "   ep.room_id = rl.room_id"
                "   AND ep.stream_ordering > rl.stream_ordering"
                "   AND ep.user_id = ?"
                "   AND ep.stream_ordering > ?"
                "   AND ep.stream_ordering <= ?"
                "   AND ep.notif = 1"
                " ORDER BY ep.stream_ordering DESC LIMIT ?"
            )
            args = [user_id, user_id, min_stream_ordering, max_stream_ordering, limit]
            txn.execute(sql, args)
            return txn.fetchall()

        after_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email_arr", get_after_receipt
        )

        # There are rooms with push actions in them but you don't have a read receipt in
        # them e.g. rooms you've been invited to, so get push actions for rooms which do
        # not have read receipts in them too.
        def get_no_receipt(txn):
            sql = (
                "SELECT ep.event_id, ep.room_id, ep.stream_ordering, ep.actions,"
                "   ep.highlight, e.received_ts"
                " FROM event_push_actions AS ep"
                " INNER JOIN events AS e USING (room_id, event_id)"
                " WHERE"
                "   ep.room_id NOT IN ("
                "     SELECT room_id FROM receipts_linearized"
                "       WHERE receipt_type = 'm.read' AND user_id = ?"
                "       GROUP BY room_id"
                "   )"
                "   AND ep.user_id = ?"
                "   AND ep.stream_ordering > ?"
                "   AND ep.stream_ordering <= ?"
                "   AND ep.notif = 1"
                " ORDER BY ep.stream_ordering DESC LIMIT ?"
            )
            args = [user_id, user_id, min_stream_ordering, max_stream_ordering, limit]
            txn.execute(sql, args)
            return txn.fetchall()

        no_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email_nrr", get_no_receipt
        )

        # Make a list of dicts from the two sets of results.
        notifs = [
            {
                "event_id": row[0],
                "room_id": row[1],
                "stream_ordering": row[2],
                "actions": _deserialize_action(row[3], row[4]),
                "received_ts": row[5],
            }
            for row in after_read_receipt + no_read_receipt
        ]

        # Now sort it so it's ordered correctly, since currently it will
        # contain results from the first query, correctly ordered, followed
        # by results from the second query, but we want them all ordered
        # by received_ts (most recent first)
        notifs.sort(key=lambda r: -(r["received_ts"] or 0))

        # Now return the first `limit`
        return notifs[:limit]

    async def get_if_maybe_push_in_range_for_user(
        self, user_id: str, min_stream_ordering: int
    ) -> bool:
        """A fast check to see if there might be something to push for the
        user since the given stream ordering. May return false positives.

        Useful to know whether to bother starting a pusher on start up or not.

        Args:
            user_id
            min_stream_ordering

        Returns:
            True if there may be push to process, False if there definitely isn't.
        """

        def _get_if_maybe_push_in_range_for_user_txn(txn):
            sql = """
                SELECT 1 FROM event_push_actions
                WHERE user_id = ? AND stream_ordering > ? AND notif = 1
                LIMIT 1
            """

            txn.execute(sql, (user_id, min_stream_ordering))
            return bool(txn.fetchone())

        return await self.db_pool.runInteraction(
            "get_if_maybe_push_in_range_for_user",
            _get_if_maybe_push_in_range_for_user_txn,
        )

    async def add_push_actions_to_staging(
        self,
        event_id: str,
        user_id_actions: Dict[str, List[Union[dict, str]]],
        count_as_unread: bool,
    ) -> None:
        """Add the push actions for the event to the push action staging area.

        Args:
            event_id
            user_id_actions: A mapping of user_id to list of push actions, where
                an action can either be a string or dict.
            count_as_unread: Whether this event should increment unread counts.
        """
        if not user_id_actions:
            return

        # This is a helper function for generating the necessary tuple that
        # can be used to insert into the `event_push_actions_staging` table.
        def _gen_entry(user_id, actions):
            is_highlight = 1 if _action_has_highlight(actions) else 0
            notif = 1 if "notify" in actions else 0
            return (
                event_id,  # event_id column
                user_id,  # user_id column
                _serialize_action(actions, is_highlight),  # actions column
                notif,  # notif column
                is_highlight,  # highlight column
                int(count_as_unread),  # unread column
            )

        def _add_push_actions_to_staging_txn(txn):
            # We don't use simple_insert_many here to avoid the overhead
            # of generating lists of dicts.

            sql = """
                INSERT INTO event_push_actions_staging
                    (event_id, user_id, actions, notif, highlight, unread)
                VALUES (?, ?, ?, ?, ?, ?)
            """

            txn.execute_batch(
                sql,
                (
                    _gen_entry(user_id, actions)
                    for user_id, actions in user_id_actions.items()
                ),
            )

        return await self.db_pool.runInteraction(
            "add_push_actions_to_staging", _add_push_actions_to_staging_txn
        )

    async def remove_push_actions_from_staging(self, event_id: str) -> None:
        """Called if we failed to persist the event to ensure that stale push
        actions don't build up in the DB
        """

        try:
            res = await self.db_pool.simple_delete(
                table="event_push_actions_staging",
                keyvalues={"event_id": event_id},
                desc="remove_push_actions_from_staging",
            )
            return res
        except Exception:
            # this method is called from an exception handler, so propagating
            # another exception here really isn't helpful - there's nothing
            # the caller can do about it. Just log the exception and move on.
            logger.exception(
                "Error removing push actions after event persistence failure"
            )

    @wrap_as_background_process("event_push_action_stream_orderings")
    async def _find_stream_orderings_for_times(self) -> None:
        await self.db_pool.runInteraction(
            "_find_stream_orderings_for_times",
            self._find_stream_orderings_for_times_txn,
        )

    def _find_stream_orderings_for_times_txn(self, txn: LoggingTransaction) -> None:
        logger.info("Searching for stream ordering 1 month ago")
        self.stream_ordering_month_ago = self._find_first_stream_ordering_after_ts_txn(
            txn, self._clock.time_msec() - 30 * 24 * 60 * 60 * 1000
        )
        logger.info(
            "Found stream ordering 1 month ago: it's %d", self.stream_ordering_month_ago
        )
        logger.info("Searching for stream ordering 1 day ago")
        self.stream_ordering_day_ago = self._find_first_stream_ordering_after_ts_txn(
            txn, self._clock.time_msec() - 24 * 60 * 60 * 1000
        )
        logger.info(
            "Found stream ordering 1 day ago: it's %d", self.stream_ordering_day_ago
        )

    async def find_first_stream_ordering_after_ts(self, ts: int) -> int:
        """Gets the stream ordering corresponding to a given timestamp.

        Specifically, finds the stream_ordering of the first event that was
        received on or after the timestamp. This is done by a binary search on
        the events table, since there is no index on received_ts, so is
        relatively slow.

        Args:
            ts: timestamp in millis

        Returns:
            stream ordering of the first event received on/after the timestamp
        """
        return await self.db_pool.runInteraction(
            "_find_first_stream_ordering_after_ts_txn",
            self._find_first_stream_ordering_after_ts_txn,
            ts,
        )

    @staticmethod
    def _find_first_stream_ordering_after_ts_txn(txn, ts):
        """
        Find the stream_ordering of the first event that was received on or
        after a given timestamp. This is relatively slow as there is no index
        on received_ts but we can then use this to delete push actions before
        this.

        received_ts must necessarily be in the same order as stream_ordering
        and stream_ordering is indexed, so we manually binary search using
        stream_ordering

        Args:
            txn (twisted.enterprise.adbapi.Transaction):
            ts (int): timestamp to search for

        Returns:
            int: stream ordering
        """
        txn.execute("SELECT MAX(stream_ordering) FROM events")
        max_stream_ordering = txn.fetchone()[0]

        if max_stream_ordering is None:
            return 0

        # We want the first stream_ordering in which received_ts is greater
        # than or equal to ts. Call this point X.
        #
        # We maintain the invariants:
        #
        #   range_start <= X <= range_end
        #
        range_start = 0
        range_end = max_stream_ordering + 1

        # Given a stream_ordering, look up the timestamp at that
        # stream_ordering.
        #
        # The array may be sparse (we may be missing some stream_orderings).
        # We treat the gaps as the same as having the same value as the
        # preceding entry, because we will pick the lowest stream_ordering
        # which satisfies our requirement of received_ts >= ts.
        #
        # For example, if our array of events indexed by stream_ordering is
        # [10, <none>, 20], we should treat this as being equivalent to
        # [10, 10, 20].
        #
        sql = (
            "SELECT received_ts FROM events"
            " WHERE stream_ordering <= ?"
            " ORDER BY stream_ordering DESC"
            " LIMIT 1"
        )

        while range_end - range_start > 0:
            middle = (range_end + range_start) // 2
            txn.execute(sql, (middle,))
            row = txn.fetchone()
            if row is None:
                # no rows with stream_ordering<=middle
                range_start = middle + 1
                continue

            middle_ts = row[0]
            if ts > middle_ts:
                # we got a timestamp lower than the one we were looking for.
                # definitely need to look higher: X > middle.
                range_start = middle + 1
            else:
                # we got a timestamp higher than (or the same as) the one we
                # were looking for. We aren't yet sure about the point we
                # looked up, but we can be sure that X <= middle.
                range_end = middle

        return range_end

    async def get_time_of_last_push_action_before(self, stream_ordering):
        def f(txn):
            sql = (
                "SELECT e.received_ts"
                " FROM event_push_actions AS ep"
                " JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id"
                " WHERE ep.stream_ordering > ? AND notif = 1"
                " ORDER BY ep.stream_ordering ASC"
                " LIMIT 1"
            )
            txn.execute(sql, (stream_ordering,))
            return txn.fetchone()

        result = await self.db_pool.runInteraction(
            "get_time_of_last_push_action_before", f
        )
        return result[0] if result else None

    @wrap_as_background_process("rotate_notifs")
    async def _rotate_notifs(self):
        if self._doing_notif_rotation or self.stream_ordering_day_ago is None:
            return
        self._doing_notif_rotation = True

        try:
            while True:
                logger.info("Rotating notifications")

                caught_up = await self.db_pool.runInteraction(
                    "_rotate_notifs", self._rotate_notifs_txn
                )
                if caught_up:
                    break
                await self.hs.get_clock().sleep(self._rotate_delay)
        finally:
            self._doing_notif_rotation = False

    def _rotate_notifs_txn(self, txn):
        """Archives older notifications into event_push_summary. Returns whether
        the archiving process has caught up or not.
        """

        old_rotate_stream_ordering = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        # We don't to try and rotate millions of rows at once, so we cap the
        # maximum stream ordering we'll rotate before.
        txn.execute(
            """
            SELECT stream_ordering FROM event_push_actions
            WHERE stream_ordering > ?
            ORDER BY stream_ordering ASC LIMIT 1 OFFSET ?
        """,
            (old_rotate_stream_ordering, self._rotate_count),
        )
        stream_row = txn.fetchone()
        if stream_row:
            (offset_stream_ordering,) = stream_row
            rotate_to_stream_ordering = min(
                self.stream_ordering_day_ago, offset_stream_ordering
            )
            caught_up = offset_stream_ordering >= self.stream_ordering_day_ago
        else:
            rotate_to_stream_ordering = self.stream_ordering_day_ago
            caught_up = True

        logger.info("Rotating notifications up to: %s", rotate_to_stream_ordering)

        self._rotate_notifs_before_txn(txn, rotate_to_stream_ordering)

        # We have caught up iff we were limited by `stream_ordering_day_ago`
        return caught_up

    def _rotate_notifs_before_txn(self, txn, rotate_to_stream_ordering):
        old_rotate_stream_ordering = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        # Calculate the new counts that should be upserted into event_push_summary
        sql = """
            SELECT user_id, room_id,
                coalesce(old.%s, 0) + upd.cnt,
                upd.stream_ordering,
                old.user_id
            FROM (
                SELECT user_id, room_id, count(*) as cnt,
                    max(stream_ordering) as stream_ordering
                FROM event_push_actions
                WHERE ? <= stream_ordering AND stream_ordering < ?
                    AND highlight = 0
                    AND %s = 1
                GROUP BY user_id, room_id
            ) AS upd
            LEFT JOIN event_push_summary AS old USING (user_id, room_id)
        """

        # First get the count of unread messages.
        txn.execute(
            sql % ("unread_count", "unread"),
            (old_rotate_stream_ordering, rotate_to_stream_ordering),
        )

        # We need to merge results from the two requests (the one that retrieves the
        # unread count and the one that retrieves the notifications count) into a single
        # object because we might not have the same amount of rows in each of them. To do
        # this, we use a dict indexed on the user ID and room ID to make it easier to
        # populate.
        summaries = {}  # type: Dict[Tuple[str, str], _EventPushSummary]
        for row in txn:
            summaries[(row[0], row[1])] = _EventPushSummary(
                unread_count=row[2],
                stream_ordering=row[3],
                old_user_id=row[4],
                notif_count=0,
            )

        # Then get the count of notifications.
        txn.execute(
            sql % ("notif_count", "notif"),
            (old_rotate_stream_ordering, rotate_to_stream_ordering),
        )

        for row in txn:
            if (row[0], row[1]) in summaries:
                summaries[(row[0], row[1])].notif_count = row[2]
            else:
                # Because the rules on notifying are different than the rules on marking
                # a message unread, we might end up with messages that notify but aren't
                # marked unread, so we might not have a summary for this (user, room)
                # tuple to complete.
                summaries[(row[0], row[1])] = _EventPushSummary(
                    unread_count=0,
                    stream_ordering=row[3],
                    old_user_id=row[4],
                    notif_count=row[2],
                )

        logger.info("Rotating notifications, handling %d rows", len(summaries))

        # If the `old.user_id` above is NULL then we know there isn't already an
        # entry in the table, so we simply insert it. Otherwise we update the
        # existing table.
        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_push_summary",
            values=[
                {
                    "user_id": user_id,
                    "room_id": room_id,
                    "notif_count": summary.notif_count,
                    "unread_count": summary.unread_count,
                    "stream_ordering": summary.stream_ordering,
                }
                for ((user_id, room_id), summary) in summaries.items()
                if summary.old_user_id is None
            ],
        )

        txn.execute_batch(
            """
                UPDATE event_push_summary
                SET notif_count = ?, unread_count = ?, stream_ordering = ?
                WHERE user_id = ? AND room_id = ?
            """,
            (
                (
                    summary.notif_count,
                    summary.unread_count,
                    summary.stream_ordering,
                    user_id,
                    room_id,
                )
                for ((user_id, room_id), summary) in summaries.items()
                if summary.old_user_id is not None
            ),
        )

        txn.execute(
            "DELETE FROM event_push_actions"
            " WHERE ? <= stream_ordering AND stream_ordering < ? AND highlight = 0",
            (old_rotate_stream_ordering, rotate_to_stream_ordering),
        )

        logger.info("Rotating notifications, deleted %s push actions", txn.rowcount)

        txn.execute(
            "UPDATE event_push_summary_stream_ordering SET stream_ordering = ?",
            (rotate_to_stream_ordering,),
        )

    def _remove_old_push_actions_before_txn(
        self, txn, room_id, user_id, stream_ordering
    ):
        """
        Purges old push actions for a user and room before a given
        stream_ordering.

        We however keep a months worth of highlighted notifications, so that
        users can still get a list of recent highlights.

        Args:
            txn: The transcation
            room_id: Room ID to delete from
            user_id: user ID to delete for
            stream_ordering: The lowest stream ordering which will
                                  not be deleted.
        """
        txn.call_after(
            self.get_unread_event_push_actions_by_room_for_user.invalidate_many,
            (room_id, user_id),
        )

        # We need to join on the events table to get the received_ts for
        # event_push_actions and sqlite won't let us use a join in a delete so
        # we can't just delete where received_ts < x. Furthermore we can
        # only identify event_push_actions by a tuple of room_id, event_id
        # we we can't use a subquery.
        # Instead, we look up the stream ordering for the last event in that
        # room received before the threshold time and delete event_push_actions
        # in the room with a stream_odering before that.
        txn.execute(
            "DELETE FROM event_push_actions "
            " WHERE user_id = ? AND room_id = ? AND "
            " stream_ordering <= ?"
            " AND ((stream_ordering < ? AND highlight = 1) or highlight = 0)",
            (user_id, room_id, stream_ordering, self.stream_ordering_month_ago),
        )

        txn.execute(
            """
            DELETE FROM event_push_summary
            WHERE room_id = ? AND user_id = ? AND stream_ordering <= ?
        """,
            (room_id, user_id, stream_ordering),
        )


class EventPushActionsStore(EventPushActionsWorkerStore):
    EPA_HIGHLIGHT_INDEX = "epa_highlight_index"

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_index_update(
            self.EPA_HIGHLIGHT_INDEX,
            index_name="event_push_actions_u_highlight",
            table="event_push_actions",
            columns=["user_id", "stream_ordering"],
        )

        self.db_pool.updates.register_background_index_update(
            "event_push_actions_highlights_index",
            index_name="event_push_actions_highlights_index",
            table="event_push_actions",
            columns=["user_id", "room_id", "topological_ordering", "stream_ordering"],
            where_clause="highlight=1",
        )

    async def get_push_actions_for_user(
        self, user_id, before=None, limit=50, only_highlight=False
    ):
        def f(txn):
            before_clause = ""
            if before:
                before_clause = "AND epa.stream_ordering < ?"
                args = [user_id, before, limit]
            else:
                args = [user_id, limit]

            if only_highlight:
                if len(before_clause) > 0:
                    before_clause += " "
                before_clause += "AND epa.highlight = 1"

            # NB. This assumes event_ids are globally unique since
            # it makes the query easier to index
            sql = (
                "SELECT epa.event_id, epa.room_id,"
                " epa.stream_ordering, epa.topological_ordering,"
                " epa.actions, epa.highlight, epa.profile_tag, e.received_ts"
                " FROM event_push_actions epa, events e"
                " WHERE epa.event_id = e.event_id"
                " AND epa.user_id = ? %s"
                " AND epa.notif = 1"
                " ORDER BY epa.stream_ordering DESC"
                " LIMIT ?" % (before_clause,)
            )
            txn.execute(sql, args)
            return self.db_pool.cursor_to_dict(txn)

        push_actions = await self.db_pool.runInteraction("get_push_actions_for_user", f)
        for pa in push_actions:
            pa["actions"] = _deserialize_action(pa["actions"], pa["highlight"])
        return push_actions


def _action_has_highlight(actions):
    for action in actions:
        try:
            if action.get("set_tweak", None) == "highlight":
                return action.get("value", True)
        except AttributeError:
            pass

    return False


@attr.s(slots=True)
class _EventPushSummary:
    """Summary of pending event push actions for a given user in a given room.
    Used in _rotate_notifs_before_txn to manipulate results from event_push_actions.
    """

    unread_count = attr.ib(type=int)
    stream_ordering = attr.ib(type=int)
    old_user_id = attr.ib(type=str)
    notif_count = attr.ib(type=int)
