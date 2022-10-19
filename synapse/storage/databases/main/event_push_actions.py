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

"""Responsible for storing and fetching push actions / notifications.

There are two main uses for push actions:
  1. Sending out push to a user's device; and
  2. Tracking per-room per-user notification counts (used in sync requests).

For the former we simply use the `event_push_actions` table, which contains all
the calculated actions for a given user (which were calculated by the
`BulkPushRuleEvaluator`).

For the latter we could simply count the number of rows in `event_push_actions`
table for a given room/user, but in practice this is *very* heavyweight when
there were a large number of notifications (due to e.g. the user never reading a
room). Plus, keeping all push actions indefinitely uses a lot of disk space.

To fix these issues, we add a new table `event_push_summary` that tracks
per-user per-room counts of all notifications that happened before a stream
ordering S. Thus, to get the notification count for a user / room we can simply
query a single row in `event_push_summary` and count the number of rows in
`event_push_actions` with a stream ordering larger than S (and as long as S is
"recent", the number of rows needing to be scanned will be small).

The `event_push_summary` table is updated via a background job that periodically
chooses a new stream ordering S' (usually the latest stream ordering), counts
all notifications in `event_push_actions` between the existing S and S', and
adds them to the existing counts in `event_push_summary`.

This allows us to delete old rows from `event_push_actions` once those rows have
been counted and added to `event_push_summary` (we call this process
"rotation").


We need to handle when a user sends a read receipt to the room. Again this is
done as a background process. For each receipt we clear the row in
`event_push_summary` and count the number of notifications in
`event_push_actions` that happened after the receipt but before S, and insert
that count into `event_push_summary` (If the receipt happened *after* S then we
simply clear the `event_push_summary`.)

Note that its possible that if the read receipt is for an old event the relevant
`event_push_actions` rows will have been rotated and we get the wrong count
(it'll be too low). We accept this as a rare edge case that is unlikely to
impact the user much (since the vast majority of read receipts will be for the
latest event).

The last complication is to handle the race where we request the notifications
counts after a user sends a read receipt into the room, but *before* the
background update handles the receipt (without any special handling the counts
would be outdated). We fix this by including in `event_push_summary` the read
receipt we used when updating `event_push_summary`, and every time we query the
table we check if that matches the most recent read receipt in the room. If yes,
continue as above, if not we simply query the `event_push_actions` table
directly.

Since read receipts are almost always for recent events, scanning the
`event_push_actions` table in this case is unlikely to be a problem. Even if it
is a problem, it is temporary until the background job handles the new read
receipt.
"""

import logging
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    List,
    Mapping,
    Optional,
    Tuple,
    Union,
    cast,
)

import attr

from synapse.api.constants import MAIN_TIMELINE, ReceiptTypes
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore
from synapse.storage.databases.main.stream import StreamWorkerStore
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


DEFAULT_NOTIF_ACTION: List[Union[dict, str]] = [
    "notify",
    {"set_tweak": "highlight", "value": False},
]
DEFAULT_HIGHLIGHT_ACTION: List[Union[dict, str]] = [
    "notify",
    {"set_tweak": "sound", "value": "default"},
    {"set_tweak": "highlight"},
]


@attr.s(slots=True, auto_attribs=True)
class _RoomReceipt:
    """
    HttpPushAction instances include the information used to generate HTTP
    requests to a push gateway.
    """

    unthreaded_stream_ordering: int = 0
    # threaded_stream_ordering includes the main pseudo-thread.
    threaded_stream_ordering: Dict[str, int] = attr.Factory(dict)

    def is_unread(self, thread_id: str, stream_ordering: int) -> bool:
        """Returns True if the stream ordering is unread according to the receipt information."""

        # Only include push actions with a stream ordering after both the unthreaded
        # and threaded receipt. Properly handles a user without any receipts present.
        return (
            self.unthreaded_stream_ordering < stream_ordering
            and self.threaded_stream_ordering.get(thread_id, 0) < stream_ordering
        )


# A _RoomReceipt with no receipts in it.
MISSING_ROOM_RECEIPT = _RoomReceipt()


@attr.s(slots=True, frozen=True, auto_attribs=True)
class HttpPushAction:
    """
    HttpPushAction instances include the information used to generate HTTP
    requests to a push gateway.
    """

    event_id: str
    room_id: str
    stream_ordering: int
    actions: List[Union[dict, str]]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class EmailPushAction(HttpPushAction):
    """
    EmailPushAction instances include the information used to render an email
    push notification.
    """

    received_ts: Optional[int]


@attr.s(slots=True, frozen=True, auto_attribs=True)
class UserPushAction(EmailPushAction):
    """
    UserPushAction instances include the necessary information to respond to
    /notifications requests.
    """

    topological_ordering: int
    highlight: bool
    profile_tag: str


@attr.s(slots=True, auto_attribs=True)
class NotifCounts:
    """
    The per-user, per-room, per-thread count of notifications. Used by sync and push.
    """

    notify_count: int = 0
    unread_count: int = 0
    highlight_count: int = 0


@attr.s(slots=True, auto_attribs=True)
class RoomNotifCounts:
    """
    The per-user, per-room count of notifications. Used by sync and push.
    """

    main_timeline: NotifCounts
    # Map of thread ID to the notification counts.
    threads: Dict[str, NotifCounts]

    def __len__(self) -> int:
        # To properly account for the amount of space in any caches.
        return len(self.threads) + 1


def _serialize_action(
    actions: Collection[Union[Mapping, str]], is_highlight: bool
) -> str:
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


def _deserialize_action(actions: str, is_highlight: bool) -> List[Union[dict, str]]:
    """Custom deserializer for actions. This allows us to "compress" common actions"""
    if actions:
        return db_to_json(actions)

    if is_highlight:
        return DEFAULT_HIGHLIGHT_ACTION
    else:
        return DEFAULT_NOTIF_ACTION


class EventPushActionsWorkerStore(ReceiptsWorkerStore, StreamWorkerStore, SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        # Track when the process started.
        self._started_ts = self._clock.time_msec()

        # These get correctly set by _find_stream_orderings_for_times_txn
        self.stream_ordering_month_ago: Optional[int] = None
        self.stream_ordering_day_ago: Optional[int] = None

        cur = db_conn.cursor(txn_name="_find_stream_orderings_for_times_txn")
        self._find_stream_orderings_for_times_txn(cur)
        cur.close()

        self.find_stream_orderings_looping_call = self._clock.looping_call(
            self._find_stream_orderings_for_times, 10 * 60 * 1000
        )

        self._rotate_count = 10000
        self._doing_notif_rotation = False
        if hs.config.worker.run_background_tasks:
            self._rotate_notif_loop = self._clock.looping_call(
                self._rotate_notifs, 30 * 1000
            )

            self._clear_old_staging_loop = self._clock.looping_call(
                self._clear_old_push_actions_staging, 30 * 60 * 1000
            )

        self.db_pool.updates.register_background_index_update(
            "event_push_summary_unique_index",
            index_name="event_push_summary_unique_index",
            table="event_push_summary",
            columns=["user_id", "room_id"],
            unique=True,
            replaces_index="event_push_summary_user_rm",
        )

        self.db_pool.updates.register_background_index_update(
            "event_push_summary_unique_index2",
            index_name="event_push_summary_unique_index2",
            table="event_push_summary",
            columns=["user_id", "room_id", "thread_id"],
            unique=True,
        )

        self.db_pool.updates.register_background_update_handler(
            "event_push_backfill_thread_id",
            self._background_backfill_thread_id,
        )

        # Indexes which will be used to quickly make the thread_id column non-null.
        self.db_pool.updates.register_background_index_update(
            "event_push_actions_thread_id_null",
            index_name="event_push_actions_thread_id_null",
            table="event_push_actions",
            columns=["thread_id"],
            where_clause="thread_id IS NULL",
        )
        self.db_pool.updates.register_background_index_update(
            "event_push_summary_thread_id_null",
            index_name="event_push_summary_thread_id_null",
            table="event_push_summary",
            columns=["thread_id"],
            where_clause="thread_id IS NULL",
        )

        # Check ASAP (and then later, every 1s) to see if we have finished
        # background updates the event_push_actions and event_push_summary tables.
        self._clock.call_later(0.0, self._check_event_push_backfill_thread_id)
        self._event_push_backfill_thread_id_done = False

    @wrap_as_background_process("check_event_push_backfill_thread_id")
    async def _check_event_push_backfill_thread_id(self) -> None:
        """
        Has thread_id finished backfilling?

        If not, we need to just-in-time update it so the queries work.
        """
        done = await self.db_pool.updates.has_completed_background_update(
            "event_push_backfill_thread_id"
        )

        if done:
            self._event_push_backfill_thread_id_done = True
        else:
            # Reschedule to run.
            self._clock.call_later(15.0, self._check_event_push_backfill_thread_id)

    async def _background_backfill_thread_id(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        """
        Fill in the thread_id field for event_push_actions and event_push_summary.

        This is preparatory so that it can be made non-nullable in the future.

        Because all current (null) data is done in an unthreaded manner this
        simply assumes it is on the "main" timeline. Since event_push_actions
        are periodically cleared it is not possible to correctly re-calculate
        the thread_id.
        """
        event_push_actions_done = progress.get("event_push_actions_done", False)

        def add_thread_id_txn(
            txn: LoggingTransaction, start_stream_ordering: int
        ) -> int:
            sql = """
            SELECT stream_ordering
            FROM event_push_actions
            WHERE
                thread_id IS NULL
                AND stream_ordering > ?
            ORDER BY stream_ordering
            LIMIT ?
            """
            txn.execute(sql, (start_stream_ordering, batch_size))

            # No more rows to process.
            rows = txn.fetchall()
            if not rows:
                progress["event_push_actions_done"] = True
                self.db_pool.updates._background_update_progress_txn(
                    txn, "event_push_backfill_thread_id", progress
                )
                return 0

            # Update the thread ID for any of those rows.
            max_stream_ordering = rows[-1][0]

            sql = """
            UPDATE event_push_actions
            SET thread_id = 'main'
            WHERE ? < stream_ordering AND stream_ordering <= ? AND thread_id IS NULL
            """
            txn.execute(
                sql,
                (
                    start_stream_ordering,
                    max_stream_ordering,
                ),
            )

            # Update progress.
            processed_rows = txn.rowcount
            progress["max_event_push_actions_stream_ordering"] = max_stream_ordering
            self.db_pool.updates._background_update_progress_txn(
                txn, "event_push_backfill_thread_id", progress
            )

            return processed_rows

        def add_thread_id_summary_txn(txn: LoggingTransaction) -> int:
            min_user_id = progress.get("max_summary_user_id", "")
            min_room_id = progress.get("max_summary_room_id", "")

            # Slightly overcomplicated query for getting the Nth user ID / room
            # ID tuple, or the last if there are less than N remaining.
            sql = """
            SELECT user_id, room_id FROM (
                SELECT user_id, room_id FROM event_push_summary
                WHERE (user_id, room_id) > (?, ?)
                    AND thread_id IS NULL
                ORDER BY user_id, room_id
                LIMIT ?
            ) AS e
            ORDER BY user_id DESC, room_id DESC
            LIMIT 1
            """

            txn.execute(sql, (min_user_id, min_room_id, batch_size))
            row = txn.fetchone()
            if not row:
                return 0

            max_user_id, max_room_id = row

            sql = """
            UPDATE event_push_summary
            SET thread_id = 'main'
            WHERE
                (?, ?) < (user_id, room_id) AND (user_id, room_id) <= (?, ?)
                AND thread_id IS NULL
            """
            txn.execute(sql, (min_user_id, min_room_id, max_user_id, max_room_id))
            processed_rows = txn.rowcount

            progress["max_summary_user_id"] = max_user_id
            progress["max_summary_room_id"] = max_room_id
            self.db_pool.updates._background_update_progress_txn(
                txn, "event_push_backfill_thread_id", progress
            )

            return processed_rows

        # First update the event_push_actions table, then the event_push_summary table.
        #
        # Note that the event_push_actions_staging table is ignored since it is
        # assumed that items in that table will only exist for a short period of
        # time.
        if not event_push_actions_done:
            result = await self.db_pool.runInteraction(
                "event_push_backfill_thread_id",
                add_thread_id_txn,
                progress.get("max_event_push_actions_stream_ordering", 0),
            )
        else:
            result = await self.db_pool.runInteraction(
                "event_push_backfill_thread_id",
                add_thread_id_summary_txn,
            )

            # Only done after the event_push_summary table is done.
            if not result:
                await self.db_pool.updates._end_background_update(
                    "event_push_backfill_thread_id"
                )

        return result

    @cached(tree=True, max_entries=5000, iterable=True)
    async def get_unread_event_push_actions_by_room_for_user(
        self,
        room_id: str,
        user_id: str,
    ) -> RoomNotifCounts:
        """Get the notification count, the highlight count and the unread message count
        for a given user in a given room after their latest read receipt.

        Note that this function assumes the user to be a current member of the room,
        since it's either called by the sync handler to handle joined room entries, or by
        the HTTP pusher to calculate the badge of unread joined rooms.

        Args:
            room_id: The room to retrieve the counts in.
            user_id: The user to retrieve the counts for.

        Returns
            A RoomNotifCounts object containing the notification count, the
            highlight count and the unread message count for both the main timeline
            and threads.
        """
        return await self.db_pool.runInteraction(
            "get_unread_event_push_actions_by_room",
            self._get_unread_counts_by_receipt_txn,
            room_id,
            user_id,
        )

    def _get_unread_counts_by_receipt_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        user_id: str,
    ) -> RoomNotifCounts:
        # Get the stream ordering of the user's latest receipt in the room.
        result = self.get_last_unthreaded_receipt_for_user_txn(
            txn,
            user_id,
            room_id,
            receipt_types=(ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE),
        )

        if result:
            _, stream_ordering = result

        else:
            # If the user has no receipts in the room, retrieve the stream ordering for
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

    def _get_unread_counts_by_pos_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        user_id: str,
        unthreaded_receipt_stream_ordering: int,
    ) -> RoomNotifCounts:
        """Get the number of unread messages for a user/room that have happened
        since the given stream ordering.

        Args:
            txn: The database transaction.
            room_id: The room ID to get unread counts for.
            user_id: The user ID to get unread counts for.
            unthreaded_receipt_stream_ordering: The stream ordering of the user's latest
                unthreaded receipt in the room. If there are no unthreaded receipts,
                the stream ordering of the user's join event.

        Returns:
            A RoomNotifCounts object containing the notification count, the
            highlight count and the unread message count for both the main timeline
            and threads.
        """

        main_counts = NotifCounts()
        thread_counts: Dict[str, NotifCounts] = {}

        def _get_thread(thread_id: str) -> NotifCounts:
            if thread_id == MAIN_TIMELINE:
                return main_counts
            return thread_counts.setdefault(thread_id, NotifCounts())

        receipt_types_clause, receipts_args = make_in_list_sql_clause(
            self.database_engine,
            "receipt_type",
            (ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE),
        )

        # First ensure that the existing rows have an updated thread_id field.
        if not self._event_push_backfill_thread_id_done:
            txn.execute(
                """
                UPDATE event_push_summary
                SET thread_id = ?
                WHERE room_id = ? AND user_id = ? AND thread_id is NULL
                """,
                (MAIN_TIMELINE, room_id, user_id),
            )
            txn.execute(
                """
                UPDATE event_push_actions
                SET thread_id = ?
                WHERE room_id = ? AND user_id = ? AND thread_id is NULL
                """,
                (MAIN_TIMELINE, room_id, user_id),
            )

        # First we pull the counts from the summary table.
        #
        # We check that `last_receipt_stream_ordering` matches the stream ordering of the
        # latest receipt for the thread (which may be either the unthreaded read receipt
        # or the threaded read receipt).
        #
        # If it doesn't match then a new read receipt has arrived and we haven't yet
        # updated the counts in `event_push_summary` to reflect that; in that case we
        # simply ignore `event_push_summary` counts.
        #
        # We then do a manual count of all the rows in the `event_push_actions` table
        # for any user/room/thread which did not have a valid summary found.
        #
        # If `last_receipt_stream_ordering` is null then that means it's up-to-date
        # (as the row was written by an older version of Synapse that
        # updated `event_push_summary` synchronously when persisting a new read
        # receipt).
        txn.execute(
            f"""
                SELECT notif_count, COALESCE(unread_count, 0), thread_id
                FROM event_push_summary
                LEFT JOIN (
                    SELECT thread_id, MAX(stream_ordering) AS threaded_receipt_stream_ordering
                    FROM receipts_linearized
                    LEFT JOIN events USING (room_id, event_id)
                    WHERE
                        user_id = ?
                        AND room_id = ?
                        AND stream_ordering > ?
                        AND {receipt_types_clause}
                    GROUP BY thread_id
                ) AS receipts USING (thread_id)
                WHERE room_id = ? AND user_id = ?
                AND (
                    (last_receipt_stream_ordering IS NULL AND stream_ordering > COALESCE(threaded_receipt_stream_ordering, ?))
                    OR last_receipt_stream_ordering = COALESCE(threaded_receipt_stream_ordering, ?)
                ) AND (notif_count != 0 OR COALESCE(unread_count, 0) != 0)
            """,
            (
                user_id,
                room_id,
                unthreaded_receipt_stream_ordering,
                *receipts_args,
                room_id,
                user_id,
                unthreaded_receipt_stream_ordering,
                unthreaded_receipt_stream_ordering,
            ),
        )
        summarised_threads = set()
        for notif_count, unread_count, thread_id in txn:
            summarised_threads.add(thread_id)
            counts = _get_thread(thread_id)
            counts.notify_count += notif_count
            counts.unread_count += unread_count

        # Next we need to count highlights, which aren't summarised
        sql = f"""
            SELECT COUNT(*), thread_id FROM event_push_actions
            LEFT JOIN (
                SELECT thread_id, MAX(stream_ordering) AS threaded_receipt_stream_ordering
                FROM receipts_linearized
                LEFT JOIN events USING (room_id, event_id)
                WHERE
                    user_id = ?
                    AND room_id = ?
                    AND stream_ordering > ?
                    AND {receipt_types_clause}
                GROUP BY thread_id
            ) AS receipts USING (thread_id)
            WHERE user_id = ?
                AND room_id = ?
                AND stream_ordering > COALESCE(threaded_receipt_stream_ordering, ?)
                AND highlight = 1
            GROUP BY thread_id
        """
        txn.execute(
            sql,
            (
                user_id,
                room_id,
                unthreaded_receipt_stream_ordering,
                *receipts_args,
                user_id,
                room_id,
                unthreaded_receipt_stream_ordering,
            ),
        )
        for highlight_count, thread_id in txn:
            _get_thread(thread_id).highlight_count += highlight_count

        # For threads which were summarised we need to count actions since the last
        # rotation.
        thread_id_clause, thread_id_args = make_in_list_sql_clause(
            self.database_engine, "thread_id", summarised_threads
        )

        # The (inclusive) event stream ordering that was previously summarised.
        rotated_upto_stream_ordering = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        unread_counts = self._get_notif_unread_count_for_user_room(
            txn, room_id, user_id, rotated_upto_stream_ordering
        )
        for notif_count, unread_count, thread_id in unread_counts:
            if thread_id not in summarised_threads:
                continue

            if thread_id == MAIN_TIMELINE:
                counts.notify_count += notif_count
                counts.unread_count += unread_count
            elif thread_id in thread_counts:
                thread_counts[thread_id].notify_count += notif_count
                thread_counts[thread_id].unread_count += unread_count
            else:
                # Previous thread summaries of 0 are discarded above.
                #
                # TODO If empty summaries are deleted this can be removed.
                thread_counts[thread_id] = NotifCounts(
                    notify_count=notif_count,
                    unread_count=unread_count,
                    highlight_count=0,
                )

        # Finally we need to count push actions that aren't included in the
        # summary returned above. This might be due to recent events that haven't
        # been summarised yet or the summary is out of date due to a recent read
        # receipt.
        sql = f"""
            SELECT
                COUNT(CASE WHEN notif = 1 THEN 1 END),
                COUNT(CASE WHEN unread = 1 THEN 1 END),
                thread_id
            FROM event_push_actions
            LEFT JOIN (
                SELECT thread_id, MAX(stream_ordering) AS threaded_receipt_stream_ordering
                FROM receipts_linearized
                LEFT JOIN events USING (room_id, event_id)
                WHERE
                    user_id = ?
                    AND room_id = ?
                    AND stream_ordering > ?
                    AND {receipt_types_clause}
                GROUP BY thread_id
            ) AS receipts USING (thread_id)
            WHERE user_id = ?
                AND room_id = ?
                AND stream_ordering > COALESCE(threaded_receipt_stream_ordering, ?)
                AND NOT {thread_id_clause}
            GROUP BY thread_id
        """
        txn.execute(
            sql,
            (
                user_id,
                room_id,
                unthreaded_receipt_stream_ordering,
                *receipts_args,
                user_id,
                room_id,
                unthreaded_receipt_stream_ordering,
                *thread_id_args,
            ),
        )
        for notif_count, unread_count, thread_id in txn:
            counts = _get_thread(thread_id)
            counts.notify_count += notif_count
            counts.unread_count += unread_count

        return RoomNotifCounts(main_counts, thread_counts)

    def _get_notif_unread_count_for_user_room(
        self,
        txn: LoggingTransaction,
        room_id: str,
        user_id: str,
        stream_ordering: int,
        max_stream_ordering: Optional[int] = None,
        thread_id: Optional[str] = None,
    ) -> List[Tuple[int, int, str]]:
        """Returns the notify and unread counts from `event_push_actions` for
        the given user/room in the given range.

        Does not consult `event_push_summary` table, which may include push
        actions that have been deleted from `event_push_actions` table.

        Args:
            txn: The database transaction.
            room_id: The room ID to get unread counts for.
            user_id: The user ID to get unread counts for.
            stream_ordering: The (exclusive) minimum stream ordering to consider.
            max_stream_ordering: The (inclusive) maximum stream ordering to consider.
                If this is not given, then no maximum is applied.
            thread_id: The thread ID to fetch unread counts for. If this is not provided
                then the results for *all* threads is returned.

                Note that if this is provided the resulting list will only have 0 or
                1 tuples in it.

        Return:
            A tuple of the notif count and unread count in the given range for
            each thread.
        """

        # If there have been no events in the room since the stream ordering,
        # there can't be any push actions either.
        if not self._events_stream_cache.has_entity_changed(room_id, stream_ordering):
            return []

        stream_ordering_clause = ""
        args = [user_id, room_id, stream_ordering]
        if max_stream_ordering is not None:
            stream_ordering_clause = "AND ea.stream_ordering <= ?"
            args.append(max_stream_ordering)

            # If the max stream ordering is less than the min stream ordering,
            # then obviously there are zero push actions in that range.
            if max_stream_ordering <= stream_ordering:
                return []

        # Either limit the results to a specific thread or fetch all threads.
        thread_id_clause = ""
        if thread_id is not None:
            thread_id_clause = "AND thread_id = ?"
            args.append(thread_id)

        sql = f"""
            SELECT
               COUNT(CASE WHEN notif = 1 THEN 1 END),
               COUNT(CASE WHEN unread = 1 THEN 1 END),
               thread_id
            FROM event_push_actions ea
            WHERE user_id = ?
               AND room_id = ?
               AND ea.stream_ordering > ?
               {stream_ordering_clause}
               {thread_id_clause}
            GROUP BY thread_id
        """

        txn.execute(sql, args)
        return cast(List[Tuple[int, int, str]], txn.fetchall())

    async def get_push_action_users_in_range(
        self, min_stream_ordering: int, max_stream_ordering: int
    ) -> List[str]:
        def f(txn: LoggingTransaction) -> List[str]:
            sql = (
                "SELECT DISTINCT(user_id) FROM event_push_actions WHERE"
                " stream_ordering >= ? AND stream_ordering <= ? AND notif = 1"
            )
            txn.execute(sql, (min_stream_ordering, max_stream_ordering))
            return [r[0] for r in txn]

        return await self.db_pool.runInteraction("get_push_action_users_in_range", f)

    def _get_receipts_by_room_txn(
        self, txn: LoggingTransaction, user_id: str
    ) -> Dict[str, _RoomReceipt]:
        """
        Generate a map of room ID to the latest stream ordering that has been
        read by the given user.

        Args:
            txn:
            user_id: The user to fetch receipts for.

        Returns:
            A map including all rooms the user is in with a receipt. It maps
            room IDs to _RoomReceipt instances
        """
        receipt_types_clause, args = make_in_list_sql_clause(
            self.database_engine,
            "receipt_type",
            (ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE),
        )

        sql = f"""
            SELECT room_id, thread_id, MAX(stream_ordering)
            FROM receipts_linearized
            INNER JOIN events USING (room_id, event_id)
            WHERE {receipt_types_clause}
            AND user_id = ?
            GROUP BY room_id, thread_id
        """

        args.extend((user_id,))
        txn.execute(sql, args)

        result: Dict[str, _RoomReceipt] = {}
        for room_id, thread_id, stream_ordering in txn:
            room_receipt = result.setdefault(room_id, _RoomReceipt())
            if thread_id is None:
                room_receipt.unthreaded_stream_ordering = stream_ordering
            else:
                room_receipt.threaded_stream_ordering[thread_id] = stream_ordering

        return result

    async def get_unread_push_actions_for_user_in_range_for_http(
        self,
        user_id: str,
        min_stream_ordering: int,
        max_stream_ordering: int,
        limit: int = 20,
    ) -> List[HttpPushAction]:
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

        receipts_by_room = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http_receipts",
            self._get_receipts_by_room_txn,
            user_id=user_id,
        )

        def get_push_actions_txn(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, str, int, str, bool]]:
            sql = """
                SELECT ep.event_id, ep.room_id, ep.thread_id, ep.stream_ordering,
                    ep.actions, ep.highlight
                FROM event_push_actions AS ep
                WHERE
                    ep.user_id = ?
                    AND ep.stream_ordering > ?
                    AND ep.stream_ordering <= ?
                    AND ep.notif = 1
                ORDER BY ep.stream_ordering ASC LIMIT ?
            """
            txn.execute(sql, (user_id, min_stream_ordering, max_stream_ordering, limit))
            return cast(List[Tuple[str, str, str, int, str, bool]], txn.fetchall())

        push_actions = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http", get_push_actions_txn
        )

        notifs = [
            HttpPushAction(
                event_id=event_id,
                room_id=room_id,
                stream_ordering=stream_ordering,
                actions=_deserialize_action(actions, highlight),
            )
            for event_id, room_id, thread_id, stream_ordering, actions, highlight in push_actions
            if receipts_by_room.get(room_id, MISSING_ROOM_RECEIPT).is_unread(
                thread_id, stream_ordering
            )
        ]

        # Now sort it so it's ordered correctly, since currently it will
        # contain results from the first query, correctly ordered, followed
        # by results from the second query, but we want them all ordered
        # by stream_ordering, oldest first.
        notifs.sort(key=lambda r: r.stream_ordering)

        # Take only up to the limit. We have to stop at the limit because
        # one of the subqueries may have hit the limit.
        return notifs[:limit]

    async def get_unread_push_actions_for_user_in_range_for_email(
        self,
        user_id: str,
        min_stream_ordering: int,
        max_stream_ordering: int,
        limit: int = 20,
    ) -> List[EmailPushAction]:
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

        receipts_by_room = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email_receipts",
            self._get_receipts_by_room_txn,
            user_id=user_id,
        )

        def get_push_actions_txn(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, str, int, str, bool, int]]:
            sql = """
                SELECT ep.event_id, ep.room_id, ep.thread_id, ep.stream_ordering,
                    ep.actions, ep.highlight, e.received_ts
                FROM event_push_actions AS ep
                INNER JOIN events AS e USING (room_id, event_id)
                WHERE
                    ep.user_id = ?
                    AND ep.stream_ordering > ?
                    AND ep.stream_ordering <= ?
                    AND ep.notif = 1
                ORDER BY ep.stream_ordering DESC LIMIT ?
            """
            txn.execute(sql, (user_id, min_stream_ordering, max_stream_ordering, limit))
            return cast(List[Tuple[str, str, str, int, str, bool, int]], txn.fetchall())

        push_actions = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email", get_push_actions_txn
        )

        # Make a list of dicts from the two sets of results.
        notifs = [
            EmailPushAction(
                event_id=event_id,
                room_id=room_id,
                stream_ordering=stream_ordering,
                actions=_deserialize_action(actions, highlight),
                received_ts=received_ts,
            )
            for event_id, room_id, thread_id, stream_ordering, actions, highlight, received_ts in push_actions
            if receipts_by_room.get(room_id, MISSING_ROOM_RECEIPT).is_unread(
                thread_id, stream_ordering
            )
        ]

        # Now sort it so it's ordered correctly, since currently it will
        # contain results from the first query, correctly ordered, followed
        # by results from the second query, but we want them all ordered
        # by received_ts (most recent first)
        notifs.sort(key=lambda r: -(r.received_ts or 0))

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

        def _get_if_maybe_push_in_range_for_user_txn(txn: LoggingTransaction) -> bool:
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
        user_id_actions: Dict[str, Collection[Union[Mapping, str]]],
        count_as_unread: bool,
        thread_id: str,
    ) -> None:
        """Add the push actions for the event to the push action staging area.

        Args:
            event_id
            user_id_actions: A mapping of user_id to list of push actions, where
                an action can either be a string or dict.
            count_as_unread: Whether this event should increment unread counts.
            thread_id: The thread this event is parent of, if applicable.
        """
        if not user_id_actions:
            return

        # This is a helper function for generating the necessary tuple that
        # can be used to insert into the `event_push_actions_staging` table.
        def _gen_entry(
            user_id: str, actions: Collection[Union[Mapping, str]]
        ) -> Tuple[str, str, str, int, int, int, str, int]:
            is_highlight = 1 if _action_has_highlight(actions) else 0
            notif = 1 if "notify" in actions else 0
            return (
                event_id,  # event_id column
                user_id,  # user_id column
                _serialize_action(actions, bool(is_highlight)),  # actions column
                notif,  # notif column
                is_highlight,  # highlight column
                int(count_as_unread),  # unread column
                thread_id,  # thread_id column
                self._clock.time_msec(),  # inserted_ts column
            )

        await self.db_pool.simple_insert_many(
            "event_push_actions_staging",
            keys=(
                "event_id",
                "user_id",
                "actions",
                "notif",
                "highlight",
                "unread",
                "thread_id",
                "inserted_ts",
            ),
            values=[
                _gen_entry(user_id, actions)
                for user_id, actions in user_id_actions.items()
            ],
            desc="add_push_actions_to_staging",
        )

    async def remove_push_actions_from_staging(self, event_id: str) -> None:
        """Called if we failed to persist the event to ensure that stale push
        actions don't build up in the DB
        """

        try:
            await self.db_pool.simple_delete(
                table="event_push_actions_staging",
                keyvalues={"event_id": event_id},
                desc="remove_push_actions_from_staging",
            )
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
    def _find_first_stream_ordering_after_ts_txn(
        txn: LoggingTransaction, ts: int
    ) -> int:
        """
        Find the stream_ordering of the first event that was received on or
        after a given timestamp. This is relatively slow as there is no index
        on received_ts but we can then use this to delete push actions before
        this.

        received_ts must necessarily be in the same order as stream_ordering
        and stream_ordering is indexed, so we manually binary search using
        stream_ordering

        Args:
            txn:
            ts: timestamp to search for

        Returns:
            The stream ordering
        """
        txn.execute("SELECT MAX(stream_ordering) FROM events")
        max_stream_ordering = cast(Tuple[Optional[int]], txn.fetchone())[0]

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
        sql = """
            SELECT received_ts FROM events
            WHERE stream_ordering <= ?
            ORDER BY stream_ordering DESC
            LIMIT 1
        """

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

    async def get_time_of_last_push_action_before(
        self, stream_ordering: int
    ) -> Optional[int]:
        def f(txn: LoggingTransaction) -> Optional[Tuple[int]]:
            sql = """
                SELECT e.received_ts
                FROM event_push_actions AS ep
                JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id
                WHERE ep.stream_ordering > ? AND notif = 1
                ORDER BY ep.stream_ordering ASC
                LIMIT 1
            """
            txn.execute(sql, (stream_ordering,))
            return cast(Optional[Tuple[int]], txn.fetchone())

        result = await self.db_pool.runInteraction(
            "get_time_of_last_push_action_before", f
        )
        return result[0] if result else None

    @wrap_as_background_process("rotate_notifs")
    async def _rotate_notifs(self) -> None:
        if self._doing_notif_rotation or self.stream_ordering_day_ago is None:
            return
        self._doing_notif_rotation = True

        try:
            # First we recalculate push summaries and delete stale push actions
            # for rooms/users with new receipts.
            while True:
                logger.debug("Handling new receipts")

                caught_up = await self.db_pool.runInteraction(
                    "_handle_new_receipts_for_notifs_txn",
                    self._handle_new_receipts_for_notifs_txn,
                )
                if caught_up:
                    break

            # Then we update the event push summaries for any new events
            while True:
                logger.info("Rotating notifications")

                caught_up = await self.db_pool.runInteraction(
                    "_rotate_notifs", self._rotate_notifs_txn
                )
                if caught_up:
                    break

            # Finally we clear out old event push actions.
            await self._remove_old_push_actions_that_have_rotated()
        finally:
            self._doing_notif_rotation = False

    def _handle_new_receipts_for_notifs_txn(self, txn: LoggingTransaction) -> bool:
        """Check for new read receipts and delete from event push actions.

        Any push actions which predate the user's most recent read receipt are
        now redundant, so we can remove them from `event_push_actions` and
        update `event_push_summary`.

        Returns true if all new receipts have been processed.
        """

        limit = 100

        # The (inclusive) receipt stream ID that was previously processed..
        min_receipts_stream_id = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_last_receipt_stream_id",
            keyvalues={},
            retcol="stream_id",
        )

        max_receipts_stream_id = self._receipts_id_gen.get_current_token()

        # The (inclusive) event stream ordering that was previously summarised.
        old_rotate_stream_ordering = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        sql = """
            SELECT r.stream_id, r.room_id, r.user_id, r.thread_id, e.stream_ordering
            FROM receipts_linearized AS r
            INNER JOIN events AS e USING (event_id)
            WHERE ? < r.stream_id AND r.stream_id <= ? AND user_id LIKE ?
            ORDER BY r.stream_id ASC
            LIMIT ?
        """

        # We only want local users, so we add a dodgy filter to the above query
        # and recheck it below.
        user_filter = "%:" + self.hs.hostname

        txn.execute(
            sql,
            (
                min_receipts_stream_id,
                max_receipts_stream_id,
                user_filter,
                limit,
            ),
        )
        rows = cast(List[Tuple[int, str, str, Optional[str], int]], txn.fetchall())

        # For each new read receipt we delete push actions from before it and
        # recalculate the summary.
        #
        # Care must be taken of whether it is a threaded or unthreaded receipt.
        for _, room_id, user_id, thread_id, stream_ordering in rows:
            # Only handle our own read receipts.
            if not self.hs.is_mine_id(user_id):
                continue

            thread_clause = ""
            thread_args: Tuple = ()
            if thread_id is not None:
                thread_clause = "AND thread_id = ?"
                thread_args = (thread_id,)

            # For each new read receipt we delete push actions from before it and
            # recalculate the summary.
            txn.execute(
                f"""
                DELETE FROM event_push_actions
                WHERE room_id = ?
                    AND user_id = ?
                    AND stream_ordering <= ?
                    AND highlight = 0
                    {thread_clause}
                """,
                (room_id, user_id, stream_ordering, *thread_args),
            )

            # First ensure that the existing rows have an updated thread_id field.
            if not self._event_push_backfill_thread_id_done:
                txn.execute(
                    """
                    UPDATE event_push_summary
                    SET thread_id = ?
                    WHERE room_id = ? AND user_id = ? AND thread_id is NULL
                    """,
                    (MAIN_TIMELINE, room_id, user_id),
                )
                txn.execute(
                    """
                    UPDATE event_push_actions
                    SET thread_id = ?
                    WHERE room_id = ? AND user_id = ? AND thread_id is NULL
                    """,
                    (MAIN_TIMELINE, room_id, user_id),
                )

            # Fetch the notification counts between the stream ordering of the
            # latest receipt and what was previously summarised.
            unread_counts = self._get_notif_unread_count_for_user_room(
                txn,
                room_id,
                user_id,
                stream_ordering,
                old_rotate_stream_ordering,
                thread_id,
            )

            # For an unthreaded receipt, mark the summary for all threads in the room
            # as cleared.
            if thread_id is None:
                self.db_pool.simple_update_txn(
                    txn,
                    table="event_push_summary",
                    keyvalues={"user_id": user_id, "room_id": room_id},
                    updatevalues={
                        "notif_count": 0,
                        "unread_count": 0,
                        "stream_ordering": old_rotate_stream_ordering,
                        "last_receipt_stream_ordering": stream_ordering,
                    },
                )

            # For a threaded receipt, we *always* want to update that receipt,
            # event if there are no new notifications in that thread. This ensures
            # the stream_ordering & last_receipt_stream_ordering are updated.
            elif not unread_counts:
                unread_counts = [(0, 0, thread_id)]

            # Then any updated threads get their notification count and unread
            # count updated.
            self.db_pool.simple_update_many_txn(
                txn,
                table="event_push_summary",
                key_names=("room_id", "user_id", "thread_id"),
                key_values=[(room_id, user_id, row[2]) for row in unread_counts],
                value_names=(
                    "notif_count",
                    "unread_count",
                    "stream_ordering",
                    "last_receipt_stream_ordering",
                ),
                value_values=[
                    (row[0], row[1], old_rotate_stream_ordering, stream_ordering)
                    for row in unread_counts
                ],
            )

        # We always update `event_push_summary_last_receipt_stream_id` to
        # ensure that we don't rescan the same receipts for remote users.

        receipts_last_processed_stream_id = max_receipts_stream_id
        if len(rows) >= limit:
            # If we pulled out a limited number of rows we only update the
            # position to the last receipt we processed, so we continue
            # processing the rest next iteration.
            receipts_last_processed_stream_id = rows[-1][0]

        self.db_pool.simple_update_txn(
            txn,
            table="event_push_summary_last_receipt_stream_id",
            keyvalues={},
            updatevalues={"stream_id": receipts_last_processed_stream_id},
        )

        return len(rows) < limit

    def _rotate_notifs_txn(self, txn: LoggingTransaction) -> bool:
        """Archives older notifications (from event_push_actions) into event_push_summary.

        Returns whether the archiving process has caught up or not.
        """

        # The (inclusive) event stream ordering that was previously summarised.
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

            # We need to bound by the current token to ensure that we handle
            # out-of-order writes correctly.
            rotate_to_stream_ordering = min(
                offset_stream_ordering, self._stream_id_gen.get_current_token()
            )
            caught_up = False
        else:
            rotate_to_stream_ordering = self._stream_id_gen.get_current_token()
            caught_up = True

        logger.info("Rotating notifications up to: %s", rotate_to_stream_ordering)

        self._rotate_notifs_before_txn(
            txn, old_rotate_stream_ordering, rotate_to_stream_ordering
        )

        return caught_up

    def _rotate_notifs_before_txn(
        self,
        txn: LoggingTransaction,
        old_rotate_stream_ordering: int,
        rotate_to_stream_ordering: int,
    ) -> None:
        """Archives older notifications (from event_push_actions) into event_push_summary.

        Any event_push_actions between old_rotate_stream_ordering (exclusive) and
        rotate_to_stream_ordering (inclusive) will be added to the event_push_summary
        table.

        Args:
            txn: The database transaction.
            old_rotate_stream_ordering: The previous maximum event stream ordering.
            rotate_to_stream_ordering: The new maximum event stream ordering to summarise.
        """

        # Ensure that any new actions have an updated thread_id.
        if not self._event_push_backfill_thread_id_done:
            txn.execute(
                """
                UPDATE event_push_actions
                SET thread_id = ?
                WHERE ? < stream_ordering AND stream_ordering <= ? AND thread_id IS NULL
                """,
                (MAIN_TIMELINE, old_rotate_stream_ordering, rotate_to_stream_ordering),
            )

        # XXX Do we need to update summaries here too?

        # Calculate the new counts that should be upserted into event_push_summary
        sql = """
            SELECT user_id, room_id, thread_id,
                coalesce(old.%s, 0) + upd.cnt,
                upd.stream_ordering
            FROM (
                SELECT user_id, room_id, thread_id, count(*) as cnt,
                    max(ea.stream_ordering) as stream_ordering
                FROM event_push_actions AS ea
                LEFT JOIN event_push_summary AS old USING (user_id, room_id, thread_id)
                WHERE ? < ea.stream_ordering AND ea.stream_ordering <= ?
                    AND (
                        old.last_receipt_stream_ordering IS NULL
                        OR old.last_receipt_stream_ordering < ea.stream_ordering
                    )
                    AND %s = 1
                GROUP BY user_id, room_id, thread_id
            ) AS upd
            LEFT JOIN event_push_summary AS old USING (user_id, room_id, thread_id)
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
        summaries: Dict[Tuple[str, str, str], _EventPushSummary] = {}
        for row in txn:
            summaries[(row[0], row[1], row[2])] = _EventPushSummary(
                unread_count=row[3],
                stream_ordering=row[4],
                notif_count=0,
            )

        # Then get the count of notifications.
        txn.execute(
            sql % ("notif_count", "notif"),
            (old_rotate_stream_ordering, rotate_to_stream_ordering),
        )

        for row in txn:
            if (row[0], row[1], row[2]) in summaries:
                summaries[(row[0], row[1], row[2])].notif_count = row[3]
            else:
                # Because the rules on notifying are different than the rules on marking
                # a message unread, we might end up with messages that notify but aren't
                # marked unread, so we might not have a summary for this (user, room)
                # tuple to complete.
                summaries[(row[0], row[1], row[2])] = _EventPushSummary(
                    unread_count=0,
                    stream_ordering=row[4],
                    notif_count=row[3],
                )

        logger.info("Rotating notifications, handling %d rows", len(summaries))

        # Ensure that any updated threads have the proper thread_id.
        if not self._event_push_backfill_thread_id_done:
            txn.execute_batch(
                """
                UPDATE event_push_summary
                SET thread_id = ?
                WHERE room_id = ? AND user_id = ? AND thread_id is NULL
                """,
                [
                    (MAIN_TIMELINE, room_id, user_id)
                    for user_id, room_id, _ in summaries
                ],
            )

        self.db_pool.simple_upsert_many_txn(
            txn,
            table="event_push_summary",
            key_names=("user_id", "room_id", "thread_id"),
            key_values=[
                (user_id, room_id, thread_id)
                for user_id, room_id, thread_id in summaries
            ],
            value_names=("notif_count", "unread_count", "stream_ordering"),
            value_values=[
                (
                    summary.notif_count,
                    summary.unread_count,
                    summary.stream_ordering,
                )
                for summary in summaries.values()
            ],
        )

        txn.execute(
            "UPDATE event_push_summary_stream_ordering SET stream_ordering = ?",
            (rotate_to_stream_ordering,),
        )

    async def _remove_old_push_actions_that_have_rotated(self) -> None:
        """
        Clear out old push actions that have been summarised (and are older than
        1 day ago).
        """

        # We want to clear out anything that is older than a day that *has* already
        # been rotated.
        rotated_upto_stream_ordering = await self.db_pool.simple_select_one_onecol(
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        max_stream_ordering_to_delete = min(
            rotated_upto_stream_ordering, self.stream_ordering_day_ago
        )

        def remove_old_push_actions_that_have_rotated_txn(
            txn: LoggingTransaction,
        ) -> bool:
            # We don't want to clear out too much at a time, so we bound our
            # deletes.
            batch_size = self._rotate_count

            txn.execute(
                """
                SELECT stream_ordering FROM event_push_actions
                WHERE stream_ordering <= ? AND highlight = 0
                ORDER BY stream_ordering ASC LIMIT 1 OFFSET ?
                """,
                (
                    max_stream_ordering_to_delete,
                    batch_size,
                ),
            )
            stream_row = txn.fetchone()

            if stream_row:
                (stream_ordering,) = stream_row
            else:
                stream_ordering = max_stream_ordering_to_delete

            # We need to use a inclusive bound here to handle the case where a
            # single stream ordering has more than `batch_size` rows.
            txn.execute(
                """
                DELETE FROM event_push_actions
                WHERE stream_ordering <= ? AND highlight = 0
                """,
                (stream_ordering,),
            )

            logger.info("Rotating notifications, deleted %s push actions", txn.rowcount)

            return txn.rowcount < batch_size

        while True:
            done = await self.db_pool.runInteraction(
                "_remove_old_push_actions_that_have_rotated",
                remove_old_push_actions_that_have_rotated_txn,
            )
            if done:
                break

    @wrap_as_background_process("_clear_old_push_actions_staging")
    async def _clear_old_push_actions_staging(self) -> None:
        """Clear out any old event push actions from the staging table for
        events that we failed to persist.
        """

        # We delete anything more than an hour old, on the assumption that we'll
        # never take more than an hour to persist an event.
        delete_before_ts = self._clock.time_msec() - 60 * 60 * 1000

        if self._started_ts > delete_before_ts:
            # We need to wait for at least an hour before we started deleting,
            # so that we know it's safe to delete rows with NULL `inserted_ts`.
            return

        # We don't have an index on `inserted_ts`, instead we assume that the
        # number of "live" rows in `event_push_actions_staging` is small enough
        # that an infrequent periodic scan won't cause a problem.
        #
        # Note: we also delete any columns with NULL `inserted_ts`, this is safe
        # as we added a default value to new rows and so they must be at least
        # an hour old.
        limit = 1000
        sql = """
            DELETE FROM event_push_actions_staging WHERE event_id IN (
                SELECT event_id FROM event_push_actions_staging WHERE
                inserted_ts < ? OR inserted_ts IS NULL
                LIMIT ?
            )
        """

        def _clear_old_push_actions_staging_txn(txn: LoggingTransaction) -> bool:
            txn.execute(sql, (delete_before_ts, limit))
            return txn.rowcount >= limit

        while True:
            # Returns true if we have more stuff to delete from the table.
            deleted = await self.db_pool.runInteraction(
                "_clear_old_push_actions_staging", _clear_old_push_actions_staging_txn
            )

            if not deleted:
                return

            # We sleep to ensure that we don't overwhelm the DB.
            await self._clock.sleep(1.0)


class EventPushActionsStore(EventPushActionsWorkerStore):
    EPA_HIGHLIGHT_INDEX = "epa_highlight_index"

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
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

        # Add index to make deleting old push actions faster.
        self.db_pool.updates.register_background_index_update(
            "event_push_actions_stream_highlight_index",
            index_name="event_push_actions_stream_highlight_index",
            table="event_push_actions",
            columns=["highlight", "stream_ordering"],
            where_clause="highlight=0",
        )

    async def get_push_actions_for_user(
        self,
        user_id: str,
        before: Optional[str] = None,
        limit: int = 50,
        only_highlight: bool = False,
    ) -> List[UserPushAction]:
        def f(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, int, int, str, bool, str, int]]:
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
            sql = """
                SELECT epa.event_id, epa.room_id,
                    epa.stream_ordering, epa.topological_ordering,
                    epa.actions, epa.highlight, epa.profile_tag, e.received_ts
                FROM event_push_actions epa, events e
                WHERE epa.event_id = e.event_id
                    AND epa.user_id = ? %s
                    AND epa.notif = 1
                ORDER BY epa.stream_ordering DESC
                LIMIT ?
            """ % (
                before_clause,
            )
            txn.execute(sql, args)
            return cast(
                List[Tuple[str, str, int, int, str, bool, str, int]], txn.fetchall()
            )

        push_actions = await self.db_pool.runInteraction("get_push_actions_for_user", f)
        return [
            UserPushAction(
                event_id=row[0],
                room_id=row[1],
                stream_ordering=row[2],
                actions=_deserialize_action(row[4], row[5]),
                received_ts=row[7],
                topological_ordering=row[3],
                highlight=row[5],
                profile_tag=row[6],
            )
            for row in push_actions
        ]


def _action_has_highlight(actions: Collection[Union[Mapping, str]]) -> bool:
    for action in actions:
        if not isinstance(action, dict):
            continue

        if action.get("set_tweak", None) == "highlight":
            return action.get("value", True)

    return False


@attr.s(slots=True, auto_attribs=True)
class _EventPushSummary:
    """Summary of pending event push actions for a given user in a given room.
    Used in _rotate_notifs_before_txn to manipulate results from event_push_actions.
    """

    unread_count: int
    stream_ordering: int
    notif_count: int
