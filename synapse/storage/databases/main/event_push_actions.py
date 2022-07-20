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
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple, Union, cast

import attr

from synapse.api.constants import ReceiptTypes
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.receipts import ReceiptsWorkerStore
from synapse.storage.databases.main.stream import StreamWorkerStore
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
    The per-user, per-room count of notifications. Used by sync and push.
    """

    notify_count: int = 0
    unread_count: int = 0
    highlight_count: int = 0


def _serialize_action(actions: List[Union[dict, str]], is_highlight: bool) -> str:
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

        self.db_pool.updates.register_background_index_update(
            "event_push_summary_unique_index",
            index_name="event_push_summary_unique_index",
            table="event_push_summary",
            columns=["user_id", "room_id"],
            unique=True,
            replaces_index="event_push_summary_user_rm",
        )

    @cached(tree=True, max_entries=5000)
    async def get_unread_event_push_actions_by_room_for_user(
        self,
        room_id: str,
        user_id: str,
    ) -> NotifCounts:
        """Get the notification count, the highlight count and the unread message count
        for a given user in a given room after the given read receipt.

        Note that this function assumes the user to be a current member of the room,
        since it's either called by the sync handler to handle joined room entries, or by
        the HTTP pusher to calculate the badge of unread joined rooms.

        Args:
            room_id: The room to retrieve the counts in.
            user_id: The user to retrieve the counts for.

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
        )

    def _get_unread_counts_by_receipt_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        user_id: str,
    ) -> NotifCounts:
        result = self.get_last_receipt_for_user_txn(
            txn,
            user_id,
            room_id,
            receipt_types=(ReceiptTypes.READ, ReceiptTypes.READ_PRIVATE),
        )

        stream_ordering = None
        if result:
            _, stream_ordering = result

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

    def _get_unread_counts_by_pos_txn(
        self, txn: LoggingTransaction, room_id: str, user_id: str, stream_ordering: int
    ) -> NotifCounts:
        """Get the number of unread messages for a user/room that have happened
        since the given stream ordering.
        """

        counts = NotifCounts()

        # First we pull the counts from the summary table.
        #
        # We check that `last_receipt_stream_ordering` matches the stream
        # ordering given. If it doesn't match then a new read receipt has arrived and
        # we haven't yet updated the counts in `event_push_summary` to reflect
        # that; in that case we simply ignore `event_push_summary` counts
        # and do a manual count of all of the rows in the `event_push_actions` table
        # for this user/room.
        #
        # If `last_receipt_stream_ordering` is null then that means it's up to
        # date (as the row was written by an older version of Synapse that
        # updated `event_push_summary` synchronously when persisting a new read
        # receipt).
        txn.execute(
            """
                SELECT stream_ordering, notif_count, COALESCE(unread_count, 0)
                FROM event_push_summary
                WHERE room_id = ? AND user_id = ?
                AND (
                    (last_receipt_stream_ordering IS NULL AND stream_ordering > ?)
                    OR last_receipt_stream_ordering = ?
                )
            """,
            (room_id, user_id, stream_ordering, stream_ordering),
        )
        row = txn.fetchone()

        summary_stream_ordering = 0
        if row:
            summary_stream_ordering = row[0]
            counts.notify_count += row[1]
            counts.unread_count += row[2]

        # Next we need to count highlights, which aren't summarized
        sql = """
            SELECT COUNT(*) FROM event_push_actions
            WHERE user_id = ?
                AND room_id = ?
                AND stream_ordering > ?
                AND highlight = 1
        """
        txn.execute(sql, (user_id, room_id, stream_ordering))
        row = txn.fetchone()
        if row:
            counts.highlight_count += row[0]

        # Finally we need to count push actions that aren't included in the
        # summary returned above, e.g. recent events that haven't been
        # summarized yet, or the summary is empty due to a recent read receipt.
        stream_ordering = max(stream_ordering, summary_stream_ordering)
        notify_count, unread_count = self._get_notif_unread_count_for_user_room(
            txn, room_id, user_id, stream_ordering
        )

        counts.notify_count += notify_count
        counts.unread_count += unread_count

        return counts

    def _get_notif_unread_count_for_user_room(
        self,
        txn: LoggingTransaction,
        room_id: str,
        user_id: str,
        stream_ordering: int,
        max_stream_ordering: Optional[int] = None,
    ) -> Tuple[int, int]:
        """Returns the notify and unread counts from `event_push_actions` for
        the given user/room in the given range.

        Does not consult `event_push_summary` table, which may include push
        actions that have been deleted from `event_push_actions` table.
        """

        # If there have been no events in the room since the stream ordering,
        # there can't be any push actions either.
        if not self._events_stream_cache.has_entity_changed(room_id, stream_ordering):
            return 0, 0

        clause = ""
        args = [user_id, room_id, stream_ordering]
        if max_stream_ordering is not None:
            clause = "AND ea.stream_ordering <= ?"
            args.append(max_stream_ordering)

            # If the max stream ordering is less than the min stream ordering,
            # then obviously there are zero push actions in that range.
            if max_stream_ordering <= stream_ordering:
                return 0, 0

        sql = f"""
            SELECT
               COUNT(CASE WHEN notif = 1 THEN 1 END),
               COUNT(CASE WHEN unread = 1 THEN 1 END)
             FROM event_push_actions ea
             WHERE user_id = ?
               AND room_id = ?
               AND ea.stream_ordering > ?
               {clause}
        """

        txn.execute(sql, args)
        row = txn.fetchone()

        if row:
            return cast(Tuple[int, int], row)

        return 0, 0

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
        # find rooms that have a read receipt in them and return the next
        # push actions
        def get_after_receipt(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, int, str, bool]]:
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
            return cast(List[Tuple[str, str, int, str, bool]], txn.fetchall())

        after_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http_arr", get_after_receipt
        )

        # There are rooms with push actions in them but you don't have a read receipt in
        # them e.g. rooms you've been invited to, so get push actions for rooms which do
        # not have read receipts in them too.
        def get_no_receipt(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, int, str, bool]]:
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
            return cast(List[Tuple[str, str, int, str, bool]], txn.fetchall())

        no_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_http_nrr", get_no_receipt
        )

        notifs = [
            HttpPushAction(
                event_id=row[0],
                room_id=row[1],
                stream_ordering=row[2],
                actions=_deserialize_action(row[3], row[4]),
            )
            for row in after_read_receipt + no_read_receipt
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
        # find rooms that have a read receipt in them and return the most recent
        # push actions
        def get_after_receipt(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, int, str, bool, int]]:
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
            return cast(List[Tuple[str, str, int, str, bool, int]], txn.fetchall())

        after_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email_arr", get_after_receipt
        )

        # There are rooms with push actions in them but you don't have a read receipt in
        # them e.g. rooms you've been invited to, so get push actions for rooms which do
        # not have read receipts in them too.
        def get_no_receipt(
            txn: LoggingTransaction,
        ) -> List[Tuple[str, str, int, str, bool, int]]:
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
            return cast(List[Tuple[str, str, int, str, bool, int]], txn.fetchall())

        no_read_receipt = await self.db_pool.runInteraction(
            "get_unread_push_actions_for_user_in_range_email_nrr", get_no_receipt
        )

        # Make a list of dicts from the two sets of results.
        notifs = [
            EmailPushAction(
                event_id=row[0],
                room_id=row[1],
                stream_ordering=row[2],
                actions=_deserialize_action(row[3], row[4]),
                received_ts=row[5],
            )
            for row in after_read_receipt + no_read_receipt
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
        def _gen_entry(
            user_id: str, actions: List[Union[dict, str]]
        ) -> Tuple[str, str, str, int, int, int]:
            is_highlight = 1 if _action_has_highlight(actions) else 0
            notif = 1 if "notify" in actions else 0
            return (
                event_id,  # event_id column
                user_id,  # user_id column
                _serialize_action(actions, bool(is_highlight)),  # actions column
                notif,  # notif column
                is_highlight,  # highlight column
                int(count_as_unread),  # unread column
            )

        def _add_push_actions_to_staging_txn(txn: LoggingTransaction) -> None:
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

    async def get_time_of_last_push_action_before(
        self, stream_ordering: int
    ) -> Optional[int]:
        def f(txn: LoggingTransaction) -> Optional[Tuple[int]]:
            sql = (
                "SELECT e.received_ts"
                " FROM event_push_actions AS ep"
                " JOIN events e ON ep.room_id = e.room_id AND ep.event_id = e.event_id"
                " WHERE ep.stream_ordering > ? AND notif = 1"
                " ORDER BY ep.stream_ordering ASC"
                " LIMIT 1"
            )
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
        """

        limit = 100

        min_receipts_stream_id = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_last_receipt_stream_id",
            keyvalues={},
            retcol="stream_id",
        )

        max_receipts_stream_id = self._receipts_id_gen.get_current_token()

        sql = """
            SELECT r.stream_id, r.room_id, r.user_id, e.stream_ordering
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
        rows = txn.fetchall()

        old_rotate_stream_ordering = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_push_summary_stream_ordering",
            keyvalues={},
            retcol="stream_ordering",
        )

        # For each new read receipt we delete push actions from before it and
        # recalculate the summary.
        for _, room_id, user_id, stream_ordering in rows:
            # Only handle our own read receipts.
            if not self.hs.is_mine_id(user_id):
                continue

            txn.execute(
                """
                DELETE FROM event_push_actions
                WHERE room_id = ?
                    AND user_id = ?
                    AND stream_ordering <= ?
                    AND highlight = 0
                """,
                (room_id, user_id, stream_ordering),
            )

            notif_count, unread_count = self._get_notif_unread_count_for_user_room(
                txn, room_id, user_id, stream_ordering, old_rotate_stream_ordering
            )

            self.db_pool.simple_upsert_txn(
                txn,
                table="event_push_summary",
                keyvalues={"room_id": room_id, "user_id": user_id},
                values={
                    "notif_count": notif_count,
                    "unread_count": unread_count,
                    "stream_ordering": old_rotate_stream_ordering,
                    "last_receipt_stream_ordering": stream_ordering,
                },
            )

        # We always update `event_push_summary_last_receipt_stream_id` to
        # ensure that we don't rescan the same receipts for remote users.

        upper_limit = max_receipts_stream_id
        if len(rows) >= limit:
            # If we pulled out a limited number of rows we only update the
            # position to the last receipt we processed, so we continue
            # processing the rest next iteration.
            upper_limit = rows[-1][0]

        self.db_pool.simple_update_txn(
            txn,
            table="event_push_summary_last_receipt_stream_id",
            keyvalues={},
            updatevalues={"stream_id": upper_limit},
        )

        return len(rows) < limit

    def _rotate_notifs_txn(self, txn: LoggingTransaction) -> bool:
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

        self._rotate_notifs_before_txn(txn, rotate_to_stream_ordering)

        return caught_up

    def _rotate_notifs_before_txn(
        self, txn: LoggingTransaction, rotate_to_stream_ordering: int
    ) -> None:
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
                upd.stream_ordering
            FROM (
                SELECT user_id, room_id, count(*) as cnt,
                    max(ea.stream_ordering) as stream_ordering
                FROM event_push_actions AS ea
                LEFT JOIN event_push_summary AS old USING (user_id, room_id)
                WHERE ? < ea.stream_ordering AND ea.stream_ordering <= ?
                    AND (
                        old.last_receipt_stream_ordering IS NULL
                        OR old.last_receipt_stream_ordering < ea.stream_ordering
                    )
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
        summaries: Dict[Tuple[str, str], _EventPushSummary] = {}
        for row in txn:
            summaries[(row[0], row[1])] = _EventPushSummary(
                unread_count=row[2],
                stream_ordering=row[3],
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
                    notif_count=row[2],
                )

        logger.info("Rotating notifications, handling %d rows", len(summaries))

        self.db_pool.simple_upsert_many_txn(
            txn,
            table="event_push_summary",
            key_names=("user_id", "room_id"),
            key_values=[(user_id, room_id) for user_id, room_id in summaries],
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

    async def _remove_old_push_actions_that_have_rotated(
        self,
    ) -> None:
        """Clear out old push actions that have been summarized."""

        # We want to clear out anything that older than a day that *has* already
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
            psql_only=True,
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


def _action_has_highlight(actions: List[Union[dict, str]]) -> bool:
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
