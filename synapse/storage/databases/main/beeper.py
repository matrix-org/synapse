# Beep beep!

import logging
from typing import TYPE_CHECKING, List, Optional, Tuple, cast

from synapse.events import EventBase
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.types import RoomStreamToken
from synapse.util.caches.descriptors import cached

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class BeeperStore(SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.user_notification_counts_enabled: bool = (
            hs.config.experimental.beeper_user_notification_counts_enabled
        )

        if (
            self.user_notification_counts_enabled
            and hs.config.worker.run_background_tasks
        ):
            self.aggregate_notification_counts_loop = self._clock.looping_call(
                self.beeper_aggregate_notification_counts, 30 * 1000
            )
            self.is_aggregating_notification_counts = False

    @cached(max_entries=50000, num_args=2, tree=True)
    async def beeper_preview_event_for_room_id_and_user_id(
        self, room_id: str, user_id: str, to_key: RoomStreamToken
    ) -> Optional[Tuple[str, int]]:
        def beeper_preview_txn(txn: LoggingTransaction) -> Optional[Tuple[str, int]]:
            sql = """
            SELECT e.event_id, COALESCE(re.origin_server_ts, e.origin_server_ts) as origin_server_ts
            FROM events AS e
            LEFT JOIN redactions as r
                ON e.event_id = r.redacts
            -- Join to relations to find replacements
            LEFT JOIN event_relations as er
                ON e.event_id = er.event_id AND er.relation_type = 'm.replace'
            -- Join the original event that was replaced
            LEFT JOIN events as re
                ON re.event_id = er.relates_to_id
            WHERE
                e.stream_ordering <= ?
                AND e.room_id = ?
                AND r.redacts IS NULL
                AND (
                    e.type = 'm.room.message'
                    OR e.type = 'm.room.encrypted'
                    OR e.type = 'm.reaction'
                )
                AND CASE
                    -- Only find non-redacted reactions to our own messages
                    WHEN (e.type = 'm.reaction') THEN (
                        SELECT ? = ee.sender AND ee.event_id NOT IN (
                            SELECT redacts FROM redactions WHERE redacts = ee.event_id
                        ) FROM events as ee
                        WHERE ee.event_id = (
                            SELECT eer.relates_to_id FROM event_relations AS eer
                            WHERE eer.event_id = e.event_id
                        )
                    )
                    ELSE (true) END
            ORDER BY e.stream_ordering DESC
            LIMIT 1
            """

            txn.execute(
                sql,
                (
                    to_key.stream,
                    room_id,
                    user_id,
                ),
            )

            return cast(Optional[Tuple[str, int]], txn.fetchone())

        return await self.db_pool.runInteraction(
            "beeper_preview_for_room_id_and_user_id",
            beeper_preview_txn,
        )

    async def beeper_cleanup_tombstoned_room(self, room_id: str) -> None:
        def beeper_cleanup_tombstoned_room_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_delete_txn(
                txn, table="event_push_actions", keyvalues={"room_id": room_id}
            )
            self.db_pool.simple_delete_txn(
                txn, table="event_push_summary", keyvalues={"room_id": room_id}
            )

        await self.db_pool.runInteraction(
            "beeper_cleanup_tombstoned_room",
            beeper_cleanup_tombstoned_room_txn,
        )

    def beeper_add_notification_counts_txn(
        self,
        txn: LoggingTransaction,
        notifiable_events: List[EventBase],
    ) -> None:
        if not self.user_notification_counts_enabled:
            return

        sql = """
            INSERT INTO beeper_user_notification_counts (
                room_id, event_stream_ordering,
                user_id, thread_id, notifs, unreads, highlights
            )
            SELECT ?, ?, user_id, thread_id, notif, unread, highlight
            FROM event_push_actions_staging
            WHERE event_id = ?
        """

        txn.execute_batch(
            sql,
            (
                (
                    event.room_id,
                    event.internal_metadata.stream_ordering,
                    event.event_id,
                )
                for event in notifiable_events
            ),
        )

    def beeper_clear_notification_counts_txn(
        self,
        txn: LoggingTransaction,
        user_id: str,
        room_id: str,
        stream_ordering: int,
    ) -> None:
        if not self.user_notification_counts_enabled:
            return

        sql = """
            DELETE FROM beeper_user_notification_counts
            WHERE
                user_id = ?
                AND room_id = ?
                AND event_stream_ordering <= ?
        """

        txn.execute(sql, (user_id, room_id, stream_ordering))

    async def beeper_aggregate_notification_counts(self) -> None:
        if not self.user_notification_counts_enabled:
            return

        def aggregate_txn(txn: LoggingTransaction) -> None:
            sql = """
                WITH recent_rows AS (  -- Aggregate the tables, flag aggregated rows for deletion
                    SELECT
                        user_id,
                        room_id
                    FROM
                        beeper_user_notification_counts
                    WHERE
                        event_stream_ordering > (
                            SELECT event_stream_ordering FROM beeper_user_notification_counts_stream_ordering
                        )
                        -- Arbitrary 100k offset for now
                        AND event_stream_ordering < SELECT MAX(stream_ordering) - 100000 FROM events
                )
                UPDATE
                    beeper_user_notification_counts AS epc
                SET
                    unreads = CASE WHEN epc.event_stream_ordering = agg.max_eso THEN agg.unreads ELSE 0 END,
                    notifs = CASE WHEN epc.event_stream_ordering = agg.max_eso THEN agg.notifs ELSE 0 END,
                    highlights = CASE WHEN epc.event_stream_ordering = agg.max_eso THEN agg.highlights ELSE 0 END,
                    aggregated = epc.event_stream_ordering != agg.max_eso
                FROM (
                    SELECT
                        user_id,
                        room_id,
                        SUM(unreads) AS unreads,
                        SUM(notifs) AS notifs,
                        SUM(highlights) AS highlights,
                        MAX(event_stream_ordering) AS max_eso
                    FROM
                        beeper_user_notification_counts
                    WHERE
                        user_id IN(SELECT user_id FROM recent_rows)
                        AND room_id IN(SELECT room_id FROM recent_rows)
                    GROUP BY
                        user_id,
                        room_id
                ) AS agg
                WHERE
                    epc.room_id = agg.room_id
                    AND epc.user_id = agg.user_id
                RETURNING
                    event_stream_ordering;
            """

            txn.execute(sql)
            orders = list(txn)
            if not orders:
                return

            max_stream_ordering = max(orders)
            txn.execute(
                "UPDATE beeper_user_notification_counts_stream_ordering SET stream_ordering = ?",
                max_stream_ordering,
            )

            logger.info(f"Aggregated {len(orders)} notification count rows")

        if self.is_aggregating_notification_counts:
            return

        self.is_aggregating_notification_counts = True

        try:
            logger.debug("Aggregating notification counts")

            await self.db_pool.runInteraction(
                "beeper_aggregate_notification_counts",
                aggregate_txn,
            )
        finally:
            self.is_aggregating_notification_counts = False
