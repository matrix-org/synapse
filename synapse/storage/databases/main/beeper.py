# Beep beep!

import logging
from typing import Optional, Tuple, cast

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import LoggingTransaction
from synapse.types import RoomStreamToken
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)


class BeeperStore(SQLBaseStore):
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
