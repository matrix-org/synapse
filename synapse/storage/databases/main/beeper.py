# Beep beep!

import logging

from synapse.storage._base import SQLBaseStore
from synapse.storage.database import LoggingTransaction
from synapse.types import JsonDict, RoomStreamToken
from synapse.util.caches.descriptors import cached

logger = logging.getLogger(__name__)


class BeeperStore(SQLBaseStore):
    @cached(max_entries=50000, iterable=True)
    async def beeper_preview_for_room_id_and_user_id(
        self, room_id: str, user_id: str, to_key: RoomStreamToken
    ) -> JsonDict:
        res = {}

        def _beeper_preview_for_room_id_and_user_id(txn: LoggingTransaction) -> None:
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
            for event_id, origin_server_ts in txn:
                res["event_id"] = event_id
                res["origin_server_ts"] = origin_server_ts

        await self.db_pool.runInteraction(
            "beeper_preview_for_room_id_and_user_id",
            _beeper_preview_for_room_id_and_user_id,
        )

        return res
