import logging
from typing import Dict, List

from synapse.api.errors import SynapseError
from synapse.storage._base import SQLBaseStore

logger = logging.getLogger(__name__)


class EventForwardExtremitiesStore(SQLBaseStore):
    async def delete_forward_extremities_for_room(self, room_id: str) -> int:
        """Delete any extra forward extremities for a room.

        Invalidates the "get_latest_event_ids_in_room" cache if any forward
        extremities were deleted.

        Returns count deleted.
        """

        def delete_forward_extremities_for_room_txn(txn):
            # First we need to get the event_id to not delete
            sql = (
                "SELECT "
                "   last_value(event_id) OVER w AS event_id"
                "   FROM event_forward_extremities"
                "   NATURAL JOIN events"
                " where room_id = ?"
                "   WINDOW w AS ("
                "   PARTITION BY room_id"
                "       ORDER BY stream_ordering"
                "       range between unbounded preceding and unbounded following"
                "   )"
                "   ORDER BY stream_ordering"
            )
            txn.execute(sql, (room_id,))
            rows = txn.fetchall()
            try:
                event_id = rows[0][0]
                logger.debug(
                    "Found event_id %s as the forward extremity to keep for room %s",
                    event_id,
                    room_id,
                )
            except KeyError:
                msg = "No forward extremity event found for room %s" % room_id
                logger.warning(msg)
                raise SynapseError(400, msg)

            # Now delete the extra forward extremities
            sql = (
                "DELETE FROM event_forward_extremities "
                "WHERE"
                "   event_id != ?"
                "   AND room_id = ?"
            )

            txn.execute(sql, (event_id, room_id))
            logger.info(
                "Deleted %s extra forward extremities for room %s",
                txn.rowcount,
                room_id,
            )

            if txn.rowcount > 0:
                # Invalidate the cache
                self._invalidate_cache_and_stream(
                    txn, self.get_latest_event_ids_in_room, (room_id,),
                )

            return txn.rowcount

        return await self.db_pool.runInteraction(
            "delete_forward_extremities_for_room",
            delete_forward_extremities_for_room_txn,
        )

    async def get_forward_extremities_for_room(self, room_id: str) -> List[Dict]:
        """Get list of forward extremities for a room."""

        def get_forward_extremities_for_room_txn(txn):
            sql = (
                "SELECT event_id, state_group FROM event_forward_extremities NATURAL JOIN event_to_state_groups "
                "WHERE room_id = ?"
            )

            txn.execute(sql, (room_id,))
            rows = txn.fetchall()
            return [{"event_id": row[0], "state_group": row[1]} for row in rows]

        return await self.db_pool.runInteraction(
            "get_forward_extremities_for_room", get_forward_extremities_for_room_txn,
        )
