from typing import List, Dict

from synapse.storage._base import SQLBaseStore


class EventForwardExtremitiesStore(SQLBaseStore):
    async def get_forward_extremities_for_room(self, room_id: str) -> List[Dict]:
        def get_forward_extremities_for_room_txn(txn):
            sql = (
                "SELECT event_id, state_group FROM event_forward_extremities NATURAL JOIN event_to_state_groups "
                "WHERE room_id = ?"
            )

            txn.execute(sql, (room_id,))
            rows = txn.fetchall()
            return [{"event_id": row[0], "state_group": row[1]} for row in rows]

        return await self.db_pool.runInteraction(
            "get_forward_extremities_for_room", get_forward_extremities_for_room_txn
        )
