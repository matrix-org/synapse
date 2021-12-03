# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from typing import Optional

from synapse.storage._base import SQLBaseStore


class RoomBatchStore(SQLBaseStore):
    async def get_insertion_event_id_by_batch_id(
        self, room_id: str, batch_id: str
    ) -> Optional[str]:
        """Retrieve a insertion event ID.

        Args:
            batch_id: The batch ID of the insertion event to retrieve.

        Returns:
            The event_id of an insertion event, or None if there is no known
            insertion event for the given insertion event.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="insertion_events",
            keyvalues={"room_id": room_id, "next_batch_id": batch_id},
            retcol="event_id",
            allow_none=True,
        )

    async def store_state_group_id_for_event_id(
        self, event_id: str, state_group_id: int
    ) -> None:
        await self.db_pool.simple_upsert(
            table="event_to_state_groups",
            keyvalues={"event_id": event_id},
            values={"state_group": state_group_id, "event_id": event_id},
            # Unique constraint on event_id so we don't have to lock
            lock=False,
        )
