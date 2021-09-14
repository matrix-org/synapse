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
from synapse.storage.database import DatabasePool


class RoomBatchStore(SQLBaseStore):
    async def get_insertion_event_by_chunk_id(self, chunk_id: str) -> Optional[str]:
        """Retrieve a insertion event ID.

        Args:
            chunk_id: The chunk ID of the insertion event to retrieve.

        Returns:
            The event_id of an insertion event, or None if there is no known
            insertion event for the given insertion event.
        """
        return await self.db_pool.simple_select_one_onecol(
            table="insertion_events",
            keyvalues={"next_chunk_id": chunk_id},
            retcol="event_id",
            allow_none=True,
        )
