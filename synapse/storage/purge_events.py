# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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

import itertools
import logging
from typing import TYPE_CHECKING, Set

from synapse.storage.databases import Databases

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class PurgeEventsStorage:
    """High level interface for purging rooms and event history."""

    def __init__(self, hs: "HomeServer", stores: Databases):
        self.stores = stores

    async def purge_room(self, room_id: str) -> None:
        """Deletes all record of a room"""

        state_groups_to_delete = await self.stores.main.purge_room(room_id)
        await self.stores.state.purge_room_state(room_id, state_groups_to_delete)

    async def purge_history(
        self, room_id: str, token: str, delete_local_events: bool
    ) -> None:
        """Deletes room history before a certain point

        Args:
            room_id: The room ID

            token: A topological token to delete events before

            delete_local_events:
                if True, we will delete local events as well as remote ones
                (instead of just marking them as outliers and deleting their
                state groups).
        """
        state_groups = await self.stores.main.purge_history(
            room_id, token, delete_local_events
        )

        logger.info("[purge] finding state groups that can be deleted")

        sg_to_delete = await self._find_unreferenced_groups(state_groups)

        await self.stores.state.purge_unreferenced_state_groups(room_id, sg_to_delete)

    async def _find_unreferenced_groups(self, state_groups: Set[int]) -> Set[int]:
        """Used when purging history to figure out which state groups can be
        deleted.

        Args:
            state_groups: Set of state groups referenced by events
                that are going to be deleted.

        Returns:
            The set of state groups that can be deleted.
        """
        # Graph of state group -> previous group
        graph = {}

        # Set of events that we have found to be referenced by events
        referenced_groups = set()

        # Set of state groups we've already seen
        state_groups_seen = set(state_groups)

        # Set of state groups to handle next.
        next_to_search = set(state_groups)
        while next_to_search:
            # We bound size of groups we're looking up at once, to stop the
            # SQL query getting too big
            if len(next_to_search) < 100:
                current_search = next_to_search
                next_to_search = set()
            else:
                current_search = set(itertools.islice(next_to_search, 100))
                next_to_search -= current_search

            referenced = await self.stores.main.get_referenced_state_groups(
                current_search
            )
            referenced_groups |= referenced

            # We don't continue iterating up the state group graphs for state
            # groups that are referenced.
            current_search -= referenced

            edges = await self.stores.state.get_previous_state_groups(current_search)

            prevs = set(edges.values())
            # We don't bother re-handling groups we've already seen
            prevs -= state_groups_seen
            next_to_search |= prevs
            state_groups_seen |= prevs

            graph.update(edges)

        to_delete = state_groups_seen - referenced_groups

        return to_delete
