# -*- coding: utf-8 -*-
#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import json
import logging
from typing import List, Optional, Sequence, Set, Tuple

import attr

import synapse.util.stringutils as stringutils
from synapse.api.errors import StoreError
from synapse.storage._base import SQLBaseStore, db_to_json
from synapse.storage.database import LoggingTransaction

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _PaginationSession:
    """The information that is stored for pagination."""

    # The queue of rooms which are still to process as packed _RoomQueueEntry tuples.
    room_queue: List[Tuple[str, Sequence[str], int]]
    # A set of rooms which have been processed.
    processed_rooms: Set[str]


class RoomSummaryStore(SQLBaseStore):
    """
    Manage user interactive authentication sessions.
    """

    async def create_room_hierarchy_pagination_session(
        self,
        room_id: str,
        suggested_only: bool,
        max_depth: Optional[int],
        room_queue: List[Tuple[str, Sequence[str], int]],
        processed_rooms: Set[str],
    ) -> str:
        """
        Creates a new pagination session for the room hierarchy endpoint.

        Args:
            room_id: The room ID the pagination session is for.
            suggested_only: Whether we should only return children with the
                "suggested" flag set.
            max_depth: The maximum depth in the tree to explore, must be a
                non-negative integer.
            room_queue:
                The queue of rooms which are still to process.
            processed_rooms:
                A set of rooms which have been processed.

        Returns:
            The newly created session ID.

        Raises:
            StoreError if a unique session ID cannot be generated.
        """
        pagination_state = json.dumps(
            {
                "room_queue": room_queue,
                "processed_rooms": list(processed_rooms),
            }
        )

        # autogen a session ID and try to create it. We may clash, so just
        # try a few times till one goes through, giving up eventually.
        attempts = 0
        while attempts < 5:
            session_id = stringutils.random_string(24)

            try:
                await self.db_pool.simple_insert(
                    table="room_hierarchy_pagination_sessions",
                    values={
                        "session_id": session_id,
                        "room_id": room_id,
                        "suggested_only": suggested_only,
                        "max_depth": max_depth,
                        "pagination_state": pagination_state,
                        "creation_time": self.hs.get_clock().time_msec(),
                    },
                    desc="create_room_hierarchy_pagination_session",
                )
                logger.debug(
                    "Persisted room hierarchy pagination session: %s for room %s (suggested: %s, max_depth: %s)",
                    session_id,
                    room_id,
                    suggested_only,
                    max_depth,
                )

                return session_id
            except self.db_pool.engine.module.IntegrityError:
                attempts += 1
        raise StoreError(500, "Couldn't generate a session ID.")

    async def get_room_hierarchy_pagination_session(
        self,
        room_id: str,
        suggested_only: bool,
        max_depth: Optional[int],
        session_id: str,
    ) -> _PaginationSession:
        """
        Retrieve data stored with set_session_data

        Args:
            room_id: The room ID the pagination session is for.
            suggested_only: Whether we should only return children with the
                "suggested" flag set.
            max_depth: The maximum depth in the tree to explore, must be a
                non-negative integer.
            session_id: The pagination session ID.

        Raises:
            StoreError if the session cannot be found.
        """
        logger.debug(
            "Fetch room hierarchy pagination session: %s for room %s (suggested: %s, max_depth: %s)",
            session_id,
            room_id,
            suggested_only,
            max_depth,
        )
        result = await self.db_pool.simple_select_one(
            table="room_hierarchy_pagination_sessions",
            keyvalues={
                "session_id": session_id,
                "room_id": room_id,
                "suggested_only": suggested_only,
            },
            retcols=(
                "max_depth",
                "pagination_state",
            ),
            desc="get_room_hierarchy_pagination_sessions",
        )
        # Check the value of max_depth separately since null != null.
        if result["max_depth"] != max_depth:
            raise StoreError(404, "No row found (room_hierarchy_pagination_sessions)")

        pagination_state = db_to_json(result["pagination_state"])

        return _PaginationSession(
            room_queue=pagination_state["room_queue"],
            processed_rooms=set(pagination_state["processed_rooms"]),
        )

    async def delete_old_room_hierarchy_pagination_sessions(
        self, expiration_time: int
    ) -> None:
        """
        Remove sessions which were last used earlier than the expiration time.

        Args:
            expiration_time: The latest time that is still considered valid.
                This is an epoch time in milliseconds.

        """
        await self.db_pool.runInteraction(
            "delete_old_room_hierarchy_pagination_sessions",
            self._delete_old_room_hierarchy_pagination_sessions_txn,
            expiration_time,
        )

    def _delete_old_room_hierarchy_pagination_sessions_txn(
        self, txn: LoggingTransaction, expiration_time: int
    ):
        # Get the expired sessions.
        sql = "DELETE FROM room_hierarchy_pagination_sessions WHERE creation_time <= ?"
        txn.execute(sql, [expiration_time])
