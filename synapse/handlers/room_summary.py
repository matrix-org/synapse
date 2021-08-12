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

import logging
from typing import TYPE_CHECKING, List, Optional

from synapse.api.errors import NotFoundError
from synapse.handlers.space_summary import RoomSummaryMixin
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomSummaryHandler(RoomSummaryMixin):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._clock = hs.get_clock()
        self._server_name = hs.hostname

    async def get_room_summary(
        self,
        requester: Optional[str],
        room_id: str,
        remote_room_hosts: Optional[List[str]] = None,
    ) -> JsonDict:
        """
        Implementation of the room summary C-S API MSC3266

        Args:
            requester:  user id of the user making this request,
                can be None for unauthenticated requests

            room_id: room id to start the summary at

            remote_room_hosts: a list of homeservers to try fetching data through
                if we don't know it ourselves

        Returns:
            summary dict to return
        """
        is_in_room = await self._store.is_host_joined(room_id, self._server_name)

        if is_in_room:
            room_summary = await self._summarize_local_room(requester, None, room_id)

            if requester:
                (
                    membership,
                    _,
                ) = await self._store.get_local_current_membership_for_user_in_room(
                    requester, room_id
                )

                room_summary["membership"] = membership or "leave"
        else:
            room_summary = await self._summarize_remote_room(room_id, remote_room_hosts)

            # validate that the requester has permission to see this room
            include_room = self._is_remote_room_accessible(
                requester, room_id, room_summary
            )

            if not include_room:
                raise NotFoundError("Room not found or is not accessible")

        # Before returning to the client, remove the allowed_room_ids
        # and allowed_spaces keys.
        room_summary.pop("allowed_room_ids", None)
        room_summary.pop("allowed_spaces", None)

        return room_summary

    async def _summarize_local_room(
        self,
        requester: Optional[str],
        origin: Optional[str],
        room_id: str,
    ) -> JsonDict:
        """
        Generate a room entry and a list of event entries for a given room.

        Args:
            requester:
                The user requesting the summary, if it is a local request. None
                if this is a federation request.
            origin:
                The server requesting the summary, if it is a federation request.
                None if this is a local request.
            room_id: The room ID to summarize.

        Returns:
            summary dict to return
        """
        if not await self._auth.is_room_visible(room_id, requester, origin):
            raise NotFoundError("Room not found or is not accessible")

        return await self._build_room_entry(room_id, for_federation=bool(origin))

    async def _summarize_remote_room(
        self,
        room_id: str,
        remote_room_hosts: Optional[List[str]],
    ) -> JsonDict:
        """
        Request room entries and a list of event entries for a given room by querying a remote server.

        Args:
            room_id: The room to summarize.
            remote_room_hosts: List of homeservers to attempt to fetch the data from.

        Returns:
            summary dict to return
        """
        logger.info("Requesting summary for %s via %s", room_id, remote_room_hosts)

        # TODO federation API, descoped from initial unstable implementation as MSC needs more maturing on that side.
        raise NotFoundError("Room not found or is not accessible")
