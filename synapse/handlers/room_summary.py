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

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    JoinRules,
)
from synapse.api.errors import NotFoundError
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomSummaryMixin:
    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastore()
        self._event_auth_handler = hs.get_event_auth_handler()

    async def build_room_entry(self, room_id: str) -> JsonDict:
        """Generate en entry suitable for the 'rooms' list in the summary response"""
        stats = await self._store.get_room_with_stats(room_id)

        # currently this should be impossible because we call
        # check_user_in_room_or_world_readable on the room before we get here, so
        # there should always be an entry
        assert stats is not None, "unable to retrieve stats for %s" % (room_id,)

        current_state_ids = await self._store.get_current_state_ids(room_id)
        create_event = await self._store.get_event(
            current_state_ids[(EventTypes.Create, "")]
        )

        room_version = await self._store.get_room_version(room_id)
        allowed_rooms = None
        if await self._event_auth_handler.has_restricted_join_rules(
            current_state_ids, room_version
        ):
            allowed_rooms = await self._event_auth_handler.get_rooms_that_allow_join(
                current_state_ids
            )

        entry = {
            "room_id": stats["room_id"],
            "name": stats["name"],
            "topic": stats["topic"],
            "canonical_alias": stats["canonical_alias"],
            "num_joined_members": stats["joined_members"],
            "avatar_url": stats["avatar"],
            "join_rules": stats["join_rules"],
            "world_readable": (
                stats["history_visibility"] == HistoryVisibility.WORLD_READABLE
            ),
            "guest_can_join": stats["guest_access"] == "can_join",
            "creation_ts": create_event.origin_server_ts,
            "room_type": create_event.content.get(EventContentFields.ROOM_TYPE),
            "is_encrypted": (EventTypes.RoomEncryption, "") in current_state_ids,
            "allowed_room_ids": allowed_rooms,  # this field is stripped from the cs response
        }

        # Filter out Nones – rather omit the field altogether
        room_entry = {k: v for k, v in entry.items() if v is not None}

        return room_entry

    async def requester_can_see_room_entry(
        self,
        room: JsonDict,
        requester: Optional[str],
    ) -> bool:
        # The room should only be allowed in the summary if:
        #     a. the user is in the room;
        #     b. the room is world readable; or
        #     c. the user could join the room, e.g. the join rules
        #        are set to public or the user is in a space that
        #        has been granted access to the room.
        #
        # Note that we know the user is not in the root room (which is
        # why the remote call was made in the first place), but the user
        # could be in one of the children rooms and we just didn't know
        # about the link.

        # The API doesn't return the room version so assume that a
        # join rule of knock is valid.
        include_room = (
            room.get("join_rules") in (JoinRules.PUBLIC, JoinRules.KNOCK)
            or room.get("world_readable") is True
        )

        # Check if the user is a member of any of the allowed rooms
        # from the response.
        allowed_rooms = room.get("allowed_room_ids")
        if (
            not include_room
            and requester
            and allowed_rooms
            and isinstance(allowed_rooms, list)
        ):
            include_room = await self._event_auth_handler.is_user_in_rooms(
                allowed_rooms, requester
            )

        return include_room


class RoomSummaryHandler(RoomSummaryMixin):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
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
            include_room = self.requester_can_see_room_entry(room_summary, requester)

            if not include_room:
                raise NotFoundError("Room not found or is not accessible")

        # Before returning to the client, remove the allowed_room_ids key.
        room_summary.pop("allowed_room_ids", None)

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
        if not await self._auth.is_room_accessible(room_id, requester, origin):
            raise NotFoundError("Room not found or is not accessible")

        return await self.build_room_entry(room_id)

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
