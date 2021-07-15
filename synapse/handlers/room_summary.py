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
    Membership,
)
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomSummaryHandler:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._event_auth_handler = hs.get_event_auth_handler()
        self._store = hs.get_datastore()
        self._event_serializer = hs.get_event_client_serializer()
        self._server_name = hs.hostname
        self._federation_client = hs.get_federation_client()

    async def get_room_summary(
        self,
        requester: Optional[str],
        room_id: str,
        remote_room_hosts: List[str],
    ) -> JsonDict:
        """
        Implementation of the room summary C-S API MSC3244

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
                membership, _ = await self._store.get_local_current_membership_for_user_in_room(
                    requester, room_id
                )

                room_summary["membership"] = membership or "leave"
        else:
            room_summary = await self._summarize_remote_room(room_id, remote_room_hosts)

            # TODO validate that the requester has permission to see this room
            # https://github.com/matrix-org/matrix-doc/pull/3266/files#diff-97aeb566f3ce4bd6ec3b98e71ecbca3d6e86c0407e6a82afbc57e86bf0316607R106-R108

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
        if not await self._is_room_accessible(room_id, requester, origin):
            return None

        return await self._build_room_entry(room_id)

    async def _summarize_remote_room(
        self,
        room_id: str,
        remote_room_hosts: List[str],
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

        return None  # TODO federation API

    # TODO extract into mixin/helper method
    async def _is_room_accessible(
        self, room_id: str, requester: Optional[str], origin: Optional[str]
    ) -> bool:
        """
        Calculate whether the room should be shown to the requester.

        It should be included if:

        * The requester is joined or can join the room (per MSC3173).
        * The origin server has any user that is joined or can join the room.
        * The history visibility is set to world readable.

        Args:
            room_id: The room ID to summarize.
            requester:
                The user requesting the summary, if it is a local request. None
                if this is a federation request.
            origin:
                The server requesting the summary, if it is a federation request.
                None if this is a local request.

        Returns:
             True if the room should be visible to the requester.
        """
        state_ids = await self._store.get_current_state_ids(room_id)

        # If there's no state for the room, it isn't known.
        if not state_ids:
            # The user might have a pending invite for the room.
            if requester and await self._store.get_invite_for_local_user_in_room(
                requester, room_id
            ):
                return True

            logger.info("room %s is unknown, omitting from summary", room_id)
            return False

        room_version = await self._store.get_room_version(room_id)

        # Include the room if it has join rules of public or knock.
        join_rules_event_id = state_ids.get((EventTypes.JoinRules, ""))
        if join_rules_event_id:
            join_rules_event = await self._store.get_event(join_rules_event_id)
            join_rule = join_rules_event.content.get("join_rule")
            if join_rule == JoinRules.PUBLIC or (
                room_version.msc2403_knocking and join_rule == JoinRules.KNOCK
            ):
                return True

        # Include the room if it is peekable.
        hist_vis_event_id = state_ids.get((EventTypes.RoomHistoryVisibility, ""))
        if hist_vis_event_id:
            hist_vis_ev = await self._store.get_event(hist_vis_event_id)
            hist_vis = hist_vis_ev.content.get("history_visibility")
            if hist_vis == HistoryVisibility.WORLD_READABLE:
                return True

        # Otherwise we need to check information specific to the user or server.

        # If we have an authenticated requesting user, check if they are a member
        # of the room (or can join the room).
        if requester:
            member_event_id = state_ids.get((EventTypes.Member, requester), None)

            # If they're in the room they can see info on it.
            if member_event_id:
                member_event = await self._store.get_event(member_event_id)
                if member_event.membership in (Membership.JOIN, Membership.INVITE):
                    return True

            # Otherwise, check if they should be allowed access via membership in a space.
            if await self._event_auth_handler.has_restricted_join_rules(
                state_ids, room_version
            ):
                allowed_rooms = (
                    await self._event_auth_handler.get_rooms_that_allow_join(state_ids)
                )
                if await self._event_auth_handler.is_user_in_rooms(
                    allowed_rooms, requester
                ):
                    return True

        # If this is a request over federation, check if the host is in the room or
        # has a user who could join the room.
        elif origin:
            if await self._event_auth_handler.check_host_in_room(
                room_id, origin
            ) or await self._store.is_host_invited(room_id, origin):
                return True

            # Alternately, if the host has a user in any of the spaces specified
            # for access, then the host can see this room (and should do filtering
            # if the requester cannot see it).
            if await self._event_auth_handler.has_restricted_join_rules(
                state_ids, room_version
            ):
                allowed_rooms = (
                    await self._event_auth_handler.get_rooms_that_allow_join(state_ids)
                )
                for space_id in allowed_rooms:
                    if await self._event_auth_handler.check_host_in_room(
                        space_id, origin
                    ):
                        return True

        logger.info(
            "room %s is unpeekable and requester %s is not a member / not allowed to join, omitting from summary",
            room_id,
            requester or origin,
        )
        return False

    async def _build_room_entry(self, room_id: str) -> JsonDict:
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
