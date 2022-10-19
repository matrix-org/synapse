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

import itertools
import logging
import re
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import attr

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    JoinRules,
    Membership,
    RoomTypes,
)
from synapse.api.errors import (
    Codes,
    NotFoundError,
    StoreError,
    SynapseError,
    UnstableSpecAuthError,
    UnsupportedRoomVersionError,
)
from synapse.api.ratelimiting import Ratelimiter
from synapse.events import EventBase
from synapse.types import JsonDict, Requester
from synapse.util.caches.response_cache import ResponseCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# number of rooms to return. We'll stop once we hit this limit.
MAX_ROOMS = 50

# max number of events to return per room.
MAX_ROOMS_PER_SPACE = 50

# max number of federation servers to hit per room
MAX_SERVERS_PER_SPACE = 3


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _PaginationKey:
    """The key used to find unique pagination session."""

    # The first three entries match the request parameters (and cannot change
    # during a pagination session).
    room_id: str
    suggested_only: bool
    max_depth: Optional[int]
    # The randomly generated token.
    token: str


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _PaginationSession:
    """The information that is stored for pagination."""

    # The time the pagination session was created, in milliseconds.
    creation_time_ms: int
    # The queue of rooms which are still to process.
    room_queue: List["_RoomQueueEntry"]
    # A set of rooms which have been processed.
    processed_rooms: Set[str]


class RoomSummaryHandler:
    # A unique key used for pagination sessions for the room hierarchy endpoint.
    _PAGINATION_SESSION_TYPE = "room_hierarchy_pagination"

    # The time a pagination session remains valid for.
    _PAGINATION_SESSION_VALIDITY_PERIOD_MS = 5 * 60 * 1000

    def __init__(self, hs: "HomeServer"):
        self._event_auth_handler = hs.get_event_auth_handler()
        self._store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self._event_serializer = hs.get_event_client_serializer()
        self._server_name = hs.hostname
        self._federation_client = hs.get_federation_client()
        self._ratelimiter = Ratelimiter(
            store=self._store, clock=hs.get_clock(), rate_hz=5, burst_count=10
        )

        # If a user tries to fetch the same page multiple times in quick succession,
        # only process the first attempt and return its result to subsequent requests.
        self._pagination_response_cache: ResponseCache[
            Tuple[str, str, bool, Optional[int], Optional[int], Optional[str]]
        ] = ResponseCache(
            hs.get_clock(),
            "get_room_hierarchy",
        )
        self._msc3266_enabled = hs.config.experimental.msc3266_enabled

    async def get_room_hierarchy(
        self,
        requester: Requester,
        requested_room_id: str,
        suggested_only: bool = False,
        max_depth: Optional[int] = None,
        limit: Optional[int] = None,
        from_token: Optional[str] = None,
    ) -> JsonDict:
        """
        Implementation of the room hierarchy C-S API.

        Args:
            requester: The user ID of the user making this request.
            requested_room_id: The room ID to start the hierarchy at (the "root" room).
            suggested_only: Whether we should only return children with the "suggested"
                flag set.
            max_depth: The maximum depth in the tree to explore, must be a
                non-negative integer.

                0 would correspond to just the root room, 1 would include just
                the root room's children, etc.
            limit: An optional limit on the number of rooms to return per
                page. Must be a positive integer.
            from_token: An optional pagination token.

        Returns:
            The JSON hierarchy dictionary.
        """
        await self._ratelimiter.ratelimit(requester)

        # If a user tries to fetch the same page multiple times in quick succession,
        # only process the first attempt and return its result to subsequent requests.
        #
        # This is due to the pagination process mutating internal state, attempting
        # to process multiple requests for the same page will result in errors.
        return await self._pagination_response_cache.wrap(
            (
                requester.user.to_string(),
                requested_room_id,
                suggested_only,
                max_depth,
                limit,
                from_token,
            ),
            self._get_room_hierarchy,
            requester.user.to_string(),
            requested_room_id,
            suggested_only,
            max_depth,
            limit,
            from_token,
        )

    async def _get_room_hierarchy(
        self,
        requester: str,
        requested_room_id: str,
        suggested_only: bool = False,
        max_depth: Optional[int] = None,
        limit: Optional[int] = None,
        from_token: Optional[str] = None,
    ) -> JsonDict:
        """See docstring for SpaceSummaryHandler.get_room_hierarchy."""

        # First of all, check that the room is accessible.
        if not await self._is_local_room_accessible(requested_room_id, requester):
            raise UnstableSpecAuthError(
                403,
                "User %s not in room %s, and room previews are disabled"
                % (requester, requested_room_id),
                errcode=Codes.NOT_JOINED,
            )

        # If this is continuing a previous session, pull the persisted data.
        if from_token:
            try:
                pagination_session = await self._store.get_session(
                    session_type=self._PAGINATION_SESSION_TYPE,
                    session_id=from_token,
                )
            except StoreError:
                raise SynapseError(400, "Unknown pagination token", Codes.INVALID_PARAM)

            # If the requester, room ID, suggested-only, or max depth were modified
            # the session is invalid.
            if (
                requester != pagination_session["requester"]
                or requested_room_id != pagination_session["room_id"]
                or suggested_only != pagination_session["suggested_only"]
                or max_depth != pagination_session["max_depth"]
            ):
                raise SynapseError(400, "Unknown pagination token", Codes.INVALID_PARAM)

            # Load the previous state.
            room_queue = [
                _RoomQueueEntry(*fields) for fields in pagination_session["room_queue"]
            ]
            processed_rooms = set(pagination_session["processed_rooms"])
        else:
            # The queue of rooms to process, the next room is last on the stack.
            room_queue = [_RoomQueueEntry(requested_room_id, ())]

            # Rooms we have already processed.
            processed_rooms = set()

        rooms_result: List[JsonDict] = []

        # Cap the limit to a server-side maximum.
        if limit is None:
            limit = MAX_ROOMS
        else:
            limit = min(limit, MAX_ROOMS)

        # Iterate through the queue until we reach the limit or run out of
        # rooms to include.
        while room_queue and len(rooms_result) < limit:
            queue_entry = room_queue.pop()
            room_id = queue_entry.room_id
            current_depth = queue_entry.depth
            if room_id in processed_rooms:
                # already done this room
                continue

            logger.debug("Processing room %s", room_id)

            # A map of summaries for children rooms that might be returned over
            # federation. The rationale for caching these and *maybe* using them
            # is to prefer any information local to the homeserver before trusting
            # data received over federation.
            children_room_entries: Dict[str, JsonDict] = {}
            # A set of room IDs which are children that did not have information
            # returned over federation and are known to be inaccessible to the
            # current server. We should not reach out over federation to try to
            # summarise these rooms.
            inaccessible_children: Set[str] = set()

            # If the room is known locally, summarise it!
            is_in_room = await self._store.is_host_joined(room_id, self._server_name)
            if is_in_room:
                room_entry = await self._summarize_local_room(
                    requester,
                    None,
                    room_id,
                    suggested_only,
                )

            # Otherwise, attempt to use information for federation.
            else:
                # A previous call might have included information for this room.
                # It can be used if either:
                #
                # 1. The room is not a space.
                # 2. The maximum depth has been achieved (since no children
                #    information is needed).
                if queue_entry.remote_room and (
                    queue_entry.remote_room.get("room_type") != RoomTypes.SPACE
                    or (max_depth is not None and current_depth >= max_depth)
                ):
                    room_entry = _RoomEntry(
                        queue_entry.room_id, queue_entry.remote_room
                    )

                # If the above isn't true, attempt to fetch the room
                # information over federation.
                else:
                    (
                        room_entry,
                        children_room_entries,
                        inaccessible_children,
                    ) = await self._summarize_remote_room_hierarchy(
                        queue_entry,
                        suggested_only,
                    )

                # Ensure this room is accessible to the requester (and not just
                # the homeserver).
                if room_entry and not await self._is_remote_room_accessible(
                    requester, queue_entry.room_id, room_entry.room
                ):
                    room_entry = None

            # This room has been processed and should be ignored if it appears
            # elsewhere in the hierarchy.
            processed_rooms.add(room_id)

            # There may or may not be a room entry based on whether it is
            # inaccessible to the requesting user.
            if room_entry:
                # Add the room (including the stripped m.space.child events).
                rooms_result.append(room_entry.as_json(for_client=True))

                # If this room is not at the max-depth, check if there are any
                # children to process.
                if max_depth is None or current_depth < max_depth:
                    # The children get added in reverse order so that the next
                    # room to process, according to the ordering, is the last
                    # item in the list.
                    room_queue.extend(
                        _RoomQueueEntry(
                            ev["state_key"],
                            ev["content"]["via"],
                            current_depth + 1,
                            children_room_entries.get(ev["state_key"]),
                        )
                        for ev in reversed(room_entry.children_state_events)
                        if ev["type"] == EventTypes.SpaceChild
                        and ev["state_key"] not in inaccessible_children
                    )

        result: JsonDict = {"rooms": rooms_result}

        # If there's additional data, generate a pagination token (and persist state).
        if room_queue:
            result["next_batch"] = await self._store.create_session(
                session_type=self._PAGINATION_SESSION_TYPE,
                value={
                    # Information which must be identical across pagination.
                    "requester": requester,
                    "room_id": requested_room_id,
                    "suggested_only": suggested_only,
                    "max_depth": max_depth,
                    # The stored state.
                    "room_queue": [
                        attr.astuple(room_entry) for room_entry in room_queue
                    ],
                    "processed_rooms": list(processed_rooms),
                },
                expiry_ms=self._PAGINATION_SESSION_VALIDITY_PERIOD_MS,
            )

        return result

    async def get_federation_hierarchy(
        self,
        origin: str,
        requested_room_id: str,
        suggested_only: bool,
    ) -> JsonDict:
        """
        Implementation of the room hierarchy Federation API.

        This is similar to get_room_hierarchy, but does not recurse into the space.
        It also considers whether anyone on the server may be able to access the
        room, as opposed to whether a specific user can.

        Args:
            origin: The server requesting the spaces summary.
            requested_room_id: The room ID to start the hierarchy at (the "root" room).
            suggested_only: whether we should only return children with the "suggested"
                flag set.

        Returns:
            The JSON hierarchy dictionary.
        """
        root_room_entry = await self._summarize_local_room(
            None, origin, requested_room_id, suggested_only
        )
        if root_room_entry is None:
            # Room is inaccessible to the requesting server.
            raise SynapseError(404, "Unknown room: %s" % (requested_room_id,))

        children_rooms_result: List[JsonDict] = []
        inaccessible_children: List[str] = []

        # Iterate through each child and potentially add it, but not its children,
        # to the response.
        for child_room in itertools.islice(
            root_room_entry.children_state_events, MAX_ROOMS_PER_SPACE
        ):
            room_id = child_room.get("state_key")
            assert isinstance(room_id, str)
            # If the room is unknown, skip it.
            if not await self._store.is_host_joined(room_id, self._server_name):
                continue

            room_entry = await self._summarize_local_room(
                None, origin, room_id, suggested_only, include_children=False
            )
            # If the room is accessible, include it in the results.
            #
            # Note that only the room summary (without information on children)
            # is included in the summary.
            if room_entry:
                children_rooms_result.append(room_entry.room)
            #  Otherwise, note that the requesting server shouldn't bother
            #  trying to summarize this room - they do not have access to it.
            else:
                inaccessible_children.append(room_id)

        return {
            # Include the requested room (including the stripped children events).
            "room": root_room_entry.as_json(),
            "children": children_rooms_result,
            "inaccessible_children": inaccessible_children,
        }

    async def _summarize_local_room(
        self,
        requester: Optional[str],
        origin: Optional[str],
        room_id: str,
        suggested_only: bool,
        include_children: bool = True,
    ) -> Optional["_RoomEntry"]:
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
            suggested_only: True if only suggested children should be returned.
                Otherwise, all children are returned.
            include_children:
                Whether to include the events of any children.

        Returns:
            A room entry if the room should be returned. None, otherwise.
        """
        if not await self._is_local_room_accessible(room_id, requester, origin):
            return None

        room_entry = await self._build_room_entry(room_id, for_federation=bool(origin))

        # If the room is not a space return just the room information.
        if room_entry.get("room_type") != RoomTypes.SPACE or not include_children:
            return _RoomEntry(room_id, room_entry)

        # Otherwise, look for child rooms/spaces.
        child_events = await self._get_child_events(room_id)

        if suggested_only:
            # we only care about suggested children
            child_events = filter(_is_suggested_child_event, child_events)

        stripped_events: List[JsonDict] = [
            {
                "type": e.type,
                "state_key": e.state_key,
                "content": e.content,
                "sender": e.sender,
                "origin_server_ts": e.origin_server_ts,
            }
            for e in child_events
        ]
        return _RoomEntry(room_id, room_entry, stripped_events)

    async def _summarize_remote_room_hierarchy(
        self, room: "_RoomQueueEntry", suggested_only: bool
    ) -> Tuple[Optional["_RoomEntry"], Dict[str, JsonDict], Set[str]]:
        """
        Request room entries and a list of event entries for a given room by querying a remote server.

        Args:
            room: The room to summarize.
            suggested_only: True if only suggested children should be returned.
                Otherwise, all children are returned.

        Returns:
            A tuple of:
                The room entry.
                Partial room data return over federation.
                A set of inaccessible children room IDs.
        """
        room_id = room.room_id
        logger.info("Requesting summary for %s via %s", room_id, room.via)

        via = itertools.islice(room.via, MAX_SERVERS_PER_SPACE)
        try:
            (
                room_response,
                children_state_events,
                children,
                inaccessible_children,
            ) = await self._federation_client.get_room_hierarchy(
                via,
                room_id,
                suggested_only=suggested_only,
            )
        except Exception as e:
            logger.warning(
                "Unable to get hierarchy of %s via federation: %s",
                room_id,
                e,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            return None, {}, set()

        # Map the children to their room ID.
        children_by_room_id = {
            c["room_id"]: c
            for c in children
            if "room_id" in c and isinstance(c["room_id"], str)
        }

        return (
            _RoomEntry(room_id, room_response, children_state_events),
            children_by_room_id,
            set(inaccessible_children),
        )

    async def _is_local_room_accessible(
        self, room_id: str, requester: Optional[str], origin: Optional[str] = None
    ) -> bool:
        """
        Calculate whether the room should be shown to the requester.

        It should return true if:

        * The requester is joined or can join the room (per MSC3173).
        * The origin server has any user that is joined or can join the room.
        * The history visibility is set to world readable.

        Args:
            room_id: The room ID to check accessibility of.
            requester:
                The user making the request, if it is a local request.
                None if this is a federation request.
            origin:
                The server making the request, if it is a federation request.
                None if this is a local request.

        Returns:
             True if the room is accessible to the requesting user or server.
        """
        state_ids = await self._storage_controllers.state.get_current_state_ids(room_id)

        # If there's no state for the room, it isn't known.
        if not state_ids:
            # The user might have a pending invite for the room.
            if requester and await self._store.get_invite_for_local_user_in_room(
                requester, room_id
            ):
                return True

            logger.info("room %s is unknown, omitting from summary", room_id)
            return False

        try:
            room_version = await self._store.get_room_version(room_id)
        except UnsupportedRoomVersionError:
            # If a room with an unsupported room version is encountered, ignore
            # it to avoid breaking the entire summary response.
            return False

        # Include the room if it has join rules of public or knock.
        join_rules_event_id = state_ids.get((EventTypes.JoinRules, ""))
        if join_rules_event_id:
            join_rules_event = await self._store.get_event(join_rules_event_id)
            join_rule = join_rules_event.content.get("join_rule")
            if (
                join_rule == JoinRules.PUBLIC
                or (room_version.msc2403_knocking and join_rule == JoinRules.KNOCK)
                or (
                    room_version.msc3787_knock_restricted_join_rule
                    and join_rule == JoinRules.KNOCK_RESTRICTED
                )
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
            if await self._event_auth_handler.is_host_in_room(
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
                    if await self._event_auth_handler.is_host_in_room(space_id, origin):
                        return True

        logger.info(
            "room %s is unpeekable and requester %s is not a member / not allowed to join, omitting from summary",
            room_id,
            requester or origin,
        )
        return False

    async def _is_remote_room_accessible(
        self, requester: Optional[str], room_id: str, room: JsonDict
    ) -> bool:
        """
        Calculate whether the room received over federation should be shown to the requester.

        It should return true if:

        * The requester is joined or can join the room (per MSC3173).
        * The history visibility is set to world readable.

        Note that the local server is not in the requested room (which is why the
        remote call was made in the first place), but the user could have access
        due to an invite, etc.

        Args:
            requester: The user requesting the summary. If not passed only world
                readability is checked.
            room_id: The room ID returned over federation.
            room: The summary of the room returned over federation.

        Returns:
            True if the room is accessible to the requesting user.
        """
        # The API doesn't return the room version so assume that a
        # join rule of knock is valid.
        if (
            room.get("join_rule")
            in (JoinRules.PUBLIC, JoinRules.KNOCK, JoinRules.KNOCK_RESTRICTED)
            or room.get("world_readable") is True
        ):
            return True
        elif not requester:
            return False

        # Check if the user is a member of any of the allowed rooms from the response.
        allowed_rooms = room.get("allowed_room_ids")
        if allowed_rooms and isinstance(allowed_rooms, list):
            if await self._event_auth_handler.is_user_in_rooms(
                allowed_rooms, requester
            ):
                return True

        # Finally, check locally if we can access the room. The user might
        # already be in the room (if it was a child room), or there might be a
        # pending invite, etc.
        return await self._is_local_room_accessible(room_id, requester)

    async def _build_room_entry(self, room_id: str, for_federation: bool) -> JsonDict:
        """
        Generate en entry summarising a single room.

        Args:
            room_id: The room ID to summarize.
            for_federation: True if this is a summary requested over federation
                (which includes additional fields).

        Returns:
            The JSON dictionary for the room.
        """
        stats = await self._store.get_room_with_stats(room_id)

        # currently this should be impossible because we call
        # _is_local_room_accessible on the room before we get here, so
        # there should always be an entry
        assert stats is not None, "unable to retrieve stats for %s" % (room_id,)

        current_state_ids = await self._storage_controllers.state.get_current_state_ids(
            room_id
        )
        create_event = await self._store.get_event(
            current_state_ids[(EventTypes.Create, "")]
        )

        entry = {
            "room_id": stats["room_id"],
            "name": stats["name"],
            "topic": stats["topic"],
            "canonical_alias": stats["canonical_alias"],
            "num_joined_members": stats["joined_members"],
            "avatar_url": stats["avatar"],
            "join_rule": stats["join_rules"],
            "world_readable": (
                stats["history_visibility"] == HistoryVisibility.WORLD_READABLE
            ),
            "guest_can_join": stats["guest_access"] == "can_join",
            "room_type": create_event.content.get(EventContentFields.ROOM_TYPE),
        }

        if self._msc3266_enabled:
            entry["im.nheko.summary.version"] = stats["version"]
            entry["im.nheko.summary.encryption"] = stats["encryption"]

        # Federation requests need to provide additional information so the
        # requested server is able to filter the response appropriately.
        if for_federation:
            room_version = await self._store.get_room_version(room_id)
            if await self._event_auth_handler.has_restricted_join_rules(
                current_state_ids, room_version
            ):
                allowed_rooms = (
                    await self._event_auth_handler.get_rooms_that_allow_join(
                        current_state_ids
                    )
                )
                if allowed_rooms:
                    entry["allowed_room_ids"] = allowed_rooms

        # Filter out Nones – rather omit the field altogether
        room_entry = {k: v for k, v in entry.items() if v is not None}

        return room_entry

    async def _get_child_events(self, room_id: str) -> Iterable[EventBase]:
        """
        Get the child events for a given room.

        The returned results are sorted for stability.

        Args:
            room_id: The room id to get the children of.

        Returns:
            An iterable of sorted child events.
        """

        # look for child rooms/spaces.
        current_state_ids = await self._storage_controllers.state.get_current_state_ids(
            room_id
        )

        events = await self._store.get_events_as_list(
            [
                event_id
                for key, event_id in current_state_ids.items()
                if key[0] == EventTypes.SpaceChild
            ]
        )

        # filter out any events without a "via" (which implies it has been redacted),
        # and order to ensure we return stable results.
        return sorted(filter(_has_valid_via, events), key=_child_events_comparison_key)

    async def get_room_summary(
        self,
        requester: Optional[str],
        room_id: str,
        remote_room_hosts: Optional[List[str]] = None,
    ) -> JsonDict:
        """
        Implementation of the room summary C-S API from MSC3266

        Args:
            requester:  user id of the user making this request, will be None
                for unauthenticated requests

            room_id: room id to summarise.

            remote_room_hosts: a list of homeservers to try fetching data through
                if we don't know it ourselves

        Returns:
            summary dict to return
        """
        is_in_room = await self._store.is_host_joined(room_id, self._server_name)

        if is_in_room:
            room_entry = await self._summarize_local_room(
                requester,
                None,
                room_id,
                # Suggested-only doesn't matter since no children are requested.
                suggested_only=False,
                include_children=False,
            )

            if not room_entry:
                raise NotFoundError("Room not found or is not accessible")

            room_summary = room_entry.room

            # If there was a requester, add their membership.
            if requester:
                (
                    membership,
                    _,
                ) = await self._store.get_local_current_membership_for_user_in_room(
                    requester, room_id
                )

                room_summary["membership"] = membership or "leave"
        else:
            # Reuse the hierarchy query over federation
            if remote_room_hosts is None:
                raise SynapseError(400, "Missing via to query remote room")

            (
                room_entry,
                children_room_entries,
                inaccessible_children,
            ) = await self._summarize_remote_room_hierarchy(
                _RoomQueueEntry(room_id, remote_room_hosts),
                suggested_only=True,
            )

            # The results over federation might include rooms that we, as the
            # requesting server, are allowed to see, but the requesting user is
            # not permitted to see.
            #
            # Filter the returned results to only what is accessible to the user.
            if not room_entry or not await self._is_remote_room_accessible(
                requester, room_entry.room_id, room_entry.room
            ):
                raise NotFoundError("Room not found or is not accessible")

            room = dict(room_entry.room)
            room.pop("allowed_room_ids", None)

            # If there was a requester, add their membership.
            # We keep the membership in the local membership table unless the
            # room is purged even for remote rooms.
            if requester:
                (
                    membership,
                    _,
                ) = await self._store.get_local_current_membership_for_user_in_room(
                    requester, room_id
                )
                room["membership"] = membership or "leave"

            return room

        return room_summary


@attr.s(frozen=True, slots=True, auto_attribs=True)
class _RoomQueueEntry:
    # The room ID of this entry.
    room_id: str
    # The server to query if the room is not known locally.
    via: Sequence[str]
    # The minimum number of hops necessary to get to this room (compared to the
    # originally requested room).
    depth: int = 0
    # The room summary for this room returned via federation. This will only be
    # used if the room is not known locally (and is not a space).
    remote_room: Optional[JsonDict] = None


@attr.s(frozen=True, slots=True, auto_attribs=True)
class _RoomEntry:
    room_id: str
    # The room summary for this room.
    room: JsonDict
    # An iterable of the sorted, stripped children events for children of this room.
    #
    # This may not include all children.
    children_state_events: Sequence[JsonDict] = ()

    def as_json(self, for_client: bool = False) -> JsonDict:
        """
        Returns a JSON dictionary suitable for the room hierarchy endpoint.

        It returns the room summary including the stripped m.space.child events
        as a sub-key.

        Args:
            for_client: If true, any server-server only fields are stripped from
                the result.

        """
        result = dict(self.room)

        # Before returning to the client, remove the allowed_room_ids key, if it
        # exists.
        if for_client:
            result.pop("allowed_room_ids", False)

        result["children_state"] = self.children_state_events
        return result


def _has_valid_via(e: EventBase) -> bool:
    via = e.content.get("via")
    if not via or not isinstance(via, list):
        return False
    for v in via:
        if not isinstance(v, str):
            logger.debug("Ignoring edge event %s with invalid via entry", e.event_id)
            return False
    return True


def _is_suggested_child_event(edge_event: EventBase) -> bool:
    suggested = edge_event.content.get("suggested")
    if isinstance(suggested, bool) and suggested:
        return True
    logger.debug("Ignorning not-suggested child %s", edge_event.state_key)
    return False


# Order may only contain characters in the range of \x20 (space) to \x7E (~) inclusive.
_INVALID_ORDER_CHARS_RE = re.compile(r"[^\x20-\x7E]")


def _child_events_comparison_key(
    child: EventBase,
) -> Tuple[bool, Optional[str], int, str]:
    """
    Generate a value for comparing two child events for ordering.

    The rules for ordering are:

    1. The 'order' key, if it is valid.
    2. The 'origin_server_ts' of the 'm.space.child' event.
    3. The 'room_id'.

    Args:
        child: The event for generating a comparison key.

    Returns:
        The comparison key as a tuple of:
            False if the ordering is valid.
            The 'order' field or None if it is not given or invalid.
            The 'origin_server_ts' field.
            The room ID.
    """
    order = child.content.get("order")
    # If order is not a string or doesn't meet the requirements, ignore it.
    if not isinstance(order, str):
        order = None
    elif len(order) > 50 or _INVALID_ORDER_CHARS_RE.search(order):
        order = None

    # Items without an order come last.
    return order is None, order, child.origin_server_ts, child.room_id
