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
from collections import deque
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Set, Tuple

import attr

from synapse.api.constants import (
    EventContentFields,
    EventTypes,
    HistoryVisibility,
    Membership,
    RoomTypes,
)
from synapse.events import EventBase
from synapse.events.utils import format_event_for_client_v2
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# number of rooms to return. We'll stop once we hit this limit.
MAX_ROOMS = 50

# max number of events to return per room.
MAX_ROOMS_PER_SPACE = 50

# max number of federation servers to hit per room
MAX_SERVERS_PER_SPACE = 3


class SpaceSummaryHandler:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._event_auth_handler = hs.get_event_auth_handler()
        self._store = hs.get_datastore()
        self._event_serializer = hs.get_event_client_serializer()
        self._server_name = hs.hostname
        self._federation_client = hs.get_federation_client()

    async def get_space_summary(
        self,
        requester: str,
        room_id: str,
        suggested_only: bool = False,
        max_rooms_per_space: Optional[int] = None,
    ) -> JsonDict:
        """
        Implementation of the space summary C-S API

        Args:
            requester:  user id of the user making this request

            room_id: room id to start the summary at

            suggested_only: whether we should only return children with the "suggested"
                flag set.

            max_rooms_per_space: an optional limit on the number of child rooms we will
                return. This does not apply to the root room (ie, room_id), and
                is overridden by MAX_ROOMS_PER_SPACE.

        Returns:
            summary dict to return
        """
        # first of all, check that the user is in the room in question (or it's
        # world-readable)
        await self._auth.check_user_in_room_or_world_readable(room_id, requester)

        # the queue of rooms to process
        room_queue = deque((_RoomQueueEntry(room_id, ()),))

        # rooms we have already processed
        processed_rooms = set()  # type: Set[str]

        # events we have already processed. We don't necessarily have their event ids,
        # so instead we key on (room id, state key)
        processed_events = set()  # type: Set[Tuple[str, str]]

        rooms_result = []  # type: List[JsonDict]
        events_result = []  # type: List[JsonDict]

        while room_queue and len(rooms_result) < MAX_ROOMS:
            queue_entry = room_queue.popleft()
            room_id = queue_entry.room_id
            if room_id in processed_rooms:
                # already done this room
                continue

            logger.debug("Processing room %s", room_id)

            is_in_room = await self._store.is_host_joined(room_id, self._server_name)

            # The client-specified max_rooms_per_space limit doesn't apply to the
            # room_id specified in the request, so we ignore it if this is the
            # first room we are processing.
            max_children = max_rooms_per_space if processed_rooms else None

            if is_in_room:
                room, events = await self._summarize_local_room(
                    requester, None, room_id, suggested_only, max_children
                )

                logger.debug(
                    "Query of local room %s returned events %s",
                    room_id,
                    ["%s->%s" % (ev["room_id"], ev["state_key"]) for ev in events],
                )

                if room:
                    rooms_result.append(room)
            else:
                fed_rooms, fed_events = await self._summarize_remote_room(
                    queue_entry,
                    suggested_only,
                    max_children,
                    exclude_rooms=processed_rooms,
                )

                # The results over federation might include rooms that the we,
                # as the requesting server, are allowed to see, but the requesting
                # user is not permitted see.
                #
                # Filter the returned results to only what is accessible to the user.
                room_ids = set()
                events = []
                for room in fed_rooms:
                    fed_room_id = room.get("room_id")
                    if not fed_room_id or not isinstance(fed_room_id, str):
                        continue

                    # The room should only be included in the summary if:
                    #     a. the user is in the room;
                    #     b. the room is world readable; or
                    #     c. the user is in a space that has been granted access to
                    #        the room.
                    #
                    # Note that we know the user is not in the root room (which is
                    # why the remote call was made in the first place), but the user
                    # could be in one of the children rooms and we just didn't know
                    # about the link.
                    include_room = room.get("world_readable") is True

                    # Check if the user is a member of any of the allowed spaces
                    # from the response.
                    allowed_rooms = room.get("allowed_spaces")
                    if (
                        not include_room
                        and allowed_rooms
                        and isinstance(allowed_rooms, list)
                    ):
                        include_room = await self._event_auth_handler.is_user_in_rooms(
                            allowed_rooms, requester
                        )

                    # Finally, if this isn't the requested room, check ourselves
                    # if we can access the room.
                    if not include_room and fed_room_id != queue_entry.room_id:
                        include_room = await self._is_room_accessible(
                            fed_room_id, requester, None
                        )

                    # The user can see the room, include it!
                    if include_room:
                        rooms_result.append(room)
                        room_ids.add(fed_room_id)

                    # All rooms returned don't need visiting again (even if the user
                    # didn't have access to them).
                    processed_rooms.add(fed_room_id)

                for event in fed_events:
                    if event.get("room_id") in room_ids:
                        events.append(event)

                logger.debug(
                    "Query of %s returned rooms %s, events %s",
                    room_id,
                    [room.get("room_id") for room in fed_rooms],
                    ["%s->%s" % (ev["room_id"], ev["state_key"]) for ev in fed_events],
                )

            # the room we queried may or may not have been returned, but don't process
            # it again, anyway.
            processed_rooms.add(room_id)

            # XXX: is it ok that we blindly iterate through any events returned by
            #   a remote server, whether or not they actually link to any rooms in our
            #   tree?
            for ev in events:
                # remote servers might return events we have already processed
                # (eg, Dendrite returns inward pointers as well as outward ones), so
                # we need to filter them out, to avoid returning duplicate links to the
                # client.
                ev_key = (ev["room_id"], ev["state_key"])
                if ev_key in processed_events:
                    continue
                events_result.append(ev)

                # add the child to the queue. we have already validated
                # that the vias are a list of server names.
                room_queue.append(
                    _RoomQueueEntry(ev["state_key"], ev["content"]["via"])
                )
                processed_events.add(ev_key)

        # Before returning to the client, remove the allowed_spaces key for any
        # rooms.
        for room in rooms_result:
            room.pop("allowed_spaces", None)

        return {"rooms": rooms_result, "events": events_result}

    async def federation_space_summary(
        self,
        origin: str,
        room_id: str,
        suggested_only: bool,
        max_rooms_per_space: Optional[int],
        exclude_rooms: Iterable[str],
    ) -> JsonDict:
        """
        Implementation of the space summary Federation API

        Args:
            origin: The server requesting the spaces summary.

            room_id: room id to start the summary at

            suggested_only: whether we should only return children with the "suggested"
                flag set.

            max_rooms_per_space: an optional limit on the number of child rooms we will
                return. Unlike the C-S API, this applies to the root room (room_id).
                It is clipped to MAX_ROOMS_PER_SPACE.

            exclude_rooms: a list of rooms to skip over (presumably because the
                calling server has already seen them).

        Returns:
            summary dict to return
        """
        # the queue of rooms to process
        room_queue = deque((room_id,))

        # the set of rooms that we should not walk further. Initialise it with the
        # excluded-rooms list; we will add other rooms as we process them so that
        # we do not loop.
        processed_rooms = set(exclude_rooms)  # type: Set[str]

        rooms_result = []  # type: List[JsonDict]
        events_result = []  # type: List[JsonDict]

        while room_queue and len(rooms_result) < MAX_ROOMS:
            room_id = room_queue.popleft()
            if room_id in processed_rooms:
                # already done this room
                continue

            logger.debug("Processing room %s", room_id)

            room, events = await self._summarize_local_room(
                None, origin, room_id, suggested_only, max_rooms_per_space
            )

            processed_rooms.add(room_id)

            if room:
                rooms_result.append(room)
                events_result.extend(events)

            # add any children to the queue
            room_queue.extend(edge_event["state_key"] for edge_event in events)

        return {"rooms": rooms_result, "events": events_result}

    async def _summarize_local_room(
        self,
        requester: Optional[str],
        origin: Optional[str],
        room_id: str,
        suggested_only: bool,
        max_children: Optional[int],
    ) -> Tuple[Optional[JsonDict], Sequence[JsonDict]]:
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
            max_children:
                The maximum number of children rooms to include. This is capped
                to a server-set limit.

        Returns:
            A tuple of:
                The room information, if the room should be returned to the
                user. None, otherwise.

                An iterable of the sorted children events. This may be limited
                to a maximum size or may include all children.
        """
        if not await self._is_room_accessible(room_id, requester, origin):
            return None, ()

        room_entry = await self._build_room_entry(room_id)

        # If the room is not a space, return just the room information.
        if room_entry.get("room_type") != RoomTypes.SPACE:
            return room_entry, ()

        # Otherwise, look for child rooms/spaces.
        child_events = await self._get_child_events(room_id)

        if suggested_only:
            # we only care about suggested children
            child_events = filter(_is_suggested_child_event, child_events)

        if max_children is None or max_children > MAX_ROOMS_PER_SPACE:
            max_children = MAX_ROOMS_PER_SPACE

        now = self._clock.time_msec()
        events_result = []  # type: List[JsonDict]
        for edge_event in itertools.islice(child_events, max_children):
            events_result.append(
                await self._event_serializer.serialize_event(
                    edge_event,
                    time_now=now,
                    event_format=format_event_for_client_v2,
                )
            )

        return room_entry, events_result

    async def _summarize_remote_room(
        self,
        room: "_RoomQueueEntry",
        suggested_only: bool,
        max_children: Optional[int],
        exclude_rooms: Iterable[str],
    ) -> Tuple[Sequence[JsonDict], Sequence[JsonDict]]:
        """
        Request room entries and a list of event entries for a given room by querying a remote server.

        Args:
            room: The room to summarize.
            suggested_only: True if only suggested children should be returned.
                Otherwise, all children are returned.
            max_children:
                The maximum number of children rooms to include. This is capped
                to a server-set limit.
            exclude_rooms:
                Rooms IDs which do not need to be summarized.

        Returns:
            A tuple of:
                An iterable of rooms.

                An iterable of the sorted children events. This may be limited
                to a maximum size or may include all children.
        """
        room_id = room.room_id
        logger.info("Requesting summary for %s via %s", room_id, room.via)

        # we need to make the exclusion list json-serialisable
        exclude_rooms = list(exclude_rooms)

        via = itertools.islice(room.via, MAX_SERVERS_PER_SPACE)
        try:
            res = await self._federation_client.get_space_summary(
                via,
                room_id,
                suggested_only=suggested_only,
                max_rooms_per_space=max_children,
                exclude_rooms=exclude_rooms,
            )
        except Exception as e:
            logger.warning(
                "Unable to get summary of %s via federation: %s",
                room_id,
                e,
                exc_info=logger.isEnabledFor(logging.DEBUG),
            )
            return (), ()

        return res.rooms, tuple(
            ev.data for ev in res.events if ev.event_type == EventTypes.SpaceChild
        )

    async def _is_room_accessible(
        self, room_id: str, requester: Optional[str], origin: Optional[str]
    ) -> bool:
        """
        Calculate whether the room should be shown in the spaces summary.

        It should be included if:

        * The requester is joined or invited to the room.
        * The requester can join without an invite (per MSC3083).
        * The origin server has any user that is joined or invited to the room.
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
             True if the room should be included in the spaces summary.
        """
        state_ids = await self._store.get_current_state_ids(room_id)

        # If there's no state for the room, it isn't known.
        if not state_ids:
            logger.info("room %s is unknown, omitting from summary", room_id)
            return False

        room_version = await self._store.get_room_version(room_id)

        # if we have an authenticated requesting user, first check if they are able to view
        # stripped state in the room.
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
        # is in one of the spaces specified via the join rules.
        elif origin:
            if await self._event_auth_handler.check_host_in_room(room_id, origin):
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

        # otherwise, check if the room is peekable
        hist_vis_event_id = state_ids.get((EventTypes.RoomHistoryVisibility, ""), None)
        if hist_vis_event_id:
            hist_vis_ev = await self._store.get_event(hist_vis_event_id)
            hist_vis = hist_vis_ev.content.get("history_visibility")
            if hist_vis == HistoryVisibility.WORLD_READABLE:
                return True

        logger.info(
            "room %s is unpeekable and user %s is not a member / not allowed to join, omitting from summary",
            room_id,
            requester,
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
            "world_readable": (
                stats["history_visibility"] == HistoryVisibility.WORLD_READABLE
            ),
            "guest_can_join": stats["guest_access"] == "can_join",
            "creation_ts": create_event.origin_server_ts,
            "room_type": create_event.content.get(EventContentFields.ROOM_TYPE),
            "allowed_spaces": allowed_rooms,
        }

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
        current_state_ids = await self._store.get_current_state_ids(room_id)

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


@attr.s(frozen=True, slots=True)
class _RoomQueueEntry:
    room_id = attr.ib(type=str)
    via = attr.ib(type=Sequence[str])


def _has_valid_via(e: EventBase) -> bool:
    via = e.content.get("via")
    if not via or not isinstance(via, Sequence):
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


def _child_events_comparison_key(child: EventBase) -> Tuple[bool, Optional[str], str]:
    """
    Generate a value for comparing two child events for ordering.

    The rules for ordering are supposed to be:

    1. The 'order' key, if it is valid.
    2. The 'origin_server_ts' of the 'm.room.create' event.
    3. The 'room_id'.

    But we skip step 2 since we may not have any state from the room.

    Args:
        child: The event for generating a comparison key.

    Returns:
        The comparison key as a tuple of:
            False if the ordering is valid.
            The ordering field.
            The room ID.
    """
    order = child.content.get("order")
    # If order is not a string or doesn't meet the requirements, ignore it.
    if not isinstance(order, str):
        order = None
    elif len(order) > 50 or _INVALID_ORDER_CHARS_RE.search(order):
        order = None

    # Items without an order come last.
    return (order is None, order, child.room_id)
