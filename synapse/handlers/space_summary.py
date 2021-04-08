# -*- coding: utf-8 -*-
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
from collections import deque
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Set, Tuple, cast

import attr

from synapse.api.constants import EventContentFields, EventTypes, HistoryVisibility
from synapse.api.errors import AuthError
from synapse.events import EventBase
from synapse.events.utils import format_event_for_client_v2
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# number of rooms to return. We'll stop once we hit this limit.
# TODO: allow clients to reduce this with a request param.
MAX_ROOMS = 50

# max number of events to return per room.
MAX_ROOMS_PER_SPACE = 50

# max number of federation servers to hit per room
MAX_SERVERS_PER_SPACE = 3


class SpaceSummaryHandler:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._room_list_handler = hs.get_room_list_handler()
        self._state_handler = hs.get_state_handler()
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
                rooms, events = await self._summarize_local_room(
                    requester, room_id, suggested_only, max_children
                )
            else:
                rooms, events = await self._summarize_remote_room(
                    queue_entry,
                    suggested_only,
                    max_children,
                    exclude_rooms=processed_rooms,
                )

            logger.debug(
                "Query of %s returned rooms %s, events %s",
                queue_entry.room_id,
                [room.get("room_id") for room in rooms],
                ["%s->%s" % (ev["room_id"], ev["state_key"]) for ev in events],
            )

            rooms_result.extend(rooms)

            # any rooms returned don't need visiting again
            processed_rooms.update(cast(str, room.get("room_id")) for room in rooms)

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

        return {"rooms": rooms_result, "events": events_result}

    async def federation_space_summary(
        self,
        room_id: str,
        suggested_only: bool,
        max_rooms_per_space: Optional[int],
        exclude_rooms: Iterable[str],
    ) -> JsonDict:
        """
        Implementation of the space summary Federation API

        Args:
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

            rooms, events = await self._summarize_local_room(
                None, room_id, suggested_only, max_rooms_per_space
            )

            processed_rooms.add(room_id)

            rooms_result.extend(rooms)
            events_result.extend(events)

            # add any children to the queue
            room_queue.extend(edge_event["state_key"] for edge_event in events)

        return {"rooms": rooms_result, "events": events_result}

    async def _summarize_local_room(
        self,
        requester: Optional[str],
        room_id: str,
        suggested_only: bool,
        max_children: Optional[int],
    ) -> Tuple[Sequence[JsonDict], Sequence[JsonDict]]:
        if not await self._is_room_accessible(room_id, requester):
            return (), ()

        room_entry = await self._build_room_entry(room_id)

        # look for child rooms/spaces.
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
        return (room_entry,), events_result

    async def _summarize_remote_room(
        self,
        room: "_RoomQueueEntry",
        suggested_only: bool,
        max_children: Optional[int],
        exclude_rooms: Iterable[str],
    ) -> Tuple[Sequence[JsonDict], Sequence[JsonDict]]:
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
            ev.data
            for ev in res.events
            if ev.event_type == EventTypes.MSC1772_SPACE_CHILD
        )

    async def _is_room_accessible(self, room_id: str, requester: Optional[str]) -> bool:
        # if we have an authenticated requesting user, first check if they are in the
        # room
        if requester:
            try:
                await self._auth.check_user_in_room(room_id, requester)
                return True
            except AuthError:
                pass

        # otherwise, check if the room is peekable
        hist_vis_ev = await self._state_handler.get_current_state(
            room_id, EventTypes.RoomHistoryVisibility, ""
        )
        if hist_vis_ev:
            hist_vis = hist_vis_ev.content.get("history_visibility")
            if hist_vis == HistoryVisibility.WORLD_READABLE:
                return True

        logger.info(
            "room %s is unpeekable and user %s is not a member, omitting from summary",
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

        # TODO: update once MSC1772 lands
        room_type = create_event.content.get(EventContentFields.MSC1772_ROOM_TYPE)

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
            "room_type": room_type,
        }

        # Filter out Nones – rather omit the field altogether
        room_entry = {k: v for k, v in entry.items() if v is not None}

        return room_entry

    async def _get_child_events(self, room_id: str) -> Iterable[EventBase]:
        # look for child rooms/spaces.
        current_state_ids = await self._store.get_current_state_ids(room_id)

        events = await self._store.get_events_as_list(
            [
                event_id
                for key, event_id in current_state_ids.items()
                # TODO: update once MSC1772 lands
                if key[0] == EventTypes.MSC1772_SPACE_CHILD
            ]
        )

        # filter out any events without a "via" (which implies it has been redacted)
        return (e for e in events if _has_valid_via(e))


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
