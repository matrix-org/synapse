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
from typing import TYPE_CHECKING, Iterable, List, Optional, Sequence, Set, Tuple

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


class SpaceSummaryHandler:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._room_list_handler = hs.get_room_list_handler()
        self._state_handler = hs.get_state_handler()
        self._store = hs.get_datastore()
        self._event_serializer = hs.get_event_client_serializer()

    async def get_space_summary(
        self,
        requester: str,
        room_id: str,
        suggested_only: bool = False,
        max_rooms_per_space: Optional[int] = None,
    ) -> JsonDict:
        """
        Implementation of the space summary API

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
        room_queue = deque((_RoomQueueEntry(room_id),))

        processed_rooms = set()  # type: Set[str]

        rooms_result = []  # type: List[JsonDict]
        events_result = []  # type: List[JsonDict]

        while room_queue and len(rooms_result) < MAX_ROOMS:
            queue_entry = room_queue.popleft()
            room_id = queue_entry.room_id
            logger.debug("Processing room %s", room_id)
            processed_rooms.add(room_id)

            # The client-specified max_rooms_per_space limit doesn't apply to the
            # room_id specified in the request, so we ignore it if this is the
            # first room we are processing.
            max_children = max_rooms_per_space if processed_rooms else None

            rooms, events = await self._summarize_local_room(
                requester, room_id, suggested_only, max_children
            )

            rooms_result.extend(rooms)
            events_result.extend(events)

            # add any children that we haven't already processed to the queue
            for edge_event in events:
                if edge_event["state_key"] not in processed_rooms:
                    room_queue.append(_RoomQueueEntry(edge_event["state_key"]))

        return {"rooms": rooms_result, "events": events_result}

    async def _summarize_local_room(
        self,
        requester: str,
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

    async def _is_room_accessible(self, room_id: str, requester: str) -> bool:
        try:
            await self._auth.check_user_in_room_or_world_readable(room_id, requester)
            return True
        except AuthError:
            pass

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
        return (e for e in events if e.content.get("via"))


@attr.s(frozen=True, slots=True)
class _RoomQueueEntry:
    room_id = attr.ib(type=str)


def _is_suggested_child_event(edge_event: EventBase) -> bool:
    suggested = edge_event.content.get("suggested")
    if isinstance(suggested, bool) and suggested:
        return True
    logger.debug("Ignorning not-suggested child %s", edge_event.state_key)
    return False
