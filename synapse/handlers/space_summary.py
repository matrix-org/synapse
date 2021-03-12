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

import logging
from collections import deque
from typing import TYPE_CHECKING, List, Set, Tuple

from synapse.api.constants import EventContentFields, EventTypes, HistoryVisibility
from synapse.api.errors import AuthError
from synapse.events.utils import format_event_for_client_v2
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

# number of rooms to return. We'll stop once we hit this limit.
# TODO: allow clients to reduce this with a request param.
# TODO: increase it, probably. It's deliberately low to start with so that
#    we can think about whether we need pagination.
ROOMS_LIMIT = 5

# number of events to return per room.
# TODO: allow clients to reduce this with a request param.
EVENTS_PER_ROOM_LIMIT = 5


class SpaceSummaryHandler:
    def __init__(self, hs: "HomeServer"):
        self._clock = hs.get_clock()
        self._auth = hs.get_auth()
        self._room_list_handler = hs.get_room_list_handler()
        self._state_handler = hs.get_state_handler()
        self._store = hs.get_datastore()
        self._msc1772 = hs.config.experimental.msc1772_enabled
        self._event_serializer = hs.get_event_client_serializer()

    async def get_space_summary(self, requester: str, room_id: str) -> JsonDict:
        """
        Implementation of the space summary API

        Args:
            requester:  user id of the user making this request
            room_id:    room id to start the summary at

        Returns:
            summary dict to return
        """

        # the queue of rooms to process
        room_queue = deque((room_id,))

        processed_rooms = set()  # type: Set[str]

        rooms_result = []  # type: List[JsonDict]
        events_result = []  # type: List[JsonDict]

        now = self._clock.time_msec()

        while room_queue and len(rooms_result) < ROOMS_LIMIT:
            room_id = room_queue.popleft()
            processed_rooms.add(room_id)
            try:
                await self._auth.check_user_in_room_or_world_readable(
                    room_id, requester
                )
            except AuthError:
                logger.debug(
                    "user %s cannot view room %s, omitting from summary",
                    requester,
                    room_id,
                )
                continue

            stats = await self._store.get_room_with_stats(room_id)
            assert stats is not None, "unable to retrieve stats for %s" % (room_id,)
            current_state_ids = await self._store.get_current_state_ids(room_id)
            create_event = await self._store.get_event(
                current_state_ids[(EventTypes.Create, "")]
            )

            room_type = None
            if self._msc1772:
                room_type = create_event.content.get(
                    EventContentFields.MSC1772_ROOM_TYPE
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
                "room_type": room_type,
            }

            # Filter out Nones – rather omit the field altogether
            room_entry = {k: v for k, v in entry.items() if v is not None}
            rooms_result.append(room_entry)

            if room_type != "org.matrix.msc1772.space":
                continue

            # look for child rooms/spaces.
            # TODO: add a param so that the client can request parent spaces instead

            edge_event_types = ()  # type: Tuple[str, ...]
            if self._msc1772:
                edge_event_types += (EventTypes.MSC1772_SPACE_CHILD,)

            events = await self._store.get_events_as_list(
                [
                    event_id
                    for key, event_id in current_state_ids.items()
                    if key[0] in edge_event_types
                ]
            )

            events_for_this_room = 0
            for edge_event in events:
                if not edge_event.content.get("via"):
                    # possibly redacted; ignore
                    continue

                if events_for_this_room < EVENTS_PER_ROOM_LIMIT:
                    events_result.append(
                        await self._event_serializer.serialize_event(
                            edge_event,
                            time_now=now,
                            event_format=format_event_for_client_v2,
                        )
                    )
                    events_for_this_room += 1

                # if we haven't yet visited the target of this link, add it to the
                # queue.
                edge_room_id = edge_event.state_key
                if edge_room_id not in processed_rooms:
                    room_queue.append(edge_room_id)

        return {"rooms": rooms_result, "events": events_result}
