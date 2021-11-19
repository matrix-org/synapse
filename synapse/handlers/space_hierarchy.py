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
from typing import (
    TYPE_CHECKING,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)

from synapse.api.constants import EventContentFields, EventTypes, RoomTypes
from synapse.api.errors import SynapseError
from synapse.handlers.room_summary import child_events_comparison_key, has_valid_via
from synapse.storage.state import StateFilter
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class SpaceHierarchyHandler:
    """Provides methods for walking over space hierarchies.

    Also see `RoomSummaryHandler`, which has similar functionality.
    """

    def __init__(self, hs: "HomeServer"):
        self._store = hs.get_datastore()
        self._federation_client = hs.get_federation_client()

        self._server_name = hs.hostname

    async def get_space_descendants(
        self,
        space_id: str,
        via: Optional[Iterable[str]] = None,
        enable_federation: Optional[bool] = True,
    ) -> Tuple[Sequence[Tuple[str, Iterable[str]]], Sequence[str]]:
        """Gets the children of a space, recursively.

        Args:
            space_id: The room ID of the space.
            via: A list of servers which may know about the space.
            enable_federation: A boolean controlling whether children of unknown rooms
                should be fetched over federation. Defaults to `True`.

        Returns:
            A tuple containing:
             * A list of (room ID, via) tuples, representing the descendants of the
               space. `space_id` is included in the list.
             * A list of room IDs whose children could not be fully listed.
               Rooms in this list are either spaces not known locally, and thus require
               listing over federation, or are unknown rooms or subspaces completely
               inaccessible to the local homeserver which may contain further rooms.
               Subspaces requiring listing over federation are always included here,
               regardless of the value of the `enable_federation` flag.

               This list is a subset of the previous list, except it may include
               `space_id`.
        """
        via = via or []

        # (room ID, via, federation room chunks)
        todo: List[Tuple[str, Iterable[str], Mapping[str, Optional[JsonDict]]]] = [
            (space_id, via, {})
        ]
        # [(room ID, via)]
        descendants: List[Tuple[str, Iterable[str]]] = []

        seen = {space_id}

        inaccessible_room_ids: List[str] = []

        while todo:
            space_id, via, federation_room_chunks = todo.pop()
            descendants.append((space_id, via))
            try:
                (
                    is_in_room,
                    children,
                    federation_room_chunks,
                ) = await self._get_space_children(
                    space_id,
                    via,
                    federation_room_chunks,
                    enable_federation=enable_federation,
                )
            except SynapseError:
                # Could not list children over federation
                inaccessible_room_ids.append(space_id)
                continue

            # Children were retrieved over federation, which is not guaranteed to be
            # the full list.
            if not is_in_room:
                inaccessible_room_ids.append(space_id)

            for child_room_id, child_via in reversed(children):
                if child_room_id in seen:
                    continue

                seen.add(child_room_id)

                # Queue up the child for processing.
                # The child may not actually be a space, but that's checked by
                # `_get_space_children`.
                todo.append((child_room_id, child_via, federation_room_chunks))

        return descendants, inaccessible_room_ids

    async def _get_space_children(
        self,
        space_id: str,
        via: Optional[Iterable[str]] = None,
        federation_room_chunks: Optional[Mapping[str, Optional[JsonDict]]] = None,
        enable_federation: Optional[bool] = True,
    ) -> Tuple[
        bool, Sequence[Tuple[str, Iterable[str]]], Mapping[str, Optional[JsonDict]]
    ]:
        """Gets the direct children of a space.

        Args:
            space_id: The room ID of the space.
            via: A list of servers which may know about the space.
            federation_room_chunks: A cache of room chunks previously returned by
               `_get_space_children` that may be used to skip federation requests for
               inaccessible or non-space rooms.

        Returns:
            A tuple containing:
             * A boolean indicating whether `space_id` is known to the local homeserver.
             * A list of (room ID, via) tuples, representing the children of the space,
               if `space_id` refers to a space; an empty list otherwise.
             * A dictionary of child room ID: `PublicRoomsChunk`s returned over
               federation:
               https://spec.matrix.org/latest/client-server-api/#get_matrixclientv3publicrooms
               These are supposed to include extra `room_type` and `allowed_room_ids`
               fields, as described in MSC2946.

               Contains `None` for rooms to which the remote homeserver thinks we do not
               have access.

               Local information about rooms should be trusted over data in this
               dictionary.

        Raises:
            SynapseError: if `space_id` is not known locally and its children could not
                be retrieved over federation or `enable_federation` is `False`.
        """
        via = via or []
        federation_room_chunks = federation_room_chunks or {}

        is_in_room = await self._store.is_host_joined(space_id, self._server_name)
        if is_in_room:
            children = await self._get_space_children_local(space_id)
            return True, children, {}
        else:
            # Check the room chunks previously returned over federation to see if we
            # should really make a request.
            # `federation_room_chunks` is intentionally not used earlier since we want
            # to trust local data over data from federation.
            if space_id in federation_room_chunks:
                room_chunk = federation_room_chunks[space_id]
                if room_chunk is None:
                    # `space_id` is inaccessible to the local homeserver according to
                    # federation.
                    raise SynapseError(
                        502, f"{space_id} is not accessible to the local homeserver"
                    )
                elif room_chunk.get("room_type") != RoomTypes.SPACE:
                    # `space_id` is not a space according to federation.
                    return False, [], {}

            if not enable_federation:
                raise SynapseError(
                    502, f"{space_id} is not accessible to the local homeserver"
                )

            children, room_chunks = await self._get_space_children_remote(space_id, via)
            return False, children, room_chunks

    async def _get_space_children_local(
        self, space_id: str
    ) -> Sequence[Tuple[str, Iterable[str]]]:
        """Gets the direct children of a space that the local homeserver is in.

        Args:
            space_id: The room ID of the space.

        Returns:
            A list of (room ID, via) tuples, representing the children of the space,
            if `space_id` refers to a space; an empty list otherwise.

        Raises:
            ValueError: if `space_id` is not known locally.
        """
        # Fetch the `m.room.create` and `m.space.child` events for `space_id`
        state_filter = StateFilter.from_types(
            [(EventTypes.Create, ""), (EventTypes.SpaceChild, None)]
        )
        current_state_ids = await self._store.get_filtered_current_state_ids(
            space_id, state_filter
        )
        state_events = await self._store.get_events_as_list(current_state_ids.values())
        assert len(state_events) == len(current_state_ids)

        create_event_id = current_state_ids.get((EventTypes.Create, ""))
        if create_event_id is None:
            # The local homeserver is not in this room
            raise ValueError(f"{space_id} is not a room known locally.")

        create_event = next(
            event for event in state_events if event.event_id == create_event_id
        )
        if create_event.content.get(EventContentFields.ROOM_TYPE) != RoomTypes.SPACE:
            # `space_id` is a regular room and not a space.
            # Ignore any `m.space.child` events.
            return []

        child_events = [
            event
            for event in state_events
            # Ignore events with a missing or non-array `via`, as per MSC1772
            if event.event_id != create_event_id and has_valid_via(event)
        ]
        child_events.sort(key=child_events_comparison_key)
        return [(event.state_key, event.content["via"]) for event in child_events]

    async def _get_space_children_remote(
        self, space_id: str, via: Iterable[str]
    ) -> Tuple[Sequence[Tuple[str, Iterable[str]]], Mapping[str, Optional[JsonDict]]]:
        """Gets the direct children of a space over federation.

        Args:
            space_id: The room ID of the space.
            via: A list of servers which may know about the space.

        Returns:
            A tuple containing:
             * A list of (room ID, via) tuples, representing the children of the space,
               if `space_id` refers to a space; an empty list otherwise.
             * A dictionary of child room ID: `PublicRoomsChunk`s returned over
               federation:
               https://spec.matrix.org/latest/client-server-api/#get_matrixclientv3publicrooms
               These are supposed to include extra `room_type` and `allowed_room_ids`
               fields, as described in MSC2946.

               Contains `None` for rooms to which the remote homeserver thinks we do not
               have access.

        Raises:
            SynapseError: if none of the remote servers provided us with the space's
                children.
        """
        (
            room,
            children_chunks,
            inaccessible_children,
        ) = await self._federation_client.get_room_hierarchy(
            via, space_id, suggested_only=False
        )

        child_events: List[JsonDict] = room["children_state"]
        children = [
            (child_event["room_id"], child_event["content"]["via"])
            for child_event in child_events
        ]

        room_chunks: Dict[str, Optional[JsonDict]] = {}
        room_chunks.update((room_id, None) for room_id in inaccessible_children)
        room_chunks.update(
            (room_chunk["room_id"], room_chunk) for room_chunk in children_chunks
        )

        return children, room_chunks
