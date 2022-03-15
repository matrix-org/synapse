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
from typing import TYPE_CHECKING, Optional

from synapse.api.errors import SynapseError
from synapse.types import JsonDict, Requester, StreamToken

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class RelationsHandler:
    def __init__(self, hs: "HomeServer"):
        self._main_store = hs.get_datastores().main
        self._auth = hs.get_auth()
        self._clock = hs.get_clock()
        self._event_handler = hs.get_event_handler()
        self._event_serializer = hs.get_event_client_serializer()

    async def get_relations(
        self,
        requester: Requester,
        event_id: str,
        room_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
        aggregation_key: Optional[str] = None,
        limit: int = 5,
        direction: str = "b",
        from_token: Optional[StreamToken] = None,
        to_token: Optional[StreamToken] = None,
    ) -> JsonDict:
        """Get related events of a event, ordered by topological ordering.

        TODO Accept a PaginationConfig instead of individual pagination parameters.

        Args:
            requester: The user requesting the relations.
            event_id: Fetch events that relate to this event ID.
            room_id: The room the event belongs to.
            relation_type: Only fetch events with this relation type, if given.
            event_type: Only fetch events with this event type, if given.
            aggregation_key: Only fetch events with this aggregation key, if given.
            limit: Only fetch the most recent `limit` events.
            direction: Whether to fetch the most recent first (`"b"`) or the
                oldest first (`"f"`).
            from_token: Fetch rows from the given token, or from the start if None.
            to_token: Fetch rows up to the given token, or up to the end if None.

        Returns:
            The pagination chunk.
        """

        user_id = requester.user.to_string()

        await self._auth.check_user_in_room_or_world_readable(
            room_id, user_id, allow_departed_users=True
        )

        # This gets the original event and checks that a) the event exists and
        # b) the user is allowed to view it.
        event = await self._event_handler.get_event(requester.user, room_id, event_id)
        if event is None:
            raise SynapseError(404, "Unknown parent event.")

        pagination_chunk = await self._main_store.get_relations_for_event(
            event_id=event_id,
            event=event,
            room_id=room_id,
            relation_type=relation_type,
            event_type=event_type,
            aggregation_key=aggregation_key,
            limit=limit,
            direction=direction,
            from_token=from_token,
            to_token=to_token,
        )

        events = await self._main_store.get_events_as_list(
            [c["event_id"] for c in pagination_chunk.chunk]
        )

        now = self._clock.time_msec()
        # Do not bundle aggregations when retrieving the original event because
        # we want the content before relations are applied to it.
        original_event = self._event_serializer.serialize_event(
            event, now, bundle_aggregations=None
        )
        # The relations returned for the requested event do include their
        # bundled aggregations.
        aggregations = await self._main_store.get_bundled_aggregations(
            events, requester.user.to_string()
        )
        serialized_events = self._event_serializer.serialize_events(
            events, now, bundle_aggregations=aggregations
        )

        return_value = await pagination_chunk.to_dict(self._main_store)
        return_value["chunk"] = serialized_events
        return_value["original_event"] = original_event

        return return_value
