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
from typing import TYPE_CHECKING, Dict, Iterable, Optional, cast

import attr
from frozendict import frozendict

from synapse.api.constants import RelationTypes
from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.types import JsonDict, Requester, StreamToken
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore


logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _ThreadAggregation:
    # The latest event in the thread.
    latest_event: EventBase
    # The latest edit to the latest event in the thread.
    latest_edit: Optional[EventBase]
    # The total number of events in the thread.
    count: int
    # True if the current user has sent an event to the thread.
    current_user_participated: bool


@attr.s(slots=True, auto_attribs=True)
class BundledAggregations:
    """
    The bundled aggregations for an event.

    Some values require additional processing during serialization.
    """

    annotations: Optional[JsonDict] = None
    references: Optional[JsonDict] = None
    replace: Optional[EventBase] = None
    thread: Optional[_ThreadAggregation] = None

    def __bool__(self) -> bool:
        return bool(self.annotations or self.references or self.replace or self.thread)


class RelationsHandler:
    def __init__(self, hs: "HomeServer"):
        self._main_store = hs.get_datastores().main
        self._storage = hs.get_storage()
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

        # TODO Properly handle a user leaving a room.
        (_, member_event_id) = await self._auth.check_user_in_room_or_world_readable(
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

        events = await filter_events_for_client(
            self._storage, user_id, events, is_peeking=(member_event_id is None)
        )

        now = self._clock.time_msec()
        # Do not bundle aggregations when retrieving the original event because
        # we want the content before relations are applied to it.
        original_event = self._event_serializer.serialize_event(
            event, now, bundle_aggregations=None
        )
        # The relations returned for the requested event do include their
        # bundled aggregations.
        aggregations = await self.get_bundled_aggregations(
            events, requester.user.to_string()
        )
        serialized_events = self._event_serializer.serialize_events(
            events, now, bundle_aggregations=aggregations
        )

        return_value = await pagination_chunk.to_dict(self._main_store)
        return_value["chunk"] = serialized_events
        return_value["original_event"] = original_event

        return return_value

    async def _get_bundled_aggregation_for_event(
        self, event: EventBase, user_id: str
    ) -> Optional[BundledAggregations]:
        """Generate bundled aggregations for an event.

        Note that this does not use a cache, but depends on cached methods.

        Args:
            event: The event to calculate bundled aggregations for.
            user_id: The user requesting the bundled aggregations.

        Returns:
            The bundled aggregations for an event, if bundled aggregations are
            enabled and the event can have bundled aggregations.
        """

        # Do not bundle aggregations for an event which represents an edit or an
        # annotation. It does not make sense for them to have related events.
        relates_to = event.content.get("m.relates_to")
        if isinstance(relates_to, (dict, frozendict)):
            relation_type = relates_to.get("rel_type")
            if relation_type in (RelationTypes.ANNOTATION, RelationTypes.REPLACE):
                return None

        event_id = event.event_id
        room_id = event.room_id

        # The bundled aggregations to include, a mapping of relation type to a
        # type-specific value. Some types include the direct return type here
        # while others need more processing during serialization.
        aggregations = BundledAggregations()

        annotations = await self._main_store.get_aggregation_groups_for_event(
            event_id, room_id
        )
        if annotations.chunk:
            aggregations.annotations = await annotations.to_dict(
                cast("DataStore", self)
            )

        references = await self._main_store.get_relations_for_event(
            event_id, event, room_id, RelationTypes.REFERENCE, direction="f"
        )
        if references.chunk:
            aggregations.references = await references.to_dict(cast("DataStore", self))

        # Store the bundled aggregations in the event metadata for later use.
        return aggregations

    async def get_bundled_aggregations(
        self, events: Iterable[EventBase], user_id: str
    ) -> Dict[str, BundledAggregations]:
        """Generate bundled aggregations for events.

        Args:
            events: The iterable of events to calculate bundled aggregations for.
            user_id: The user requesting the bundled aggregations.

        Returns:
            A map of event ID to the bundled aggregation for the event. Not all
            events may have bundled aggregations in the results.
        """
        # De-duplicate events by ID to handle the same event requested multiple times.
        #
        # State events do not get bundled aggregations.
        events_by_id = {
            event.event_id: event for event in events if not event.is_state()
        }

        # event ID -> bundled aggregation in non-serialized form.
        results: Dict[str, BundledAggregations] = {}

        # Fetch other relations per event.
        for event in events_by_id.values():
            event_result = await self._get_bundled_aggregation_for_event(event, user_id)
            if event_result:
                results[event.event_id] = event_result

        # Fetch any edits (but not for redacted events).
        edits = await self._main_store.get_applicable_edits(
            [
                event_id
                for event_id, event in events_by_id.items()
                if not event.internal_metadata.is_redacted()
            ]
        )
        for event_id, edit in edits.items():
            results.setdefault(event_id, BundledAggregations()).replace = edit

        # Fetch thread summaries.
        summaries = await self._main_store.get_thread_summaries(events_by_id.keys())
        # Only fetch participated for a limited selection based on what had
        # summaries.
        participated = await self._main_store.get_threads_participated(
            [event_id for event_id, summary in summaries.items() if summary], user_id
        )
        for event_id, summary in summaries.items():
            if summary:
                thread_count, latest_thread_event, edit = summary
                results.setdefault(
                    event_id, BundledAggregations()
                ).thread = _ThreadAggregation(
                    latest_event=latest_thread_event,
                    latest_edit=edit,
                    count=thread_count,
                    # If there's a thread summary it must also exist in the
                    # participated dictionary.
                    current_user_participated=participated[event_id],
                )

        return results
