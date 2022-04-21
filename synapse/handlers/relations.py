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
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Optional,
    Tuple,
)

import attr
from frozendict import frozendict

from synapse.api.constants import RelationTypes
from synapse.api.errors import SynapseError
from synapse.events import EventBase
from synapse.storage.databases.main.relations import _RelatedEvent
from synapse.types import JsonDict, Requester, StreamToken, UserID
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


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

        # Note that ignored users are not passed into get_relations_for_event
        # below. Ignored users are handled in filter_events_for_client (and by
        # not passing them in here we should get a better cache hit rate).
        related_events, next_token = await self._main_store.get_relations_for_event(
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
            [e.event_id for e in related_events]
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

        return_value = {
            "chunk": serialized_events,
            "original_event": original_event,
        }

        if next_token:
            return_value["next_batch"] = await next_token.to_string(self._main_store)

        if from_token:
            return_value["prev_batch"] = await from_token.to_string(self._main_store)

        return return_value

    async def get_relations_for_event(
        self,
        event_id: str,
        event: EventBase,
        room_id: str,
        relation_type: str,
        ignored_users: FrozenSet[str] = frozenset(),
    ) -> Tuple[List[_RelatedEvent], Optional[StreamToken]]:
        """Get a list of events which relate to an event, ordered by topological ordering.

        Args:
            event_id: Fetch events that relate to this event ID.
            event: The matching EventBase to event_id.
            room_id: The room the event belongs to.
            relation_type: The type of relation.
            ignored_users: The users ignored by the requesting user.

        Returns:
            List of event IDs that match relations requested. The rows are of
            the form `{"event_id": "..."}`.
        """

        # Call the underlying storage method, which is cached.
        related_events, next_token = await self._main_store.get_relations_for_event(
            event_id, event, room_id, relation_type, direction="f"
        )

        # Filter out ignored users and convert to the expected format.
        related_events = [
            event for event in related_events if event.sender not in ignored_users
        ]

        return related_events, next_token

    async def get_annotations_for_event(
        self,
        event_id: str,
        room_id: str,
        limit: int = 5,
        ignored_users: FrozenSet[str] = frozenset(),
    ) -> List[JsonDict]:
        """Get a list of annotations on the event, grouped by event type and
        aggregation key, sorted by count.

        This is used e.g. to get the what and how many reactions have happend
        on an event.

        Args:
            event_id: Fetch events that relate to this event ID.
            room_id: The room the event belongs to.
            limit: Only fetch the `limit` groups.
            ignored_users: The users ignored by the requesting user.

        Returns:
            List of groups of annotations that match. Each row is a dict with
            `type`, `key` and `count` fields.
        """
        # Get the base results for all users.
        full_results = await self._main_store.get_aggregation_groups_for_event(
            event_id, room_id, limit
        )

        # Then subtract off the results for any ignored users.
        ignored_results = await self._main_store.get_aggregation_groups_for_users(
            event_id, room_id, limit, ignored_users
        )

        filtered_results = []
        for result in full_results:
            key = (result["type"], result["key"])
            if key in ignored_results:
                result = result.copy()
                result["count"] -= ignored_results[key]
                if result["count"] <= 0:
                    continue
            filtered_results.append(result)

        return filtered_results

    async def get_threads_for_events(
        self, event_ids: Collection[str], user_id: str, ignored_users: FrozenSet[str]
    ) -> Dict[str, _ThreadAggregation]:
        """Get the bundled aggregations for threads for the requested events.

        Args:
            event_ids: Events to get aggregations for threads.
            user_id: The user requesting the bundled aggregations.
            ignored_users: The users ignored by the requesting user.

        Returns:
            A dictionary mapping event ID to the thread information.

            May not contain a value for all requested event IDs.
        """
        user = UserID.from_string(user_id)

        # Fetch thread summaries.
        summaries = await self._main_store.get_thread_summaries(event_ids)

        # Only fetch participated for a limited selection based on what had
        # summaries.
        thread_event_ids = [
            event_id for event_id, summary in summaries.items() if summary
        ]
        participated = await self._main_store.get_threads_participated(
            thread_event_ids, user_id
        )

        # Then subtract off the results for any ignored users.
        ignored_results = await self._main_store.get_threaded_messages_per_user(
            thread_event_ids, ignored_users
        )

        # A map of event ID to the thread aggregation.
        results = {}

        for event_id, summary in summaries.items():
            if summary:
                thread_count, latest_thread_event, edit = summary

                # Subtract off the count of any ignored users.
                for ignored_user in ignored_users:
                    thread_count -= ignored_results.get((event_id, ignored_user), 0)

                # This is gnarly, but if the latest event is from an ignored user,
                # attempt to find one that isn't from an ignored user.
                if latest_thread_event.sender in ignored_users:
                    room_id = latest_thread_event.room_id

                    # If the root event is not found, something went wrong, do
                    # not include a summary of the thread.
                    event = await self._event_handler.get_event(user, room_id, event_id)
                    if event is None:
                        continue

                    potential_events, _ = await self.get_relations_for_event(
                        event_id,
                        event,
                        room_id,
                        RelationTypes.THREAD,
                        ignored_users,
                    )

                    # If all found events are from ignored users, do not include
                    # a summary of the thread.
                    if not potential_events:
                        continue

                    # The *last* event returned is the one that is cared about.
                    event = await self._event_handler.get_event(
                        user, room_id, potential_events[-1].event_id
                    )
                    # It is unexpected that the event will not exist.
                    if event is None:
                        logger.warning(
                            "Unable to fetch latest event in a thread with event ID: %s",
                            potential_events[-1].event_id,
                        )
                        continue
                    latest_thread_event = event

                results[event_id] = _ThreadAggregation(
                    latest_event=latest_thread_event,
                    latest_edit=edit,
                    count=thread_count,
                    # If there's a thread summary it must also exist in the
                    # participated dictionary.
                    current_user_participated=participated[event_id],
                )

        return results

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

        # Fetch any ignored users of the requesting user.
        ignored_users = await self._main_store.ignored_users(user_id)

        # Fetch other relations per event.
        for event in events_by_id.values():
            # Do not bundle aggregations for an event which represents an edit or an
            # annotation. It does not make sense for them to have related events.
            relates_to = event.content.get("m.relates_to")
            if isinstance(relates_to, (dict, frozendict)):
                relation_type = relates_to.get("rel_type")
                if relation_type in (RelationTypes.ANNOTATION, RelationTypes.REPLACE):
                    continue

            annotations = await self.get_annotations_for_event(
                event.event_id, event.room_id, ignored_users=ignored_users
            )
            if annotations:
                results.setdefault(
                    event.event_id, BundledAggregations()
                ).annotations = {"chunk": annotations}

            references, next_token = await self.get_relations_for_event(
                event.event_id,
                event,
                event.room_id,
                RelationTypes.REFERENCE,
                ignored_users=ignored_users,
            )
            if references:
                aggregations = results.setdefault(event.event_id, BundledAggregations())
                aggregations.references = {
                    "chunk": [{"event_id": ev.event_id} for ev in references]
                }

                if next_token:
                    aggregations.references["next_batch"] = await next_token.to_string(
                        self._main_store
                    )

        # Fetch any edits (but not for redacted events).
        #
        # Note that there is no use in limiting edits by ignored users since the
        # parent event should be ignored in the first place if the user is ignored.
        edits = await self._main_store.get_applicable_edits(
            [
                event_id
                for event_id, event in events_by_id.items()
                if not event.internal_metadata.is_redacted()
            ]
        )
        for event_id, edit in edits.items():
            results.setdefault(event_id, BundledAggregations()).replace = edit

        threads = await self.get_threads_for_events(
            events_by_id.keys(), user_id, ignored_users
        )
        for event_id, thread in threads.items():
            results.setdefault(event_id, BundledAggregations()).thread = thread

        return results
