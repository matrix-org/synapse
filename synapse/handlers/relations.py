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
import enum
import logging
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
)

import attr

from synapse.api.constants import Direction, EventTypes, RelationTypes
from synapse.api.errors import SynapseError
from synapse.events import EventBase, relation_from_event
from synapse.events.utils import SerializeEventConfig
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.logging.opentracing import trace
from synapse.storage.databases.main.relations import ThreadsNextBatch, _RelatedEvent
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, Requester, UserID
from synapse.util.async_helpers import gather_results
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class ThreadsListInclude(str, enum.Enum):
    """Valid values for the 'include' flag of /threads."""

    all = "all"
    participated = "participated"


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _ThreadAggregation:
    # The latest event in the thread.
    latest_event: EventBase
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

    references: Optional[JsonDict] = None
    replace: Optional[EventBase] = None
    thread: Optional[_ThreadAggregation] = None

    def __bool__(self) -> bool:
        return bool(self.references or self.replace or self.thread)


class RelationsHandler:
    def __init__(self, hs: "HomeServer"):
        self._main_store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self._auth = hs.get_auth()
        self._clock = hs.get_clock()
        self._event_handler = hs.get_event_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self._event_creation_handler = hs.get_event_creation_handler()

    async def get_relations(
        self,
        requester: Requester,
        event_id: str,
        room_id: str,
        pagin_config: PaginationConfig,
        recurse: bool,
        include_original_event: bool,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> JsonDict:
        """Get related events of a event, ordered by topological ordering.

        TODO Accept a PaginationConfig instead of individual pagination parameters.

        Args:
            requester: The user requesting the relations.
            event_id: Fetch events that relate to this event ID.
            room_id: The room the event belongs to.
            pagin_config: The pagination config rules to apply, if any.
            recurse: Whether to recursively find relations.
            include_original_event: Whether to include the parent event.
            relation_type: Only fetch events with this relation type, if given.
            event_type: Only fetch events with this event type, if given.

        Returns:
            The pagination chunk.
        """

        user_id = requester.user.to_string()

        # TODO Properly handle a user leaving a room.
        (_, member_event_id) = await self._auth.check_user_in_room_or_world_readable(
            room_id, requester, allow_departed_users=True
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
            limit=pagin_config.limit,
            direction=pagin_config.direction,
            from_token=pagin_config.from_token,
            to_token=pagin_config.to_token,
            recurse=recurse,
        )

        events = await self._main_store.get_events_as_list(
            [e.event_id for e in related_events]
        )

        events = await filter_events_for_client(
            self._storage_controllers,
            user_id,
            events,
            is_peeking=(member_event_id is None),
        )

        # The relations returned for the requested event do include their
        # bundled aggregations.
        aggregations = await self.get_bundled_aggregations(
            events, requester.user.to_string()
        )

        now = self._clock.time_msec()
        serialize_options = SerializeEventConfig(requester=requester)
        return_value: JsonDict = {
            "chunk": await self._event_serializer.serialize_events(
                events,
                now,
                bundle_aggregations=aggregations,
                config=serialize_options,
            ),
        }
        if include_original_event:
            # Do not bundle aggregations when retrieving the original event because
            # we want the content before relations are applied to it.
            return_value[
                "original_event"
            ] = await self._event_serializer.serialize_event(
                event,
                now,
                bundle_aggregations=None,
                config=serialize_options,
            )

        if next_token:
            return_value["next_batch"] = await next_token.to_string(self._main_store)

        if pagin_config.from_token:
            return_value["prev_batch"] = await pagin_config.from_token.to_string(
                self._main_store
            )

        return return_value

    async def redact_events_related_to(
        self,
        requester: Requester,
        event_id: str,
        initial_redaction_event: EventBase,
        relation_types: List[str],
    ) -> None:
        """Redacts all events related to the given event ID with one of the given
        relation types.

        This method is expected to be called when redacting the event referred to by
        the given event ID.

        If an event cannot be redacted (e.g. because of insufficient permissions), log
        the error and try to redact the next one.

        Args:
            requester: The requester to redact events on behalf of.
            event_id: The event IDs to look and redact relations of.
            initial_redaction_event: The redaction for the event referred to by
                event_id.
            relation_types: The types of relations to look for. If "*" is in the list,
                all related events will be redacted regardless of the type.

        Raises:
            ShadowBanError if the requester is shadow-banned
        """
        if "*" in relation_types:
            related_event_ids = await self._main_store.get_all_relations_for_event(
                event_id
            )
        else:
            related_event_ids = (
                await self._main_store.get_all_relations_for_event_with_types(
                    event_id, relation_types
                )
            )

        for related_event_id in related_event_ids:
            try:
                await self._event_creation_handler.create_and_send_nonmember_event(
                    requester,
                    {
                        "type": EventTypes.Redaction,
                        "content": initial_redaction_event.content,
                        "room_id": initial_redaction_event.room_id,
                        "sender": requester.user.to_string(),
                        "redacts": related_event_id,
                    },
                    ratelimit=False,
                )
            except SynapseError as e:
                logger.warning(
                    "Failed to redact event %s (related to event %s): %s",
                    related_event_id,
                    event_id,
                    e.msg,
                )

    async def get_references_for_events(
        self, event_ids: Collection[str], ignored_users: FrozenSet[str] = frozenset()
    ) -> Mapping[str, Sequence[_RelatedEvent]]:
        """Get a list of references to the given events.

        Args:
            event_ids: Fetch events that relate to this event ID.
            ignored_users: The users ignored by the requesting user.

        Returns:
            A map of event IDs to a list related events.
        """

        related_events = await self._main_store.get_references_for_events(event_ids)

        # Avoid additional logic if there are no ignored users.
        if not ignored_users:
            return {
                event_id: results
                for event_id, results in related_events.items()
                if results
            }

        # Filter out ignored users.
        results = {}
        for event_id, events in related_events.items():
            # If no references, skip.
            if not events:
                continue

            # Filter ignored users out.
            events = [event for event in events if event.sender not in ignored_users]
            # If there are no events left, skip this event.
            if not events:
                continue

            results[event_id] = events

        return results

    async def _get_threads_for_events(
        self,
        events_by_id: Dict[str, EventBase],
        relations_by_id: Dict[str, str],
        user_id: str,
        ignored_users: FrozenSet[str],
    ) -> Dict[str, _ThreadAggregation]:
        """Get the bundled aggregations for threads for the requested events.

        Args:
            events_by_id: A map of event_id to events to get aggregations for threads.
            relations_by_id: A map of event_id to the relation type, if one exists
                for that event.
            user_id: The user requesting the bundled aggregations.
            ignored_users: The users ignored by the requesting user.

        Returns:
            A dictionary mapping event ID to the thread information.

            May not contain a value for all requested event IDs.
        """
        user = UserID.from_string(user_id)

        # It is not valid to start a thread on an event which itself relates to another event.
        event_ids = [eid for eid in events_by_id.keys() if eid not in relations_by_id]

        # Fetch thread summaries.
        summaries = await self._main_store.get_thread_summaries(event_ids)

        # Limit fetching whether the requester has participated in a thread to
        # events which are thread roots.
        thread_event_ids = [
            event_id for event_id, summary in summaries.items() if summary
        ]

        # Pre-seed thread participation with whether the requester sent the event.
        participated = {
            event_id: events_by_id[event_id].sender == user_id
            for event_id in thread_event_ids
        }
        # For events the requester did not send, check the database for whether
        # the requester sent a threaded reply.
        participated.update(
            await self._main_store.get_threads_participated(
                [
                    event_id
                    for event_id in thread_event_ids
                    if not participated[event_id]
                ],
                user_id,
            )
        )

        # Then subtract off the results for any ignored users.
        ignored_results = await self._main_store.get_threaded_messages_per_user(
            thread_event_ids, ignored_users
        )

        # A map of event ID to the thread aggregation.
        results = {}

        for event_id, summary in summaries.items():
            # If no thread, skip.
            if not summary:
                continue

            thread_count, latest_thread_event = summary

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

                # Attempt to find another event to use as the latest event.
                potential_events, _ = await self._main_store.get_relations_for_event(
                    event_id,
                    event,
                    room_id,
                    RelationTypes.THREAD,
                    direction=Direction.FORWARDS,
                )

                # Filter out ignored users.
                potential_events = [
                    event
                    for event in potential_events
                    if event.sender not in ignored_users
                ]

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
                count=thread_count,
                # If there's a thread summary it must also exist in the
                # participated dictionary.
                current_user_participated=events_by_id[event_id].sender == user_id
                or participated[event_id],
            )

        return results

    @trace
    async def get_bundled_aggregations(
        self, events: Iterable[EventBase], user_id: str
    ) -> Dict[str, BundledAggregations]:
        """Generate bundled aggregations for events.

        Args:
            events: The iterable of events to calculate bundled aggregations for.
            user_id: The user requesting the bundled aggregations.

        Returns:
            A map of event ID to the bundled aggregations for the event.

            Not all requested events may exist in the results (if they don't have
            bundled aggregations).

            The results may include additional events which are related to the
            requested events.
        """
        # De-duplicated events by ID to handle the same event requested multiple times.
        events_by_id = {}
        # A map of event ID to the relation in that event, if there is one.
        relations_by_id: Dict[str, str] = {}
        for event in events:
            # State events do not get bundled aggregations.
            if event.is_state():
                continue

            relates_to = relation_from_event(event)
            if relates_to:
                # An event which is a replacement (ie edit) or annotation (ie,
                # reaction) may not have any other event related to it.
                if relates_to.rel_type in (
                    RelationTypes.ANNOTATION,
                    RelationTypes.REPLACE,
                ):
                    continue

                # Track the event's relation information for later.
                relations_by_id[event.event_id] = relates_to.rel_type

            # The event should get bundled aggregations.
            events_by_id[event.event_id] = event

        # event ID -> bundled aggregation in non-serialized form.
        results: Dict[str, BundledAggregations] = {}

        # Fetch any ignored users of the requesting user.
        ignored_users = await self._main_store.ignored_users(user_id)

        # Threads are special as the latest event of a thread might cause additional
        # events to be fetched. Thus, we check those first!

        # Fetch thread summaries (but only for the directly requested events).
        threads = await self._get_threads_for_events(
            events_by_id,
            relations_by_id,
            user_id,
            ignored_users,
        )
        for event_id, thread in threads.items():
            results.setdefault(event_id, BundledAggregations()).thread = thread

            # If the latest event in a thread is not already being fetched,
            # add it. This ensures that the bundled aggregations for the
            # latest thread event is correct.
            latest_thread_event = thread.latest_event
            if latest_thread_event and latest_thread_event.event_id not in events_by_id:
                events_by_id[latest_thread_event.event_id] = latest_thread_event
                # Keep relations_by_id in sync with events_by_id:
                #
                # We know that the latest event in a thread has a thread relation
                # (as that is what makes it part of the thread).
                relations_by_id[latest_thread_event.event_id] = RelationTypes.THREAD

        async def _fetch_references() -> None:
            """Fetch any references to bundle with this event."""
            references_by_event_id = await self.get_references_for_events(
                events_by_id.keys(), ignored_users=ignored_users
            )
            for event_id, references in references_by_event_id.items():
                if references:
                    results.setdefault(event_id, BundledAggregations()).references = {
                        "chunk": [{"event_id": ev.event_id} for ev in references]
                    }

        async def _fetch_edits() -> None:
            """
            Fetch any edits (but not for redacted events).

            Note that there is no use in limiting edits by ignored users since the
            parent event should be ignored in the first place if the user is ignored.
            """
            edits = await self._main_store.get_applicable_edits(
                [
                    event_id
                    for event_id, event in events_by_id.items()
                    if not event.internal_metadata.is_redacted()
                ]
            )
            for event_id, edit in edits.items():
                results.setdefault(event_id, BundledAggregations()).replace = edit

        # Parallelize the calls for annotations, references, and edits since they
        # are unrelated.
        await make_deferred_yieldable(
            gather_results(
                (
                    run_in_background(_fetch_references),
                    run_in_background(_fetch_edits),
                )
            )
        )

        return results

    async def get_threads(
        self,
        requester: Requester,
        room_id: str,
        include: ThreadsListInclude,
        limit: int = 5,
        from_token: Optional[ThreadsNextBatch] = None,
    ) -> JsonDict:
        """Get related events of a event, ordered by topological ordering.

        Args:
            requester: The user requesting the relations.
            room_id: The room the event belongs to.
            include: One of "all" or "participated" to indicate which threads should
                be returned.
            limit: Only fetch the most recent `limit` events.
            from_token: Fetch rows from the given token, or from the start if None.

        Returns:
            The pagination chunk.
        """

        user_id = requester.user.to_string()

        # TODO Properly handle a user leaving a room.
        (_, member_event_id) = await self._auth.check_user_in_room_or_world_readable(
            room_id, requester, allow_departed_users=True
        )

        # Note that ignored users are not passed into get_threads
        # below. Ignored users are handled in filter_events_for_client (and by
        # not passing them in here we should get a better cache hit rate).
        thread_roots, next_batch = await self._main_store.get_threads(
            room_id=room_id, limit=limit, from_token=from_token
        )

        events = await self._main_store.get_events_as_list(thread_roots)

        if include == ThreadsListInclude.participated:
            # Pre-seed thread participation with whether the requester sent the event.
            participated = {event.event_id: event.sender == user_id for event in events}
            # For events the requester did not send, check the database for whether
            # the requester sent a threaded reply.
            participated.update(
                await self._main_store.get_threads_participated(
                    [eid for eid, p in participated.items() if not p],
                    user_id,
                )
            )

            # Limit the returned threads to those the user has participated in.
            events = [event for event in events if participated[event.event_id]]

        events = await filter_events_for_client(
            self._storage_controllers,
            user_id,
            events,
            is_peeking=(member_event_id is None),
        )

        aggregations = await self.get_bundled_aggregations(
            events, requester.user.to_string()
        )

        now = self._clock.time_msec()
        serialized_events = await self._event_serializer.serialize_events(
            events, now, bundle_aggregations=aggregations
        )

        return_value: JsonDict = {"chunk": serialized_events}

        if next_batch:
            return_value["next_batch"] = str(next_batch)

        return return_value
