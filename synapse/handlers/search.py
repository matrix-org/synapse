# Copyright 2015, 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Collection, Dict, Iterable, List, Optional, Set, Tuple

import attr
from unpaddedbase64 import decode_base64, encode_base64

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import NotFoundError, SynapseError
from synapse.api.filtering import Filter
from synapse.events import EventBase
from synapse.storage.state import StateFilter
from synapse.types import JsonDict, StreamKeyType, UserID
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _SearchResult:
    # The count of results.
    count: int
    # A mapping of event ID to the rank of that event.
    rank_map: Dict[str, int]
    # A list of the resulting events.
    allowed_events: List[EventBase]
    # A map of room ID to results.
    room_groups: Dict[str, JsonDict]
    # A set of event IDs to highlight.
    highlights: Set[str]


class SearchHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.state_handler = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.hs = hs
        self._event_serializer = hs.get_event_client_serializer()
        self._relations_handler = hs.get_relations_handler()
        self._storage_controllers = hs.get_storage_controllers()
        self._state_storage_controller = self._storage_controllers.state
        self.auth = hs.get_auth()

    async def get_old_rooms_from_upgraded_room(self, room_id: str) -> Iterable[str]:
        """Retrieves room IDs of old rooms in the history of an upgraded room.

        We do so by checking the m.room.create event of the room for a
        `predecessor` key. If it exists, we add the room ID to our return
        list and then check that room for a m.room.create event and so on
        until we can no longer find any more previous rooms.

        The full list of all found rooms in then returned.

        Args:
            room_id: id of the room to search through.

        Returns:
            Predecessor room ids
        """

        historical_room_ids = []

        # The initial room must have been known for us to get this far
        predecessor = await self.store.get_room_predecessor(room_id)

        while True:
            if not predecessor:
                # We have reached the end of the chain of predecessors
                break

            if not isinstance(predecessor.get("room_id"), str):
                # This predecessor object is malformed. Exit here
                break

            predecessor_room_id = predecessor["room_id"]

            # Don't add it to the list until we have checked that we are in the room
            try:
                next_predecessor_room = await self.store.get_room_predecessor(
                    predecessor_room_id
                )
            except NotFoundError:
                # The predecessor is not a known room, so we are done here
                break

            historical_room_ids.append(predecessor_room_id)

            # And repeat
            predecessor = next_predecessor_room

        return historical_room_ids

    async def search(
        self, user: UserID, content: JsonDict, batch: Optional[str] = None
    ) -> JsonDict:
        """Performs a full text search for a user.

        Args:
            user: The user performing the search.
            content: Search parameters
            batch: The next_batch parameter. Used for pagination.

        Returns:
            dict to be returned to the client with results of search
        """

        if not self.hs.config.server.enable_search:
            raise SynapseError(400, "Search is disabled on this homeserver")

        batch_group = None
        batch_group_key = None
        batch_token = None
        if batch:
            try:
                b = decode_base64(batch).decode("ascii")
                batch_group, batch_group_key, batch_token = b.split("\n")

                assert batch_group is not None
                assert batch_group_key is not None
                assert batch_token is not None
            except Exception:
                raise SynapseError(400, "Invalid batch")

        logger.info(
            "Search batch properties: %r, %r, %r",
            batch_group,
            batch_group_key,
            batch_token,
        )

        logger.info("Search content: %s", content)

        try:
            room_cat = content["search_categories"]["room_events"]

            # The actual thing to query in FTS
            search_term = room_cat["search_term"]

            # Which "keys" to search over in FTS query
            keys = room_cat.get(
                "keys", ["content.body", "content.name", "content.topic"]
            )

            # Filter to apply to results
            filter_dict = room_cat.get("filter", {})

            # What to order results by (impacts whether pagination can be done)
            order_by = room_cat.get("order_by", "rank")

            # Return the current state of the rooms?
            include_state = room_cat.get("include_state", False)

            # Include context around each event?
            event_context = room_cat.get("event_context", None)
            before_limit = after_limit = None
            include_profile = False

            # Group results together? May allow clients to paginate within a
            # group
            group_by = room_cat.get("groupings", {}).get("group_by", {})
            group_keys = [g["key"] for g in group_by]

            if event_context is not None:
                before_limit = int(event_context.get("before_limit", 5))
                after_limit = int(event_context.get("after_limit", 5))

                # Return the historic display name and avatar for the senders
                # of the events?
                include_profile = bool(event_context.get("include_profile", False))
        except KeyError:
            raise SynapseError(400, "Invalid search query")

        if order_by not in ("rank", "recent"):
            raise SynapseError(400, "Invalid order by: %r" % (order_by,))

        if set(group_keys) - {"room_id", "sender"}:
            raise SynapseError(
                400,
                "Invalid group by keys: %r"
                % (set(group_keys) - {"room_id", "sender"},),
            )

        return await self._search(
            user,
            batch_group,
            batch_group_key,
            batch_token,
            search_term,
            keys,
            filter_dict,
            order_by,
            include_state,
            group_keys,
            event_context,
            before_limit,
            after_limit,
            include_profile,
        )

    async def _search(
        self,
        user: UserID,
        batch_group: Optional[str],
        batch_group_key: Optional[str],
        batch_token: Optional[str],
        search_term: str,
        keys: List[str],
        filter_dict: JsonDict,
        order_by: str,
        include_state: bool,
        group_keys: List[str],
        event_context: Optional[bool],
        before_limit: Optional[int],
        after_limit: Optional[int],
        include_profile: bool,
    ) -> JsonDict:
        """Performs a full text search for a user.

        Args:
            user: The user performing the search.
            batch_group: Pagination information.
            batch_group_key: Pagination information.
            batch_token: Pagination information.
            search_term: Search term to search for
            keys: List of keys to search in, currently supports
                "content.body", "content.name", "content.topic"
            filter_dict: The JSON to build a filter out of.
            order_by: How to order the results. Valid values ore "rank" and "recent".
            include_state: True if the state of the room at each result should
                be included.
            group_keys: A list of ways to group the results. Valid values are
                "room_id" and "sender".
            event_context: True to include contextual events around results.
            before_limit:
                The number of events before a result to include as context.

                Only used if event_context is True.
            after_limit:
                The number of events after a result to include as context.

                Only used if event_context is True.
            include_profile: True if historical profile information should be
                included in the event context.

                Only used if event_context is True.

        Returns:
            dict to be returned to the client with results of search
        """
        search_filter = Filter(self.hs, filter_dict)

        # TODO: Search through left rooms too
        rooms = await self.store.get_rooms_for_local_user_where_membership_is(
            user.to_string(),
            membership_list=[Membership.JOIN],
            # membership_list=[Membership.JOIN, Membership.LEAVE, Membership.Ban],
        )
        room_ids = {r.room_id for r in rooms}

        # If doing a subset of all rooms seearch, check if any of the rooms
        # are from an upgraded room, and search their contents as well
        if search_filter.rooms:
            historical_room_ids: List[str] = []
            for room_id in search_filter.rooms:
                # Add any previous rooms to the search if they exist
                ids = await self.get_old_rooms_from_upgraded_room(room_id)
                historical_room_ids += ids

            # Prevent any historical events from being filtered
            search_filter = search_filter.with_room_ids(historical_room_ids)

        room_ids = search_filter.filter_rooms(room_ids)

        if batch_group == "room_id":
            room_ids.intersection_update({batch_group_key})

        if not room_ids:
            return {
                "search_categories": {
                    "room_events": {"results": [], "count": 0, "highlights": []}
                }
            }

        sender_group: Optional[Dict[str, JsonDict]]

        if order_by == "rank":
            search_result, sender_group = await self._search_by_rank(
                user, room_ids, search_term, keys, search_filter
            )
            # Unused return values for rank search.
            global_next_batch = None
        elif order_by == "recent":
            search_result, global_next_batch = await self._search_by_recent(
                user,
                room_ids,
                search_term,
                keys,
                search_filter,
                batch_group,
                batch_group_key,
                batch_token,
            )
            # Unused return values for recent search.
            sender_group = None
        else:
            # We should never get here due to the guard earlier.
            raise NotImplementedError()

        logger.info("Found %d events to return", len(search_result.allowed_events))

        # If client has asked for "context" for each event (i.e. some surrounding
        # events and state), fetch that
        if event_context is not None:
            # Note that before and after limit must be set in this case.
            assert before_limit is not None
            assert after_limit is not None

            contexts = await self._calculate_event_contexts(
                user,
                search_result.allowed_events,
                before_limit,
                after_limit,
                include_profile,
            )
        else:
            contexts = {}

        # TODO: Add a limit

        state_results = {}
        if include_state:
            for room_id in {e.room_id for e in search_result.allowed_events}:
                state = await self._storage_controllers.state.get_current_state(room_id)
                state_results[room_id] = list(state.values())

        aggregations = await self._relations_handler.get_bundled_aggregations(
            # Generate an iterable of EventBase for all the events that will be
            # returned, including contextual events.
            itertools.chain(
                # The events_before and events_after for each context.
                itertools.chain.from_iterable(
                    itertools.chain(context["events_before"], context["events_after"])
                    for context in contexts.values()
                ),
                # The returned events.
                search_result.allowed_events,
            ),
            user.to_string(),
        )

        # We're now about to serialize the events. We should not make any
        # blocking calls after this. Otherwise, the 'age' will be wrong.

        time_now = self.clock.time_msec()

        for context in contexts.values():
            context["events_before"] = self._event_serializer.serialize_events(
                context["events_before"], time_now, bundle_aggregations=aggregations
            )
            context["events_after"] = self._event_serializer.serialize_events(
                context["events_after"], time_now, bundle_aggregations=aggregations
            )

        results = [
            {
                "rank": search_result.rank_map[e.event_id],
                "result": self._event_serializer.serialize_event(
                    e, time_now, bundle_aggregations=aggregations
                ),
                "context": contexts.get(e.event_id, {}),
            }
            for e in search_result.allowed_events
        ]

        rooms_cat_res: JsonDict = {
            "results": results,
            "count": search_result.count,
            "highlights": list(search_result.highlights),
        }

        if state_results:
            rooms_cat_res["state"] = {
                room_id: self._event_serializer.serialize_events(state_events, time_now)
                for room_id, state_events in state_results.items()
            }

        if search_result.room_groups and "room_id" in group_keys:
            rooms_cat_res.setdefault("groups", {})[
                "room_id"
            ] = search_result.room_groups

        if sender_group and "sender" in group_keys:
            rooms_cat_res.setdefault("groups", {})["sender"] = sender_group

        if global_next_batch:
            rooms_cat_res["next_batch"] = global_next_batch

        return {"search_categories": {"room_events": rooms_cat_res}}

    async def _search_by_rank(
        self,
        user: UserID,
        room_ids: Collection[str],
        search_term: str,
        keys: Iterable[str],
        search_filter: Filter,
    ) -> Tuple[_SearchResult, Dict[str, JsonDict]]:
        """
        Performs a full text search for a user ordering by rank.

        Args:
            user: The user performing the search.
            room_ids: List of room ids to search in
            search_term: Search term to search for
            keys: List of keys to search in, currently supports
                "content.body", "content.name", "content.topic"
            search_filter: The event filter to use.

        Returns:
            A tuple of:
                The search results.
                A map of sender ID to results.
        """
        rank_map = {}  # event_id -> rank of event
        # Holds result of grouping by room, if applicable
        room_groups: Dict[str, JsonDict] = {}
        # Holds result of grouping by sender, if applicable
        sender_group: Dict[str, JsonDict] = {}

        search_result = await self.store.search_msgs(room_ids, search_term, keys)

        if search_result["highlights"]:
            highlights = search_result["highlights"]
        else:
            highlights = set()

        results = search_result["results"]

        # event_id -> rank of event
        rank_map = {r["event"].event_id: r["rank"] for r in results}

        filtered_events = await search_filter.filter([r["event"] for r in results])

        events = await filter_events_for_client(
            self._storage_controllers, user.to_string(), filtered_events
        )

        events.sort(key=lambda e: -rank_map[e.event_id])
        allowed_events = events[: search_filter.limit]

        for e in allowed_events:
            rm = room_groups.setdefault(
                e.room_id, {"results": [], "order": rank_map[e.event_id]}
            )
            rm["results"].append(e.event_id)

            s = sender_group.setdefault(
                e.sender, {"results": [], "order": rank_map[e.event_id]}
            )
            s["results"].append(e.event_id)

        return (
            _SearchResult(
                search_result["count"],
                rank_map,
                allowed_events,
                room_groups,
                highlights,
            ),
            sender_group,
        )

    async def _search_by_recent(
        self,
        user: UserID,
        room_ids: Collection[str],
        search_term: str,
        keys: Iterable[str],
        search_filter: Filter,
        batch_group: Optional[str],
        batch_group_key: Optional[str],
        batch_token: Optional[str],
    ) -> Tuple[_SearchResult, Optional[str]]:
        """
        Performs a full text search for a user ordering by recent.

        Args:
            user: The user performing the search.
            room_ids: List of room ids to search in
            search_term: Search term to search for
            keys: List of keys to search in, currently supports
                "content.body", "content.name", "content.topic"
            search_filter: The event filter to use.
            batch_group: Pagination information.
            batch_group_key: Pagination information.
            batch_token: Pagination information.

        Returns:
            A tuple of:
                The search results.
                Optionally, a pagination token.
        """
        rank_map = {}  # event_id -> rank of event
        # Holds result of grouping by room, if applicable
        room_groups: Dict[str, JsonDict] = {}

        # Holds the next_batch for the entire result set if one of those exists
        global_next_batch = None

        highlights = set()

        room_events: List[EventBase] = []
        i = 0

        pagination_token = batch_token

        # We keep looping and we keep filtering until we reach the limit
        # or we run out of things.
        # But only go around 5 times since otherwise synapse will be sad.
        while len(room_events) < search_filter.limit and i < 5:
            i += 1
            search_result = await self.store.search_rooms(
                room_ids,
                search_term,
                keys,
                search_filter.limit * 2,
                pagination_token=pagination_token,
            )

            if search_result["highlights"]:
                highlights.update(search_result["highlights"])

            count = search_result["count"]

            results = search_result["results"]

            results_map = {r["event"].event_id: r for r in results}

            rank_map.update({r["event"].event_id: r["rank"] for r in results})

            filtered_events = await search_filter.filter([r["event"] for r in results])

            events = await filter_events_for_client(
                self._storage_controllers, user.to_string(), filtered_events
            )

            room_events.extend(events)
            room_events = room_events[: search_filter.limit]

            if len(results) < search_filter.limit * 2:
                break
            else:
                pagination_token = results[-1]["pagination_token"]

        for event in room_events:
            group = room_groups.setdefault(event.room_id, {"results": []})
            group["results"].append(event.event_id)

        if room_events and len(room_events) >= search_filter.limit:
            last_event_id = room_events[-1].event_id
            pagination_token = results_map[last_event_id]["pagination_token"]

            # We want to respect the given batch group and group keys so
            # that if people blindly use the top level `next_batch` token
            # it returns more from the same group (if applicable) rather
            # than reverting to searching all results again.
            if batch_group and batch_group_key:
                global_next_batch = encode_base64(
                    (
                        "%s\n%s\n%s" % (batch_group, batch_group_key, pagination_token)
                    ).encode("ascii")
                )
            else:
                global_next_batch = encode_base64(
                    ("%s\n%s\n%s" % ("all", "", pagination_token)).encode("ascii")
                )

            for room_id, group in room_groups.items():
                group["next_batch"] = encode_base64(
                    ("%s\n%s\n%s" % ("room_id", room_id, pagination_token)).encode(
                        "ascii"
                    )
                )

        return (
            _SearchResult(count, rank_map, room_events, room_groups, highlights),
            global_next_batch,
        )

    async def _calculate_event_contexts(
        self,
        user: UserID,
        allowed_events: List[EventBase],
        before_limit: int,
        after_limit: int,
        include_profile: bool,
    ) -> Dict[str, JsonDict]:
        """
        Calculates the contextual events for any search results.

        Args:
            user: The user performing the search.
            allowed_events: The search results.
            before_limit:
                The number of events before a result to include as context.
            after_limit:
                The number of events after a result to include as context.
            include_profile: True if historical profile information should be
                included in the event context.

        Returns:
            A map of event ID to contextual information.
        """
        now_token = self.hs.get_event_sources().get_current_token()

        contexts = {}
        for event in allowed_events:
            res = await self.store.get_events_around(
                event.room_id, event.event_id, before_limit, after_limit
            )

            logger.info(
                "Context for search returned %d and %d events",
                len(res.events_before),
                len(res.events_after),
            )

            events_before = await filter_events_for_client(
                self._storage_controllers, user.to_string(), res.events_before
            )

            events_after = await filter_events_for_client(
                self._storage_controllers, user.to_string(), res.events_after
            )

            context: JsonDict = {
                "events_before": events_before,
                "events_after": events_after,
                "start": await now_token.copy_and_replace(
                    StreamKeyType.ROOM, res.start
                ).to_string(self.store),
                "end": await now_token.copy_and_replace(
                    StreamKeyType.ROOM, res.end
                ).to_string(self.store),
            }

            if include_profile:
                senders = {
                    ev.sender
                    for ev in itertools.chain(events_before, [event], events_after)
                }

                if events_after:
                    last_event_id = events_after[-1].event_id
                else:
                    last_event_id = event.event_id

                state_filter = StateFilter.from_types(
                    [(EventTypes.Member, sender) for sender in senders]
                )

                state = await self._state_storage_controller.get_state_for_event(
                    last_event_id, state_filter
                )

                context["profile_info"] = {
                    s.state_key: {
                        "displayname": s.content.get("displayname", None),
                        "avatar_url": s.content.get("avatar_url", None),
                    }
                    for s in state.values()
                    if s.type == EventTypes.Member and s.state_key in senders
                }

            contexts[event.event_id] = context

        return contexts
