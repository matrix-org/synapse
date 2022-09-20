# Copyright 2018 New Vector Ltd
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

import heapq
import itertools
import logging
from typing import (
    Any,
    Awaitable,
    Callable,
    Collection,
    Dict,
    Generator,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    overload,
)

from typing_extensions import Literal, Protocol

from synapse import event_auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError
from synapse.api.room_versions import RoomVersion
from synapse.events import EventBase
from synapse.types import MutableStateMap, StateMap

logger = logging.getLogger(__name__)


class Clock(Protocol):
    # This is usually synapse.util.Clock, but it's replaced with a FakeClock in tests.
    # We only ever sleep(0) though, so that other async functions can make forward
    # progress without waiting for stateres to complete.
    def sleep(self, duration_ms: float) -> Awaitable[None]:
        ...


class StateResolutionStore(Protocol):
    # This is usually synapse.state.StateResolutionStore, but it's replaced with a
    # TestStateResolutionStore in tests.
    def get_events(
        self, event_ids: Collection[str], allow_rejected: bool = False
    ) -> Awaitable[Dict[str, EventBase]]:
        ...

    def get_auth_chain_difference(
        self, room_id: str, state_sets: List[Set[str]]
    ) -> Awaitable[Set[str]]:
        ...


# We want to await to the reactor occasionally during state res when dealing
# with large data sets, so that we don't exhaust the reactor. This is done by
# awaiting to reactor during loops every N iterations.
_AWAIT_AFTER_ITERATIONS = 100


__all__ = [
    "resolve_events_with_store",
]


async def resolve_events_with_store(
    clock: Clock,
    room_id: str,
    room_version: RoomVersion,
    state_sets: Sequence[StateMap[str]],
    event_map: Optional[Dict[str, EventBase]],
    state_res_store: StateResolutionStore,
) -> StateMap[str]:
    """Resolves the state using the v2 state resolution algorithm

    Args:
        clock
        room_id: the room we are working in
        room_version: The room version
        state_sets: List of dicts of (type, state_key) -> event_id,
            which are the different state groups to resolve.
        event_map:
            a dict from event_id to event, for any events that we happen to
            have in flight (eg, those currently being persisted). This will be
            used as a starting point for finding the state we need; any missing
            events will be requested via state_res_store.

            If None, all events will be fetched via state_res_store.

        state_res_store:

    Returns:
        A map from (type, state_key) to event_id.
    """

    logger.debug("Computing conflicted state")

    # We use event_map as a cache, so if its None we need to initialize it
    if event_map is None:
        event_map = {}

    # First split up the un/conflicted state
    unconflicted_state, conflicted_state = _seperate(state_sets)

    if not conflicted_state:
        return unconflicted_state

    logger.debug("%d conflicted state entries", len(conflicted_state))
    logger.debug("Calculating auth chain difference")

    # Also fetch all auth events that appear in only some of the state sets'
    # auth chains.
    auth_diff = await _get_auth_chain_difference(
        room_id, state_sets, event_map, state_res_store
    )

    full_conflicted_set = set(
        itertools.chain(
            itertools.chain.from_iterable(conflicted_state.values()), auth_diff
        )
    )

    events = await state_res_store.get_events(
        [eid for eid in full_conflicted_set if eid not in event_map],
        allow_rejected=True,
    )
    event_map.update(events)

    # everything in the event map should be in the right room
    for event in event_map.values():
        if event.room_id != room_id:
            raise Exception(
                "Attempting to state-resolve for room %s with event %s which is in %s"
                % (
                    room_id,
                    event.event_id,
                    event.room_id,
                )
            )

    full_conflicted_set = {eid for eid in full_conflicted_set if eid in event_map}

    logger.debug("%d full_conflicted_set entries", len(full_conflicted_set))

    # Get and sort all the power events (kicks/bans/etc)
    power_events = (
        eid for eid in full_conflicted_set if _is_power_event(event_map[eid])
    )

    sorted_power_events = await _reverse_topological_power_sort(
        clock, room_id, power_events, event_map, state_res_store, full_conflicted_set
    )

    logger.debug("sorted %d power events", len(sorted_power_events))

    # Now sequentially auth each one
    resolved_state = await _iterative_auth_checks(
        clock,
        room_id,
        room_version,
        sorted_power_events,
        unconflicted_state,
        event_map,
        state_res_store,
    )

    logger.debug("resolved power events")

    # OK, so we've now resolved the power events. Now sort the remaining
    # events using the mainline of the resolved power level.

    set_power_events = set(sorted_power_events)
    leftover_events = [
        ev_id for ev_id in full_conflicted_set if ev_id not in set_power_events
    ]

    logger.debug("sorting %d remaining events", len(leftover_events))

    pl = resolved_state.get((EventTypes.PowerLevels, ""), None)
    leftover_events = await _mainline_sort(
        clock, room_id, leftover_events, pl, event_map, state_res_store
    )

    logger.debug("resolving remaining events")

    resolved_state = await _iterative_auth_checks(
        clock,
        room_id,
        room_version,
        leftover_events,
        resolved_state,
        event_map,
        state_res_store,
    )

    logger.debug("resolved")

    # We make sure that unconflicted state always still applies.
    resolved_state.update(unconflicted_state)

    logger.debug("done")

    return resolved_state


async def _get_power_level_for_sender(
    room_id: str,
    event_id: str,
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
) -> int:
    """Return the power level of the sender of the given event according to
    their auth events.

    Args:
        room_id
        event_id
        event_map
        state_res_store

    Returns:
        The power level.
    """
    event = await _get_event(room_id, event_id, event_map, state_res_store)

    pl = None
    for aid in event.auth_event_ids():
        aev = await _get_event(
            room_id, aid, event_map, state_res_store, allow_none=True
        )
        if aev and (aev.type, aev.state_key) == (EventTypes.PowerLevels, ""):
            pl = aev
            break

    if pl is None:
        # Couldn't find power level. Check if they're the creator of the room
        for aid in event.auth_event_ids():
            aev = await _get_event(
                room_id, aid, event_map, state_res_store, allow_none=True
            )
            if aev and (aev.type, aev.state_key) == (EventTypes.Create, ""):
                if aev.content.get("creator") == event.sender:
                    return 100
                break
        return 0

    level = pl.content.get("users", {}).get(event.sender)
    if level is None:
        level = pl.content.get("users_default", 0)

    if level is None:
        return 0
    else:
        return int(level)


async def _get_auth_chain_difference(
    room_id: str,
    state_sets: Sequence[Mapping[Any, str]],
    unpersisted_events: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
) -> Set[str]:
    """Compare the auth chains of each state set and return the set of events
    that only appear in some, but not all of the auth chains.

    Args:
        state_sets: The input state sets we are trying to resolve across.
        unpersisted_events: A map from event ID to EventBase containing all unpersisted
            events involved in this resolution.
        state_res_store:

    Returns:
        The auth difference of the given state sets, as a set of event IDs.
    """

    # The `StateResolutionStore.get_auth_chain_difference` function assumes that
    # all events passed to it (and their auth chains) have been persisted
    # previously. We need to manually handle any other events that are yet to be
    # persisted.
    #
    # We do this in three steps:
    #   1. Compute the set of unpersisted events belonging to the auth difference.
    #   2. Replacing any unpersisted events in the state_sets with their auth events,
    #      recursively, until the state_sets contain only persisted events.
    #      Then we call `store.get_auth_chain_difference` as normal, which computes
    #      the set of persisted events belonging to the auth difference.
    #   3. Adding the results of 1 and 2 together.

    # Map from event ID in `unpersisted_events` to their auth event IDs, and their auth
    # event IDs if they appear in the `unpersisted_events`. This is the intersection of
    # the event's auth chain with the events in `unpersisted_events` *plus* their
    # auth event IDs.
    events_to_auth_chain: Dict[str, Set[str]] = {}
    for event in unpersisted_events.values():
        chain = {event.event_id}
        events_to_auth_chain[event.event_id] = chain

        to_search = [event]
        while to_search:
            for auth_id in to_search.pop().auth_event_ids():
                chain.add(auth_id)
                auth_event = unpersisted_events.get(auth_id)
                if auth_event:
                    to_search.append(auth_event)

    # We now 1) calculate the auth chain difference for the unpersisted events
    # and 2) work out the state sets to pass to the store.
    #
    # Note: If there are no `unpersisted_events` (which is the common case), we can do a
    # much simpler calculation.
    if unpersisted_events:
        # The list of state sets to pass to the store, where each state set is a set
        # of the event ids making up the state. This is similar to `state_sets`,
        # except that (a) we only have event ids, not the complete
        # ((type, state_key)->event_id) mappings; and (b) we have stripped out
        # unpersisted events and replaced them with the persisted events in
        # their auth chain.
        state_sets_ids: List[Set[str]] = []

        # For each state set, the unpersisted event IDs reachable (by their auth
        # chain) from the events in that set.
        unpersisted_set_ids: List[Set[str]] = []

        for state_set in state_sets:
            set_ids: Set[str] = set()
            state_sets_ids.append(set_ids)

            unpersisted_ids: Set[str] = set()
            unpersisted_set_ids.append(unpersisted_ids)

            for event_id in state_set.values():
                event_chain = events_to_auth_chain.get(event_id)
                if event_chain is not None:
                    # We have an unpersisted event. We add all the auth
                    # events that it references which are also unpersisted.
                    set_ids.update(
                        e for e in event_chain if e not in unpersisted_events
                    )

                    # We also add the full chain of unpersisted event IDs
                    # referenced by this state set, so that we can work out the
                    # auth chain difference of the unpersisted events.
                    unpersisted_ids.update(
                        e for e in event_chain if e in unpersisted_events
                    )
                else:
                    set_ids.add(event_id)

        # The auth chain difference of the unpersisted events of the state sets
        # is calculated by taking the difference between the union and
        # intersections.
        union = unpersisted_set_ids[0].union(*unpersisted_set_ids[1:])
        intersection = unpersisted_set_ids[0].intersection(*unpersisted_set_ids[1:])

        auth_difference_unpersisted_part: Collection[str] = union - intersection
    else:
        auth_difference_unpersisted_part = ()
        state_sets_ids = [set(state_set.values()) for state_set in state_sets]

    difference = await state_res_store.get_auth_chain_difference(
        room_id, state_sets_ids
    )
    difference.update(auth_difference_unpersisted_part)

    return difference


def _seperate(
    state_sets: Iterable[StateMap[str]],
) -> Tuple[StateMap[str], StateMap[Set[str]]]:
    """Return the unconflicted and conflicted state. This is different than in
    the original algorithm, as this defines a key to be conflicted if one of
    the state sets doesn't have that key.

    Args:
        state_sets

    Returns:
        A tuple of unconflicted and conflicted state. The conflicted state dict
        is a map from type/state_key to set of event IDs
    """
    unconflicted_state = {}
    conflicted_state = {}

    for key in set(itertools.chain.from_iterable(state_sets)):
        event_ids = {state_set.get(key) for state_set in state_sets}
        if len(event_ids) == 1:
            unconflicted_state[key] = event_ids.pop()
        else:
            event_ids.discard(None)
            conflicted_state[key] = event_ids

    # mypy doesn't understand that discarding None above means that conflicted
    # state is StateMap[Set[str]], not StateMap[Set[Optional[Str]]].
    return unconflicted_state, conflicted_state  # type: ignore


def _is_power_event(event: EventBase) -> bool:
    """Return whether or not the event is a "power event", as defined by the
    v2 state resolution algorithm

    Args:
        event

    Returns:
        True if the event is a power event.
    """
    if (event.type, event.state_key) in (
        (EventTypes.PowerLevels, ""),
        (EventTypes.JoinRules, ""),
        (EventTypes.Create, ""),
    ):
        return True

    if event.type == EventTypes.Member:
        if event.membership in ("leave", "ban"):
            return event.sender != event.state_key

    return False


async def _add_event_and_auth_chain_to_graph(
    graph: Dict[str, Set[str]],
    room_id: str,
    event_id: str,
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
    full_conflicted_set: Set[str],
) -> None:
    """Helper function for _reverse_topological_power_sort that add the event
    and its auth chain (that is in the auth diff) to the graph

    Args:
        graph: A map from event ID to the events auth event IDs
        room_id: the room we are working in
        event_id: Event to add to the graph
        event_map
        state_res_store
        full_conflicted_set: Set of event IDs that are in the full conflicted set.
    """

    state = [event_id]
    while state:
        eid = state.pop()
        graph.setdefault(eid, set())

        event = await _get_event(room_id, eid, event_map, state_res_store)
        for aid in event.auth_event_ids():
            if aid in full_conflicted_set:
                if aid not in graph:
                    state.append(aid)

                graph.setdefault(eid, set()).add(aid)


async def _reverse_topological_power_sort(
    clock: Clock,
    room_id: str,
    event_ids: Iterable[str],
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
    full_conflicted_set: Set[str],
) -> List[str]:
    """Returns a list of the event_ids sorted by reverse topological ordering,
    and then by power level and origin_server_ts

    Args:
        clock
        room_id: the room we are working in
        event_ids: The events to sort
        event_map
        state_res_store
        full_conflicted_set: Set of event IDs that are in the full conflicted set.

    Returns:
        The sorted list
    """

    graph: Dict[str, Set[str]] = {}
    for idx, event_id in enumerate(event_ids, start=1):
        await _add_event_and_auth_chain_to_graph(
            graph, room_id, event_id, event_map, state_res_store, full_conflicted_set
        )

        # We await occasionally when we're working with large data sets to
        # ensure that we don't block the reactor loop for too long.
        if idx % _AWAIT_AFTER_ITERATIONS == 0:
            await clock.sleep(0)

    event_to_pl = {}
    for idx, event_id in enumerate(graph, start=1):
        pl = await _get_power_level_for_sender(
            room_id, event_id, event_map, state_res_store
        )
        event_to_pl[event_id] = pl

        # We await occasionally when we're working with large data sets to
        # ensure that we don't block the reactor loop for too long.
        if idx % _AWAIT_AFTER_ITERATIONS == 0:
            await clock.sleep(0)

    def _get_power_order(event_id: str) -> Tuple[int, int, str]:
        ev = event_map[event_id]
        pl = event_to_pl[event_id]

        return -pl, ev.origin_server_ts, event_id

    # Note: graph is modified during the sort
    it = lexicographical_topological_sort(graph, key=_get_power_order)
    sorted_events = list(it)

    return sorted_events


async def _iterative_auth_checks(
    clock: Clock,
    room_id: str,
    room_version: RoomVersion,
    event_ids: List[str],
    base_state: StateMap[str],
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
) -> MutableStateMap[str]:
    """Sequentially apply auth checks to each event in given list, updating the
    state as it goes along.

    Args:
        clock
        room_id
        room_version
        event_ids: Ordered list of events to apply auth checks to
        base_state: The set of state to start with
        event_map
        state_res_store

    Returns:
        Returns the final updated state
    """
    resolved_state = dict(base_state)

    for idx, event_id in enumerate(event_ids, start=1):
        event = event_map[event_id]

        auth_events = {}
        for aid in event.auth_event_ids():
            ev = await _get_event(
                room_id, aid, event_map, state_res_store, allow_none=True
            )

            if not ev:
                logger.warning(
                    "auth_event id %s for event %s is missing", aid, event_id
                )
            else:
                if ev.rejected_reason is None:
                    auth_events[(ev.type, ev.state_key)] = ev

        for key in event_auth.auth_types_for_event(room_version, event):
            if key in resolved_state:
                ev_id = resolved_state[key]
                ev = await _get_event(room_id, ev_id, event_map, state_res_store)

                if ev.rejected_reason is None:
                    auth_events[key] = event_map[ev_id]

        if event.rejected_reason is not None:
            # Do not admit previously rejected events into state.
            # TODO: This isn't spec compliant. Events that were previously rejected due
            #       to failing auth checks at their state, but pass auth checks during
            #       state resolution should be accepted. Synapse does not handle the
            #       change of rejection status well, so we preserve the previous
            #       rejection status for now.
            #
            #       Note that events rejected for non-state reasons, such as having the
            #       wrong auth events, should remain rejected.
            #
            #       https://spec.matrix.org/v1.2/rooms/v9/#rejected-events
            #       https://github.com/matrix-org/synapse/issues/13797
            continue

        try:
            event_auth.check_state_dependent_auth_rules(
                event,
                auth_events.values(),
            )

            resolved_state[(event.type, event.state_key)] = event_id
        except AuthError:
            pass

        # We await occasionally when we're working with large data sets to
        # ensure that we don't block the reactor loop for too long.
        if idx % _AWAIT_AFTER_ITERATIONS == 0:
            await clock.sleep(0)

    return resolved_state


async def _mainline_sort(
    clock: Clock,
    room_id: str,
    event_ids: List[str],
    resolved_power_event_id: Optional[str],
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
) -> List[str]:
    """Returns a sorted list of event_ids sorted by mainline ordering based on
    the given event resolved_power_event_id

    Args:
        clock
        room_id: room we're working in
        event_ids: Events to sort
        resolved_power_event_id: The final resolved power level event ID
        event_map
        state_res_store

    Returns:
        The sorted list
    """
    if not event_ids:
        # It's possible for there to be no event IDs here to sort, so we can
        # skip calculating the mainline in that case.
        return []

    mainline = []
    pl = resolved_power_event_id
    idx = 0
    while pl:
        mainline.append(pl)
        pl_ev = await _get_event(room_id, pl, event_map, state_res_store)
        auth_events = pl_ev.auth_event_ids()
        pl = None
        for aid in auth_events:
            ev = await _get_event(
                room_id, aid, event_map, state_res_store, allow_none=True
            )
            if ev and (ev.type, ev.state_key) == (EventTypes.PowerLevels, ""):
                pl = aid
                break

        # We await occasionally when we're working with large data sets to
        # ensure that we don't block the reactor loop for too long.
        if idx != 0 and idx % _AWAIT_AFTER_ITERATIONS == 0:
            await clock.sleep(0)

        idx += 1

    mainline_map = {ev_id: i + 1 for i, ev_id in enumerate(reversed(mainline))}

    event_ids = list(event_ids)

    order_map = {}
    for idx, ev_id in enumerate(event_ids, start=1):
        depth = await _get_mainline_depth_for_event(
            event_map[ev_id], mainline_map, event_map, state_res_store
        )
        order_map[ev_id] = (depth, event_map[ev_id].origin_server_ts, ev_id)

        # We await occasionally when we're working with large data sets to
        # ensure that we don't block the reactor loop for too long.
        if idx % _AWAIT_AFTER_ITERATIONS == 0:
            await clock.sleep(0)

    event_ids.sort(key=lambda ev_id: order_map[ev_id])

    return event_ids


async def _get_mainline_depth_for_event(
    event: EventBase,
    mainline_map: Dict[str, int],
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
) -> int:
    """Get the mainline depths for the given event based on the mainline map

    Args:
        event
        mainline_map: Map from event_id to mainline depth for events in the mainline.
        event_map
        state_res_store

    Returns:
        The mainline depth
    """

    room_id = event.room_id
    tmp_event: Optional[EventBase] = event

    # We do an iterative search, replacing `event with the power level in its
    # auth events (if any)
    while tmp_event:
        depth = mainline_map.get(tmp_event.event_id)
        if depth is not None:
            return depth

        auth_events = tmp_event.auth_event_ids()
        tmp_event = None

        for aid in auth_events:
            aev = await _get_event(
                room_id, aid, event_map, state_res_store, allow_none=True
            )
            if aev and (aev.type, aev.state_key) == (EventTypes.PowerLevels, ""):
                tmp_event = aev
                break

    # Didn't find a power level auth event, so we just return 0
    return 0


@overload
async def _get_event(
    room_id: str,
    event_id: str,
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
    allow_none: Literal[False] = False,
) -> EventBase:
    ...


@overload
async def _get_event(
    room_id: str,
    event_id: str,
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
    allow_none: Literal[True],
) -> Optional[EventBase]:
    ...


async def _get_event(
    room_id: str,
    event_id: str,
    event_map: Dict[str, EventBase],
    state_res_store: StateResolutionStore,
    allow_none: bool = False,
) -> Optional[EventBase]:
    """Helper function to look up event in event_map, falling back to looking
    it up in the store

    Args:
        room_id
        event_id
        event_map
        state_res_store
        allow_none: if the event is not found, return None rather than raising
            an exception

    Returns:
        The event, or none if the event does not exist (and allow_none is True).
    """
    if event_id not in event_map:
        events = await state_res_store.get_events([event_id], allow_rejected=True)
        event_map.update(events)
    event = event_map.get(event_id)

    if event is None:
        if allow_none:
            return None
        raise Exception("Unknown event %s" % (event_id,))

    if event.room_id != room_id:
        raise Exception(
            "In state res for room %s, event %s is in %s"
            % (room_id, event_id, event.room_id)
        )
    return event


def lexicographical_topological_sort(
    graph: Dict[str, Set[str]], key: Callable[[str], Any]
) -> Generator[str, None, None]:
    """Performs a lexicographic reverse topological sort on the graph.

    This returns a reverse topological sort (i.e. if node A references B then B
    appears before A in the sort), with ties broken lexicographically based on
    return value of the `key` function.

    NOTE: `graph` is modified during the sort.

    Args:
        graph: A representation of the graph where each node is a key in the
            dict and its value are the nodes edges.
        key: A function that takes a node and returns a value that is comparable
            and used to order nodes

    Yields:
        The next node in the topological sort
    """

    # Note, this is basically Kahn's algorithm except we look at nodes with no
    # outgoing edges, c.f.
    # https://en.wikipedia.org/wiki/Topological_sorting#Kahn's_algorithm
    outdegree_map = graph
    reverse_graph: Dict[str, Set[str]] = {}

    # Lists of nodes with zero out degree. Is actually a tuple of
    # `(key(node), node)` so that sorting does the right thing
    zero_outdegree = []

    for node, edges in graph.items():
        if len(edges) == 0:
            zero_outdegree.append((key(node), node))

        reverse_graph.setdefault(node, set())
        for edge in edges:
            reverse_graph.setdefault(edge, set()).add(node)

    # heapq is a built in implementation of a sorted queue.
    heapq.heapify(zero_outdegree)

    while zero_outdegree:
        _, node = heapq.heappop(zero_outdegree)

        for parent in reverse_graph[node]:
            out = outdegree_map[parent]
            out.discard(node)
            if len(out) == 0:
                heapq.heappush(zero_outdegree, (key(parent), parent))

        yield node
