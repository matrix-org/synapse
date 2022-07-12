# Copyright 2014-2016 OpenMarket Ltd
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
import logging
from collections import defaultdict
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Collection,
    DefaultDict,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

import attr
from frozendict import frozendict
from prometheus_client import Counter, Histogram

from synapse.api.constants import EventTypes
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, StateResolutionVersions
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.logging.context import ContextResourceUsage
from synapse.replication.http.state import ReplicationUpdateCurrentStateRestServlet
from synapse.state import v1, v2
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.storage.roommember import ProfileInfo
from synapse.types import StateMap
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import Measure, measure_func

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore

logger = logging.getLogger(__name__)
metrics_logger = logging.getLogger("synapse.state.metrics")

# Metrics for number of state groups involved in a resolution.
state_groups_histogram = Histogram(
    "synapse_state_number_state_groups_in_resolution",
    "Number of state groups used when performing a state resolution",
    buckets=(1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"),
)


EVICTION_TIMEOUT_SECONDS = 60 * 60


_NEXT_STATE_ID = 1

POWER_KEY = (EventTypes.PowerLevels, "")


def _gen_state_id() -> str:
    global _NEXT_STATE_ID
    s = "X%d" % (_NEXT_STATE_ID,)
    _NEXT_STATE_ID += 1
    return s


class _StateCacheEntry:
    __slots__ = ["state", "state_group", "state_id", "prev_group", "delta_ids"]

    def __init__(
        self,
        state: StateMap[str],
        state_group: Optional[int],
        prev_group: Optional[int] = None,
        delta_ids: Optional[StateMap[str]] = None,
    ):
        # A map from (type, state_key) to event_id.
        self.state = frozendict(state)

        # the ID of a state group if one and only one is involved.
        # otherwise, None otherwise?
        self.state_group = state_group

        self.prev_group = prev_group
        self.delta_ids = frozendict(delta_ids) if delta_ids is not None else None

        # The `state_id` is a unique ID we generate that can be used as ID for
        # this collection of state. Usually this would be the same as the
        # state group, but on worker instances we can't generate a new state
        # group each time we resolve state, so we generate a separate one that
        # isn't persisted and is used solely for caches.
        # `state_id` is either a state_group (and so an int) or a string. This
        # ensures we don't accidentally persist a state_id as a stateg_group
        if state_group:
            self.state_id: Union[str, int] = state_group
        else:
            self.state_id = _gen_state_id()

    def __len__(self) -> int:
        return len(self.state)


class StateHandler:
    """Fetches bits of state from the stores, and does state resolution
    where necessary
    """

    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()
        self.store = hs.get_datastores().main
        self._state_storage_controller = hs.get_storage_controllers().state
        self.hs = hs
        self._state_resolution_handler = hs.get_state_resolution_handler()
        self._storage_controllers = hs.get_storage_controllers()
        self._events_shard_config = hs.config.worker.events_shard_config
        self._instance_name = hs.get_instance_name()

        self._update_current_state_client = (
            ReplicationUpdateCurrentStateRestServlet.make_client(hs)
        )

    async def get_current_state_ids(
        self,
        room_id: str,
        latest_event_ids: Collection[str],
    ) -> StateMap[str]:
        """Get the current state, or the state at a set of events, for a room

        Args:
            room_id:
            latest_event_ids: The forward extremities to resolve.

        Returns:
            the state dict, mapping from (event_type, state_key) -> event_id
        """
        logger.debug("calling resolve_state_groups from get_current_state_ids")
        ret = await self.resolve_state_groups_for_events(room_id, latest_event_ids)
        return ret.state

    async def get_current_users_in_room(
        self, room_id: str, latest_event_ids: List[str]
    ) -> Dict[str, ProfileInfo]:
        """
        Get the users who are currently in a room.

        Note: This is much slower than using the equivalent method
        `DataStore.get_users_in_room` or `DataStore.get_users_in_room_with_profiles`,
        so this should only be used when wanting the users at a particular point
        in the room.

        Args:
            room_id: The ID of the room.
            latest_event_ids: Precomputed list of latest event IDs. Will be computed if None.
        Returns:
            Dictionary of user IDs to their profileinfo.
        """

        assert latest_event_ids is not None

        logger.debug("calling resolve_state_groups from get_current_users_in_room")
        entry = await self.resolve_state_groups_for_events(room_id, latest_event_ids)
        return await self.store.get_joined_users_from_state(room_id, entry)

    async def get_hosts_in_room_at_events(
        self, room_id: str, event_ids: Collection[str]
    ) -> FrozenSet[str]:
        """Get the hosts that were in a room at the given event ids

        Args:
            room_id:
            event_ids:

        Returns:
            The hosts in the room at the given events
        """
        entry = await self.resolve_state_groups_for_events(room_id, event_ids)
        return await self.store.get_joined_hosts(room_id, entry)

    async def compute_event_context(
        self,
        event: EventBase,
        state_ids_before_event: Optional[StateMap[str]] = None,
        partial_state: bool = False,
    ) -> EventContext:
        """Build an EventContext structure for a non-outlier event.

        (for an outlier, call EventContext.for_outlier directly)

        This works out what the current state should be for the event, and
        generates a new state group if necessary.

        Args:
            event:
            state_ids_before_event: The event ids of the state before the event if
                it can't be calculated from existing events. This is normally
                only specified when receiving an event from federation where we
                don't have the prev events, e.g. when backfilling.
            partial_state: True if `state_ids_before_event` is partial and omits
                non-critical membership events
        Returns:
            The event context.
        """

        assert not event.internal_metadata.is_outlier()

        #
        # first of all, figure out the state before the event, unless we
        # already have it.
        #
        if state_ids_before_event:
            # if we're given the state before the event, then we use that
            state_group_before_event = None
            state_group_before_event_prev_group = None
            deltas_to_state_group_before_event = None
            entry = None

        else:
            # otherwise, we'll need to resolve the state across the prev_events.

            # partial_state should not be set explicitly in this case:
            # we work it out dynamically
            assert not partial_state

            # if any of the prev-events have partial state, so do we.
            # (This is slightly racy - the prev-events might get fixed up before we use
            # their states - but I don't think that really matters; it just means we
            # might redundantly recalculate the state for this event later.)
            prev_event_ids = event.prev_event_ids()
            incomplete_prev_events = await self.store.get_partial_state_events(
                prev_event_ids
            )
            if any(incomplete_prev_events.values()):
                logger.debug(
                    "New/incoming event %s refers to prev_events %s with partial state",
                    event.event_id,
                    [k for (k, v) in incomplete_prev_events.items() if v],
                )
                partial_state = True

            logger.debug("calling resolve_state_groups from compute_event_context")
            # we've already taken into account partial state, so no need to wait for
            # complete state here.
            entry = await self.resolve_state_groups_for_events(
                event.room_id,
                event.prev_event_ids(),
                await_full_state=False,
            )

            state_ids_before_event = entry.state
            state_group_before_event = entry.state_group
            state_group_before_event_prev_group = entry.prev_group
            deltas_to_state_group_before_event = entry.delta_ids

        #
        # make sure that we have a state group at that point. If it's not a state event,
        # that will be the state group for the new event. If it *is* a state event,
        # it might get rejected (in which case we'll need to persist it with the
        # previous state group)
        #

        if not state_group_before_event:
            state_group_before_event = (
                await self._state_storage_controller.store_state_group(
                    event.event_id,
                    event.room_id,
                    prev_group=state_group_before_event_prev_group,
                    delta_ids=deltas_to_state_group_before_event,
                    current_state_ids=state_ids_before_event,
                )
            )

            # Assign the new state group to the cached state entry.
            #
            # Note that this can race in that we could generate multiple state
            # groups for the same state entry, but that is just inefficient
            # rather than dangerous.
            if entry and entry.state_group is None:
                entry.state_group = state_group_before_event

        #
        # now if it's not a state event, we're done
        #

        if not event.is_state():
            return EventContext.with_state(
                storage=self._storage_controllers,
                state_group_before_event=state_group_before_event,
                state_group=state_group_before_event,
                state_delta_due_to_event={},
                prev_group=state_group_before_event_prev_group,
                delta_ids=deltas_to_state_group_before_event,
                partial_state=partial_state,
            )

        #
        # otherwise, we'll need to create a new state group for after the event
        #

        key = (event.type, event.state_key)
        if key in state_ids_before_event:
            replaces = state_ids_before_event[key]
            if replaces != event.event_id:
                event.unsigned["replaces_state"] = replaces

        state_ids_after_event = dict(state_ids_before_event)
        state_ids_after_event[key] = event.event_id
        delta_ids = {key: event.event_id}

        state_group_after_event = (
            await self._state_storage_controller.store_state_group(
                event.event_id,
                event.room_id,
                prev_group=state_group_before_event,
                delta_ids=delta_ids,
                current_state_ids=state_ids_after_event,
            )
        )

        return EventContext.with_state(
            storage=self._storage_controllers,
            state_group=state_group_after_event,
            state_group_before_event=state_group_before_event,
            state_delta_due_to_event=delta_ids,
            prev_group=state_group_before_event,
            delta_ids=delta_ids,
            partial_state=partial_state,
        )

    @measure_func()
    async def resolve_state_groups_for_events(
        self, room_id: str, event_ids: Collection[str], await_full_state: bool = True
    ) -> _StateCacheEntry:
        """Given a list of event_ids this method fetches the state at each
        event, resolves conflicts between them and returns them.

        Args:
            room_id
            event_ids
            await_full_state: if true, will block if we do not yet have complete
               state at these events.

        Returns:
            The resolved state
        """
        logger.debug("resolve_state_groups event_ids %s", event_ids)

        state_groups = await self._state_storage_controller.get_state_group_for_events(
            event_ids, await_full_state=await_full_state
        )

        state_group_ids = state_groups.values()

        # check if each event has same state group id, if so there's no state to resolve
        state_group_ids_set = set(state_group_ids)
        if len(state_group_ids_set) == 1:
            (state_group_id,) = state_group_ids_set
            state = await self._state_storage_controller.get_state_for_groups(
                state_group_ids_set
            )
            (
                prev_group,
                delta_ids,
            ) = await self._state_storage_controller.get_state_group_delta(
                state_group_id
            )
            return _StateCacheEntry(
                state=state[state_group_id],
                state_group=state_group_id,
                prev_group=prev_group,
                delta_ids=delta_ids,
            )
        elif len(state_group_ids_set) == 0:
            return _StateCacheEntry(state={}, state_group=None)

        room_version = await self.store.get_room_version_id(room_id)

        state_to_resolve = await self._state_storage_controller.get_state_for_groups(
            state_group_ids_set
        )

        result = await self._state_resolution_handler.resolve_state_groups(
            room_id,
            room_version,
            state_to_resolve,
            None,
            state_res_store=StateResolutionStore(self.store),
        )
        return result

    async def resolve_events(
        self,
        room_version: str,
        state_sets: Collection[Iterable[EventBase]],
        event: EventBase,
    ) -> StateMap[EventBase]:
        logger.info(
            "Resolving state for %s with %d groups", event.room_id, len(state_sets)
        )
        state_set_ids = [
            {(ev.type, ev.state_key): ev.event_id for ev in st} for st in state_sets
        ]

        state_map = {ev.event_id: ev for st in state_sets for ev in st}

        new_state = await self._state_resolution_handler.resolve_events_with_store(
            event.room_id,
            room_version,
            state_set_ids,
            event_map=state_map,
            state_res_store=StateResolutionStore(self.store),
        )

        return {key: state_map[ev_id] for key, ev_id in new_state.items()}

    async def update_current_state(self, room_id: str) -> None:
        """Recalculates the current state for a room, and persists it.

        Raises:
            SynapseError(502): if all attempts to connect to the event persister worker
                fail
        """
        writer_instance = self._events_shard_config.get_instance(room_id)
        if writer_instance != self._instance_name:
            await self._update_current_state_client(
                instance_name=writer_instance,
                room_id=room_id,
            )
            return

        assert self._storage_controllers.persistence is not None
        await self._storage_controllers.persistence.update_current_state(room_id)


@attr.s(slots=True, auto_attribs=True)
class _StateResMetrics:
    """Keeps track of some usage metrics about state res."""

    # System and User CPU time, in seconds
    cpu_time: float = 0.0

    # time spent on database transactions (excluding scheduling time). This roughly
    # corresponds to the amount of work done on the db server, excluding event fetches.
    db_time: float = 0.0

    # number of events fetched from the db.
    db_events: int = 0


_biggest_room_by_cpu_counter = Counter(
    "synapse_state_res_cpu_for_biggest_room_seconds",
    "CPU time spent performing state resolution for the single most expensive "
    "room for state resolution",
)
_biggest_room_by_db_counter = Counter(
    "synapse_state_res_db_for_biggest_room_seconds",
    "Database time spent performing state resolution for the single most "
    "expensive room for state resolution",
)

_cpu_times = Histogram(
    "synapse_state_res_cpu_for_all_rooms_seconds",
    "CPU time (utime+stime) spent computing a single state resolution",
)
_db_times = Histogram(
    "synapse_state_res_db_for_all_rooms_seconds",
    "Database time spent computing a single state resolution",
)


class StateResolutionHandler:
    """Responsible for doing state conflict resolution.

    Note that the storage layer depends on this handler, so all functions must
    be storage-independent.
    """

    def __init__(self, hs: "HomeServer"):
        self.clock = hs.get_clock()

        self.resolve_linearizer = Linearizer(name="state_resolve_lock")

        # dict of set of event_ids -> _StateCacheEntry.
        self._state_cache: ExpiringCache[
            FrozenSet[int], _StateCacheEntry
        ] = ExpiringCache(
            cache_name="state_cache",
            clock=self.clock,
            max_len=100000,
            expiry_ms=EVICTION_TIMEOUT_SECONDS * 1000,
            iterable=True,
            reset_expiry_on_get=True,
        )

        #
        # stuff for tracking time spent on state-res by room
        #

        # tracks the amount of work done on state res per room
        self._state_res_metrics: DefaultDict[str, _StateResMetrics] = defaultdict(
            _StateResMetrics
        )

        self.clock.looping_call(self._report_metrics, 120 * 1000)

    async def resolve_state_groups(
        self,
        room_id: str,
        room_version: str,
        state_groups_ids: Mapping[int, StateMap[str]],
        event_map: Optional[Dict[str, EventBase]],
        state_res_store: "StateResolutionStore",
    ) -> _StateCacheEntry:
        """Resolves conflicts between a set of state groups

        Always generates a new state group (unless we hit the cache), so should
        not be called for a single state group

        Args:
            room_id: room we are resolving for (used for logging and sanity checks)
            room_version: version of the room
            state_groups_ids:
                A map from state group id to the state in that state group
                (where 'state' is a map from state key to event id)

            event_map:
                a dict from event_id to event, for any events that we happen to
                have in flight (eg, those currently being persisted). This will be
                used as a starting point for finding the state we need; any missing
                events will be requested via state_res_store.

                If None, all events will be fetched via state_res_store.

            state_res_store

        Returns:
            The resolved state
        """
        group_names = frozenset(state_groups_ids.keys())

        async with self.resolve_linearizer.queue(group_names):
            cache = self._state_cache.get(group_names, None)
            if cache:
                return cache

            logger.info(
                "Resolving state for %s with groups %s",
                room_id,
                list(group_names),
            )

            state_groups_histogram.observe(len(state_groups_ids))

            new_state = await self.resolve_events_with_store(
                room_id,
                room_version,
                list(state_groups_ids.values()),
                event_map=event_map,
                state_res_store=state_res_store,
            )

            # if the new state matches any of the input state groups, we can
            # use that state group again. Otherwise we will generate a state_id
            # which will be used as a cache key for future resolutions, but
            # not get persisted.

            with Measure(self.clock, "state.create_group_ids"):
                cache = _make_state_cache_entry(new_state, state_groups_ids)

            self._state_cache[group_names] = cache

            return cache

    async def resolve_events_with_store(
        self,
        room_id: str,
        room_version: str,
        state_sets: Sequence[StateMap[str]],
        event_map: Optional[Dict[str, EventBase]],
        state_res_store: "StateResolutionStore",
    ) -> StateMap[str]:
        """
        Args:
            room_id: the room we are working in

            room_version: Version of the room

            state_sets: List of dicts of (type, state_key) -> event_id,
                which are the different state groups to resolve.

            event_map:
                a dict from event_id to event, for any events that we happen to
                have in flight (eg, those currently being persisted). This will be
                used as a starting point for finding the state we need; any missing
                events will be requested via state_map_factory.

                If None, all events will be fetched via state_res_store.

            state_res_store: a place to fetch events from

        Returns:
            a map from (type, state_key) to event_id.
        """
        try:
            with Measure(self.clock, "state._resolve_events") as m:
                room_version_obj = KNOWN_ROOM_VERSIONS[room_version]
                if room_version_obj.state_res == StateResolutionVersions.V1:
                    return await v1.resolve_events_with_store(
                        room_id,
                        room_version_obj,
                        state_sets,
                        event_map,
                        state_res_store.get_events,
                    )
                else:
                    return await v2.resolve_events_with_store(
                        self.clock,
                        room_id,
                        room_version_obj,
                        state_sets,
                        event_map,
                        state_res_store,
                    )
        finally:
            self._record_state_res_metrics(room_id, m.get_resource_usage())

    def _record_state_res_metrics(
        self, room_id: str, rusage: ContextResourceUsage
    ) -> None:
        room_metrics = self._state_res_metrics[room_id]
        room_metrics.cpu_time += rusage.ru_utime + rusage.ru_stime
        room_metrics.db_time += rusage.db_txn_duration_sec
        room_metrics.db_events += rusage.evt_db_fetch_count

        _cpu_times.observe(rusage.ru_utime + rusage.ru_stime)
        _db_times.observe(rusage.db_txn_duration_sec)

    def _report_metrics(self) -> None:
        if not self._state_res_metrics:
            # no state res has happened since the last iteration: don't bother logging.
            return

        self._report_biggest(
            lambda i: i.cpu_time,
            "CPU time",
            _biggest_room_by_cpu_counter,
        )

        self._report_biggest(
            lambda i: i.db_time,
            "DB time",
            _biggest_room_by_db_counter,
        )

        self._state_res_metrics.clear()

    def _report_biggest(
        self,
        extract_key: Callable[[_StateResMetrics], Any],
        metric_name: str,
        prometheus_counter_metric: Counter,
    ) -> None:
        """Report metrics on the biggest rooms for state res

        Args:
            extract_key: a callable which, given a _StateResMetrics, extracts a single
                metric to sort by.
            metric_name: the name of the metric we have extracted, for the log line
            prometheus_counter_metric: a prometheus metric recording the sum of the
                the extracted metric
        """
        n_to_log = 10
        if not metrics_logger.isEnabledFor(logging.DEBUG):
            # only need the most expensive if we don't have debug logging, which
            # allows nlargest() to degrade to max()
            n_to_log = 1

        items = self._state_res_metrics.items()

        # log the N biggest rooms
        biggest: List[Tuple[str, _StateResMetrics]] = heapq.nlargest(
            n_to_log, items, key=lambda i: extract_key(i[1])
        )
        metrics_logger.debug(
            "%i biggest rooms for state-res by %s: %s",
            len(biggest),
            metric_name,
            ["%s (%gs)" % (r, extract_key(m)) for (r, m) in biggest],
        )

        # report info on the single biggest to prometheus
        _, biggest_metrics = biggest[0]
        prometheus_counter_metric.inc(extract_key(biggest_metrics))


def _make_state_cache_entry(
    new_state: StateMap[str], state_groups_ids: Mapping[int, StateMap[str]]
) -> _StateCacheEntry:
    """Given a resolved state, and a set of input state groups, pick one to base
    a new state group on (if any), and return an appropriately-constructed
    _StateCacheEntry.

    Args:
        new_state: resolved state map (mapping from (type, state_key) to event_id)

        state_groups_ids:
            map from state group id to the state in that state group (where
            'state' is a map from state key to event id)

    Returns:
        The cache entry.
    """
    # if the new state matches any of the input state groups, we can
    # use that state group again. Otherwise we will generate a state_id
    # which will be used as a cache key for future resolutions, but
    # not get persisted.

    # first look for exact matches
    new_state_event_ids = set(new_state.values())
    for sg, state in state_groups_ids.items():
        if len(new_state_event_ids) != len(state):
            continue

        old_state_event_ids = set(state.values())
        if new_state_event_ids == old_state_event_ids:
            # got an exact match.
            return _StateCacheEntry(state=new_state, state_group=sg)

    # TODO: We want to create a state group for this set of events, to
    # increase cache hits, but we need to make sure that it doesn't
    # end up as a prev_group without being added to the database

    # failing that, look for the closest match.
    prev_group = None
    delta_ids: Optional[StateMap[str]] = None

    for old_group, old_state in state_groups_ids.items():
        n_delta_ids = {k: v for k, v in new_state.items() if old_state.get(k) != v}
        if not delta_ids or len(n_delta_ids) < len(delta_ids):
            prev_group = old_group
            delta_ids = n_delta_ids

    return _StateCacheEntry(
        state=new_state, state_group=None, prev_group=prev_group, delta_ids=delta_ids
    )


@attr.s(slots=True, auto_attribs=True)
class StateResolutionStore:
    """Interface that allows state resolution algorithms to access the database
    in well defined way.
    """

    store: "DataStore"

    def get_events(
        self, event_ids: Collection[str], allow_rejected: bool = False
    ) -> Awaitable[Dict[str, EventBase]]:
        """Get events from the database

        Args:
            event_ids: The event_ids of the events to fetch
            allow_rejected: If True return rejected events.

        Returns:
            An awaitable which resolves to a dict from event_id to event.
        """

        return self.store.get_events(
            event_ids,
            redact_behaviour=EventRedactBehaviour.as_is,
            get_prev_content=False,
            allow_rejected=allow_rejected,
        )

    def get_auth_chain_difference(
        self, room_id: str, state_sets: List[Set[str]]
    ) -> Awaitable[Set[str]]:
        """Given sets of state events figure out the auth chain difference (as
        per state res v2 algorithm).

        This equivalent to fetching the full auth chain for each set of state
        and returning the events that don't appear in each and every auth
        chain.

        Returns:
            An awaitable that resolves to a set of event IDs.
        """

        return self.store.get_auth_chain_difference(room_id, state_sets)
