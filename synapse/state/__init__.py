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
from collections import ChainMap, defaultdict
from typing import (
    TYPE_CHECKING,
    Any,
    Awaitable,
    Callable,
    Collection,
    DefaultDict,
    Dict,
    FrozenSet,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
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
from synapse.storage.state import StateFilter
from synapse.types import StateMap
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import Measure, measure_func

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.controllers import StateStorageController
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
    __slots__ = ["_state", "state_group", "prev_group", "delta_ids"]

    def __init__(
        self,
        state: Optional[StateMap[str]],
        state_group: Optional[int],
        prev_group: Optional[int] = None,
        delta_ids: Optional[StateMap[str]] = None,
    ):
        if state is None and state_group is None and prev_group is None:
            raise Exception("One of state, state_group or prev_group must be not None")

        if prev_group is not None and delta_ids is None:
            raise Exception("If prev_group is set so must delta_ids")

        # A map from (type, state_key) to event_id.
        #
        # This can be None if we have a `state_group` (as then we can fetch the
        # state from the DB.)
        self._state = frozendict(state) if state is not None else None

        # the ID of a state group if one and only one is involved.
        # otherwise, None otherwise?
        self.state_group = state_group

        self.prev_group = prev_group
        self.delta_ids = frozendict(delta_ids) if delta_ids is not None else None

    async def get_state(
        self,
        state_storage: "StateStorageController",
        state_filter: Optional["StateFilter"] = None,
    ) -> StateMap[str]:
        """Get the state map for this entry, either from the in-memory state or
        looking up the state group in the DB.
        """

        if self._state is not None:
            return self._state

        if self.state_group is not None:
            return await state_storage.get_state_ids_for_group(
                self.state_group, state_filter
            )

        assert self.prev_group is not None and self.delta_ids is not None

        prev_state = await state_storage.get_state_ids_for_group(
            self.prev_group, state_filter
        )

        # ChainMap expects MutableMapping, but since we're using it immutably
        # its safe to give it immutable maps.
        return ChainMap(self.delta_ids, prev_state)  # type: ignore[arg-type]

    def set_state_group(self, state_group: int) -> None:
        """Update the state group assigned to this state (e.g. after we've
        persisted it).

        Note: this will cause the cache entry to drop any stored state.
        """

        self.state_group = state_group

        # We clear out the state as we know longer need to explicitly keep it in
        # the `state_cache` (as the store state group cache will do that).
        self._state = None

    def __len__(self) -> int:
        # The len should be used to estimate how large this cache entry is, for
        # cache eviction purposes. This is why it's fine to return 1 if we're
        # not storing any state.

        length = 0

        if self._state:
            length += len(self._state)

        if self.delta_ids:
            length += len(self.delta_ids)

        return length or 1  # Make sure its not 0.


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

    async def compute_state_after_events(
        self,
        room_id: str,
        event_ids: Collection[str],
        state_filter: Optional[StateFilter] = None,
    ) -> StateMap[str]:
        """Fetch the state after each of the given event IDs. Resolve them and return.

        This is typically used where `event_ids` is a collection of forward extremities
        in a room, intended to become the `prev_events` of a new event E. If so, the
        return value of this function represents the state before E.

        Args:
            room_id: the room_id containing the given events.
            event_ids: the events whose state should be fetched and resolved.

        Returns:
            the state dict (a mapping from (event_type, state_key) -> event_id) which
            holds the resolution of the states after the given event IDs.
        """
        logger.debug("calling resolve_state_groups from compute_state_after_events")
        ret = await self.resolve_state_groups_for_events(room_id, event_ids)
        return await ret.get_state(self._state_storage_controller, state_filter)

    async def get_current_user_ids_in_room(
        self, room_id: str, latest_event_ids: List[str]
    ) -> Set[str]:
        """
        Get the users IDs who are currently in a room.

        Note: This is much slower than using the equivalent method
        `DataStore.get_users_in_room` or `DataStore.get_users_in_room_with_profiles`,
        so this should only be used when wanting the users at a particular point
        in the room.

        Args:
            room_id: The ID of the room.
            latest_event_ids: Precomputed list of latest event IDs. Will be computed if None.
        Returns:
            Set of user IDs in the room.
        """

        assert latest_event_ids is not None

        logger.debug("calling resolve_state_groups from get_current_user_ids_in_room")
        entry = await self.resolve_state_groups_for_events(room_id, latest_event_ids)
        state = await entry.get_state(self._state_storage_controller, StateFilter.all())
        return await self.store.get_joined_user_ids_from_state(room_id, state)

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
        state = await entry.get_state(self._state_storage_controller, StateFilter.all())
        return await self.store.get_joined_hosts(room_id, state, entry)

    async def compute_event_context(
        self,
        event: EventBase,
        state_ids_before_event: Optional[StateMap[str]] = None,
        partial_state: Optional[bool] = None,
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
            partial_state:
                `True` if `state_ids_before_event` is partial and omits non-critical
                membership events.
                `False` if `state_ids_before_event` is the full state.
                `None` when `state_ids_before_event` is not provided. In this case, the
                flag will be calculated based on `event`'s prev events.
        Returns:
            The event context.

        Raises:
            RuntimeError if `state_ids_before_event` is not provided and one or more
                prev events are missing or outliers.
        """

        assert not event.internal_metadata.is_outlier()

        #
        # first of all, figure out the state before the event, unless we
        # already have it.
        #
        if state_ids_before_event:
            # if we're given the state before the event, then we use that
            state_group_before_event_prev_group = None
            deltas_to_state_group_before_event = None

            # .. though we need to get a state group for it.
            state_group_before_event = (
                await self._state_storage_controller.store_state_group(
                    event.event_id,
                    event.room_id,
                    prev_group=None,
                    delta_ids=None,
                    current_state_ids=state_ids_before_event,
                )
            )

            # the partial_state flag must be provided
            assert partial_state is not None
        else:
            # otherwise, we'll need to resolve the state across the prev_events.

            # partial_state should not be set explicitly in this case:
            # we work it out dynamically
            assert partial_state is None

            # if any of the prev-events have partial state, so do we.
            # (This is slightly racy - the prev-events might get fixed up before we use
            # their states - but I don't think that really matters; it just means we
            # might redundantly recalculate the state for this event later.)
            prev_event_ids = event.prev_event_ids()
            incomplete_prev_events = await self.store.get_partial_state_events(
                prev_event_ids
            )
            partial_state = any(incomplete_prev_events.values())
            if partial_state:
                logger.debug(
                    "New/incoming event %s refers to prev_events %s with partial state",
                    event.event_id,
                    [k for (k, v) in incomplete_prev_events.items() if v],
                )

            logger.debug("calling resolve_state_groups from compute_event_context")
            # we've already taken into account partial state, so no need to wait for
            # complete state here.
            entry = await self.resolve_state_groups_for_events(
                event.room_id,
                event.prev_event_ids(),
                await_full_state=False,
            )

            state_group_before_event_prev_group = entry.prev_group
            deltas_to_state_group_before_event = entry.delta_ids
            state_ids_before_event = None

            # We make sure that we have a state group assigned to the state.
            if entry.state_group is None:
                # store_state_group requires us to have either a previous state group
                # (with deltas) or the complete state map. So, if we don't have a
                # previous state group, load the complete state map now.
                if state_group_before_event_prev_group is None:
                    state_ids_before_event = await entry.get_state(
                        self._state_storage_controller, StateFilter.all()
                    )

                state_group_before_event = (
                    await self._state_storage_controller.store_state_group(
                        event.event_id,
                        event.room_id,
                        prev_group=state_group_before_event_prev_group,
                        delta_ids=deltas_to_state_group_before_event,
                        current_state_ids=state_ids_before_event,
                    )
                )
                entry.set_state_group(state_group_before_event)
            else:
                state_group_before_event = entry.state_group

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

        if state_ids_before_event is not None:
            replaces = state_ids_before_event.get(key)
        else:
            replaces_state_map = await entry.get_state(
                self._state_storage_controller, StateFilter.from_types([key])
            )
            replaces = replaces_state_map.get(key)

        if replaces and replaces != event.event_id:
            event.unsigned["replaces_state"] = replaces

        delta_ids = {key: event.event_id}

        state_group_after_event = (
            await self._state_storage_controller.store_state_group(
                event.event_id,
                event.room_id,
                prev_group=state_group_before_event,
                delta_ids=delta_ids,
                current_state_ids=None,
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

    async def compute_event_context_for_batched(
        self,
        event: EventBase,
        state_ids_before_event: StateMap[str],
        current_state_group: int,
    ) -> EventContext:
        """
        Generate an event context for an event that has not yet been persisted to the
        database. Intended for use with events that are created to be persisted in a batch.
        Args:
            event: the event the context is being computed for
            state_ids_before_event: a state map consisting of the state ids of the events
            created prior to this event.
            current_state_group: the current state group before the event.
        """
        state_group_before_event_prev_group = None
        deltas_to_state_group_before_event = None

        state_group_before_event = current_state_group

        # if the event is not state, we are set
        if not event.is_state():
            return EventContext.with_state(
                storage=self._storage_controllers,
                state_group_before_event=state_group_before_event,
                state_group=state_group_before_event,
                state_delta_due_to_event={},
                prev_group=state_group_before_event_prev_group,
                delta_ids=deltas_to_state_group_before_event,
                partial_state=False,
            )

        # otherwise, we'll need to create a new state group for after the event
        key = (event.type, event.state_key)

        if state_ids_before_event is not None:
            replaces = state_ids_before_event.get(key)

        if replaces and replaces != event.event_id:
            event.unsigned["replaces_state"] = replaces

        delta_ids = {key: event.event_id}

        state_group_after_event = (
            await self._state_storage_controller.store_state_group(
                event.event_id,
                event.room_id,
                prev_group=state_group_before_event,
                delta_ids=delta_ids,
                current_state_ids=None,
            )
        )

        return EventContext.with_state(
            storage=self._storage_controllers,
            state_group=state_group_after_event,
            state_group_before_event=state_group_before_event,
            state_delta_due_to_event=delta_ids,
            prev_group=state_group_before_event,
            delta_ids=delta_ids,
            partial_state=False,
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

        Raises:
            RuntimeError if we don't have a state group for one or more of the events
               (ie. they are outliers or unknown)
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
            (
                prev_group,
                delta_ids,
            ) = await self._state_storage_controller.get_state_group_delta(
                state_group_id
            )
            return _StateCacheEntry(
                state=None,
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
            return _StateCacheEntry(state=None, state_group=sg)

    # TODO: We want to create a state group for this set of events, to
    # increase cache hits, but we need to make sure that it doesn't
    # end up as a prev_group without being added to the database

    # failing that, look for the closest match.
    prev_group = None
    delta_ids: Optional[StateMap[str]] = None

    for old_group, old_state in state_groups_ids.items():
        if old_state.keys() - new_state.keys():
            # Currently we don't support deltas that remove keys from the state
            # map, so we have to ignore this group as a candidate to base the
            # new group on.
            continue

        n_delta_ids = {k: v for k, v in new_state.items() if old_state.get(k) != v}
        if not delta_ids or len(n_delta_ids) < len(delta_ids):
            prev_group = old_group
            delta_ids = n_delta_ids

    if prev_group is not None:
        # If we have a prev group and deltas then we can drop the new state from
        # the cache (to reduce memory usage).
        return _StateCacheEntry(
            state=None, state_group=None, prev_group=prev_group, delta_ids=delta_ids
        )
    else:
        return _StateCacheEntry(state=new_state, state_group=None)


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
