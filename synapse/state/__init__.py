# -*- coding: utf-8 -*-
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

import logging
from collections import namedtuple
from typing import Dict, Iterable, List, Optional, Set

from six import iteritems, itervalues

import attr
from frozendict import frozendict
from prometheus_client import Histogram

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, StateResolutionVersions
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.logging.utils import log_function
from synapse.state import v1, v2
from synapse.storage.data_stores.main.events_worker import EventRedactBehaviour
from synapse.types import StateMap
from synapse.util.async_helpers import Linearizer
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import Measure, measure_func

logger = logging.getLogger(__name__)


# Metrics for number of state groups involved in a resolution.
state_groups_histogram = Histogram(
    "synapse_state_number_state_groups_in_resolution",
    "Number of state groups used when performing a state resolution",
    buckets=(1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"),
)


KeyStateTuple = namedtuple("KeyStateTuple", ("context", "type", "state_key"))


EVICTION_TIMEOUT_SECONDS = 60 * 60


_NEXT_STATE_ID = 1

POWER_KEY = (EventTypes.PowerLevels, "")


def _gen_state_id():
    global _NEXT_STATE_ID
    s = "X%d" % (_NEXT_STATE_ID,)
    _NEXT_STATE_ID += 1
    return s


class _StateCacheEntry(object):
    __slots__ = ["state", "state_group", "state_id", "prev_group", "delta_ids"]

    def __init__(self, state, state_group, prev_group=None, delta_ids=None):
        # dict[(str, str), str] map  from (type, state_key) to event_id
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
            self.state_id = state_group
        else:
            self.state_id = _gen_state_id()

    def __len__(self):
        return len(self.state)


class StateHandler(object):
    """Fetches bits of state from the stores, and does state resolution
    where necessary
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.state_store = hs.get_storage().state
        self.hs = hs
        self._state_resolution_handler = hs.get_state_resolution_handler()

    @defer.inlineCallbacks
    def get_current_state(
        self, room_id, event_type=None, state_key="", latest_event_ids=None
    ):
        """ Retrieves the current state for the room. This is done by
        calling `get_latest_events_in_room` to get the leading edges of the
        event graph and then resolving any of the state conflicts.

        This is equivalent to getting the state of an event that were to send
        next before receiving any new events.

        If `event_type` is specified, then the method returns only the one
        event (or None) with that `event_type` and `state_key`.

        Returns:
            map from (type, state_key) to event
        """
        if not latest_event_ids:
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)

        logger.debug("calling resolve_state_groups from get_current_state")
        ret = yield self.resolve_state_groups_for_events(room_id, latest_event_ids)
        state = ret.state

        if event_type:
            event_id = state.get((event_type, state_key))
            event = None
            if event_id:
                event = yield self.store.get_event(event_id, allow_none=True)
            return event

        state_map = yield self.store.get_events(
            list(state.values()), get_prev_content=False
        )
        state = {
            key: state_map[e_id] for key, e_id in iteritems(state) if e_id in state_map
        }

        return state

    @defer.inlineCallbacks
    def get_current_state_ids(self, room_id, latest_event_ids=None):
        """Get the current state, or the state at a set of events, for a room

        Args:
            room_id (str):

            latest_event_ids (iterable[str]|None): if given, the forward
                extremities to resolve. If None, we look them up from the
                database (via a cache)

        Returns:
            Deferred[dict[(str, str), str)]]: the state dict, mapping from
                (event_type, state_key) -> event_id
        """
        if not latest_event_ids:
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)

        logger.debug("calling resolve_state_groups from get_current_state_ids")
        ret = yield self.resolve_state_groups_for_events(room_id, latest_event_ids)
        state = ret.state

        return state

    @defer.inlineCallbacks
    def get_current_users_in_room(self, room_id, latest_event_ids=None):
        """
        Get the users who are currently in a room.

        Args:
            room_id (str): The ID of the room.
            latest_event_ids (List[str]|None): Precomputed list of latest
                event IDs. Will be computed if None.
        Returns:
            Deferred[Dict[str,ProfileInfo]]: Dictionary of user IDs to their
                profileinfo.
        """
        if not latest_event_ids:
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)
        logger.debug("calling resolve_state_groups from get_current_users_in_room")
        entry = yield self.resolve_state_groups_for_events(room_id, latest_event_ids)
        joined_users = yield self.store.get_joined_users_from_state(room_id, entry)
        return joined_users

    @defer.inlineCallbacks
    def get_current_hosts_in_room(self, room_id):
        event_ids = yield self.store.get_latest_event_ids_in_room(room_id)
        return (yield self.get_hosts_in_room_at_events(room_id, event_ids))

    @defer.inlineCallbacks
    def get_hosts_in_room_at_events(self, room_id, event_ids):
        """Get the hosts that were in a room at the given event ids

        Args:
            room_id (str):
            event_ids (list[str]):

        Returns:
            Deferred[list[str]]: the hosts in the room at the given events
        """
        entry = yield self.resolve_state_groups_for_events(room_id, event_ids)
        joined_hosts = yield self.store.get_joined_hosts(room_id, entry)
        return joined_hosts

    @defer.inlineCallbacks
    def compute_event_context(
        self, event: EventBase, old_state: Optional[Iterable[EventBase]] = None
    ):
        """Build an EventContext structure for the event.

        This works out what the current state should be for the event, and
        generates a new state group if necessary.

        Args:
            event:
            old_state: The state at the event if it can't be
                calculated from existing events. This is normally only specified
                when receiving an event from federation where we don't have the
                prev events for, e.g. when backfilling.
        Returns:
            synapse.events.snapshot.EventContext:
        """

        if event.internal_metadata.is_outlier():
            # If this is an outlier, then we know it shouldn't have any current
            # state. Certainly store.get_current_state won't return any, and
            # persisting the event won't store the state group.

            # FIXME: why do we populate current_state_ids? I thought the point was
            # that we weren't supposed to have any state for outliers?
            if old_state:
                prev_state_ids = {(s.type, s.state_key): s.event_id for s in old_state}
                if event.is_state():
                    current_state_ids = dict(prev_state_ids)
                    key = (event.type, event.state_key)
                    current_state_ids[key] = event.event_id
                else:
                    current_state_ids = prev_state_ids
            else:
                current_state_ids = {}
                prev_state_ids = {}

            # We don't store state for outliers, so we don't generate a state
            # group for it.
            context = EventContext.with_state(
                state_group=None,
                state_group_before_event=None,
                current_state_ids=current_state_ids,
                prev_state_ids=prev_state_ids,
            )

            return context

        #
        # first of all, figure out the state before the event
        #

        if old_state:
            # if we're given the state before the event, then we use that
            state_ids_before_event = {
                (s.type, s.state_key): s.event_id for s in old_state
            }
            state_group_before_event = None
            state_group_before_event_prev_group = None
            deltas_to_state_group_before_event = None

        else:
            # otherwise, we'll need to resolve the state across the prev_events.
            logger.debug("calling resolve_state_groups from compute_event_context")

            entry = yield self.resolve_state_groups_for_events(
                event.room_id, event.prev_event_ids()
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
            state_group_before_event = yield self.state_store.store_state_group(
                event.event_id,
                event.room_id,
                prev_group=state_group_before_event_prev_group,
                delta_ids=deltas_to_state_group_before_event,
                current_state_ids=state_ids_before_event,
            )

            # XXX: can we update the state cache entry for the new state group? or
            # could we set a flag on resolve_state_groups_for_events to tell it to
            # always make a state group?

        #
        # now if it's not a state event, we're done
        #

        if not event.is_state():
            return EventContext.with_state(
                state_group_before_event=state_group_before_event,
                state_group=state_group_before_event,
                current_state_ids=state_ids_before_event,
                prev_state_ids=state_ids_before_event,
                prev_group=state_group_before_event_prev_group,
                delta_ids=deltas_to_state_group_before_event,
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

        state_group_after_event = yield self.state_store.store_state_group(
            event.event_id,
            event.room_id,
            prev_group=state_group_before_event,
            delta_ids=delta_ids,
            current_state_ids=state_ids_after_event,
        )

        return EventContext.with_state(
            state_group=state_group_after_event,
            state_group_before_event=state_group_before_event,
            current_state_ids=state_ids_after_event,
            prev_state_ids=state_ids_before_event,
            prev_group=state_group_before_event,
            delta_ids=delta_ids,
        )

    @measure_func()
    @defer.inlineCallbacks
    def resolve_state_groups_for_events(self, room_id, event_ids):
        """ Given a list of event_ids this method fetches the state at each
        event, resolves conflicts between them and returns them.

        Args:
            room_id (str)
            event_ids (list[str])
            explicit_room_version (str|None): If set uses the the given room
                version to choose the resolution algorithm. If None, then
                checks the database for room version.

        Returns:
            Deferred[_StateCacheEntry]: resolved state
        """
        logger.debug("resolve_state_groups event_ids %s", event_ids)

        # map from state group id to the state in that state group (where
        # 'state' is a map from state key to event id)
        # dict[int, dict[(str, str), str]]
        state_groups_ids = yield self.state_store.get_state_groups_ids(
            room_id, event_ids
        )

        if len(state_groups_ids) == 0:
            return _StateCacheEntry(state={}, state_group=None)
        elif len(state_groups_ids) == 1:
            name, state_list = list(state_groups_ids.items()).pop()

            prev_group, delta_ids = yield self.state_store.get_state_group_delta(name)

            return _StateCacheEntry(
                state=state_list,
                state_group=name,
                prev_group=prev_group,
                delta_ids=delta_ids,
            )

        room_version = yield self.store.get_room_version_id(room_id)

        result = yield self._state_resolution_handler.resolve_state_groups(
            room_id,
            room_version,
            state_groups_ids,
            None,
            state_res_store=StateResolutionStore(self.store),
        )
        return result

    @defer.inlineCallbacks
    def resolve_events(self, room_version, state_sets, event):
        logger.info(
            "Resolving state for %s with %d groups", event.room_id, len(state_sets)
        )
        state_set_ids = [
            {(ev.type, ev.state_key): ev.event_id for ev in st} for st in state_sets
        ]

        state_map = {ev.event_id: ev for st in state_sets for ev in st}

        with Measure(self.clock, "state._resolve_events"):
            new_state = yield resolve_events_with_store(
                event.room_id,
                room_version,
                state_set_ids,
                event_map=state_map,
                state_res_store=StateResolutionStore(self.store),
            )

        new_state = {key: state_map[ev_id] for key, ev_id in iteritems(new_state)}

        return new_state


class StateResolutionHandler(object):
    """Responsible for doing state conflict resolution.

    Note that the storage layer depends on this handler, so all functions must
    be storage-independent.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()

        # dict of set of event_ids -> _StateCacheEntry.
        self._state_cache = None
        self.resolve_linearizer = Linearizer(name="state_resolve_lock")

        self._state_cache = ExpiringCache(
            cache_name="state_cache",
            clock=self.clock,
            max_len=100000,
            expiry_ms=EVICTION_TIMEOUT_SECONDS * 1000,
            iterable=True,
            reset_expiry_on_get=True,
        )

    @defer.inlineCallbacks
    @log_function
    def resolve_state_groups(
        self, room_id, room_version, state_groups_ids, event_map, state_res_store
    ):
        """Resolves conflicts between a set of state groups

        Always generates a new state group (unless we hit the cache), so should
        not be called for a single state group

        Args:
            room_id (str): room we are resolving for (used for logging and sanity checks)
            room_version (str): version of the room
            state_groups_ids (dict[int, dict[(str, str), str]]):
                 map from state group id to the state in that state group
                (where 'state' is a map from state key to event id)

            event_map(dict[str,FrozenEvent]|None):
                a dict from event_id to event, for any events that we happen to
                have in flight (eg, those currently being persisted). This will be
                used as a starting point fof finding the state we need; any missing
                events will be requested via state_res_store.

                If None, all events will be fetched via state_res_store.

            state_res_store (StateResolutionStore)

        Returns:
            Deferred[_StateCacheEntry]: resolved state
        """
        logger.debug("resolve_state_groups state_groups %s", state_groups_ids.keys())

        group_names = frozenset(state_groups_ids.keys())

        with (yield self.resolve_linearizer.queue(group_names)):
            if self._state_cache is not None:
                cache = self._state_cache.get(group_names, None)
                if cache:
                    return cache

            logger.info(
                "Resolving state for %s with %d groups", room_id, len(state_groups_ids)
            )

            state_groups_histogram.observe(len(state_groups_ids))

            # start by assuming we won't have any conflicted state, and build up the new
            # state map by iterating through the state groups. If we discover a conflict,
            # we give up and instead use `resolve_events_with_store`.
            #
            # XXX: is this actually worthwhile, or should we just let
            # resolve_events_with_store do it?
            new_state = {}
            conflicted_state = False
            for st in itervalues(state_groups_ids):
                for key, e_id in iteritems(st):
                    if key in new_state:
                        conflicted_state = True
                        break
                    new_state[key] = e_id
                if conflicted_state:
                    break

            if conflicted_state:
                logger.info("Resolving conflicted state for %r", room_id)
                with Measure(self.clock, "state._resolve_events"):
                    new_state = yield resolve_events_with_store(
                        room_id,
                        room_version,
                        list(itervalues(state_groups_ids)),
                        event_map=event_map,
                        state_res_store=state_res_store,
                    )

            # if the new state matches any of the input state groups, we can
            # use that state group again. Otherwise we will generate a state_id
            # which will be used as a cache key for future resolutions, but
            # not get persisted.

            with Measure(self.clock, "state.create_group_ids"):
                cache = _make_state_cache_entry(new_state, state_groups_ids)

            if self._state_cache is not None:
                self._state_cache[group_names] = cache

            return cache


def _make_state_cache_entry(new_state, state_groups_ids):
    """Given a resolved state, and a set of input state groups, pick one to base
    a new state group on (if any), and return an appropriately-constructed
    _StateCacheEntry.

    Args:
        new_state (dict[(str, str), str]): resolved state map (mapping from
           (type, state_key) to event_id)

        state_groups_ids (dict[int, dict[(str, str), str]]):
                 map from state group id to the state in that state group
                (where 'state' is a map from state key to event id)

    Returns:
        _StateCacheEntry
    """
    # if the new state matches any of the input state groups, we can
    # use that state group again. Otherwise we will generate a state_id
    # which will be used as a cache key for future resolutions, but
    # not get persisted.

    # first look for exact matches
    new_state_event_ids = set(itervalues(new_state))
    for sg, state in iteritems(state_groups_ids):
        if len(new_state_event_ids) != len(state):
            continue

        old_state_event_ids = set(itervalues(state))
        if new_state_event_ids == old_state_event_ids:
            # got an exact match.
            return _StateCacheEntry(state=new_state, state_group=sg)

    # TODO: We want to create a state group for this set of events, to
    # increase cache hits, but we need to make sure that it doesn't
    # end up as a prev_group without being added to the database

    # failing that, look for the closest match.
    prev_group = None
    delta_ids = None

    for old_group, old_state in iteritems(state_groups_ids):
        n_delta_ids = {k: v for k, v in iteritems(new_state) if old_state.get(k) != v}
        if not delta_ids or len(n_delta_ids) < len(delta_ids):
            prev_group = old_group
            delta_ids = n_delta_ids

    return _StateCacheEntry(
        state=new_state, state_group=None, prev_group=prev_group, delta_ids=delta_ids
    )


def resolve_events_with_store(
    room_id: str,
    room_version: str,
    state_sets: List[StateMap[str]],
    event_map: Optional[Dict[str, EventBase]],
    state_res_store: "StateResolutionStore",
):
    """
    Args:
        room_id: the room we are working in

        room_version: Version of the room

        state_sets: List of dicts of (type, state_key) -> event_id,
            which are the different state groups to resolve.

        event_map:
            a dict from event_id to event, for any events that we happen to
            have in flight (eg, those currently being persisted). This will be
            used as a starting point fof finding the state we need; any missing
            events will be requested via state_map_factory.

            If None, all events will be fetched via state_res_store.

        state_res_store: a place to fetch events from

    Returns:
        Deferred[dict[(str, str), str]]:
            a map from (type, state_key) to event_id.
    """
    v = KNOWN_ROOM_VERSIONS[room_version]
    if v.state_res == StateResolutionVersions.V1:
        return v1.resolve_events_with_store(
            room_id, state_sets, event_map, state_res_store.get_events
        )
    else:
        return v2.resolve_events_with_store(
            room_id, room_version, state_sets, event_map, state_res_store
        )


@attr.s
class StateResolutionStore(object):
    """Interface that allows state resolution algorithms to access the database
    in well defined way.

    Args:
        store (DataStore)
    """

    store = attr.ib()

    def get_events(self, event_ids, allow_rejected=False):
        """Get events from the database

        Args:
            event_ids (list): The event_ids of the events to fetch
            allow_rejected (bool): If True return rejected events.

        Returns:
            Deferred[dict[str, FrozenEvent]]: Dict from event_id to event.
        """

        return self.store.get_events(
            event_ids,
            redact_behaviour=EventRedactBehaviour.AS_IS,
            get_prev_content=False,
            allow_rejected=allow_rejected,
        )

    def get_auth_chain_difference(self, state_sets: List[Set[str]]):
        """Given sets of state events figure out the auth chain difference (as
        per state res v2 algorithm).

        This equivalent to fetching the full auth chain for each set of state
        and returning the events that don't appear in each and every auth
        chain.

        Returns:
            Deferred[Set[str]]: Set of event IDs.
        """

        return self.store.get_auth_chain_difference(state_sets)
