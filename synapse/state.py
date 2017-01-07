# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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


from twisted.internet import defer

from synapse.util.logutils import log_function
from synapse.util.caches.expiringcache import ExpiringCache
from synapse.util.metrics import Measure
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError
from synapse.api.auth import AuthEventTypes
from synapse.events.snapshot import EventContext
from synapse.util.async import Linearizer

from collections import namedtuple
from frozendict import frozendict

import logging
import hashlib
import os

logger = logging.getLogger(__name__)


KeyStateTuple = namedtuple("KeyStateTuple", ("context", "type", "state_key"))


CACHE_SIZE_FACTOR = float(os.environ.get("SYNAPSE_CACHE_FACTOR", 0.1))


SIZE_OF_CACHE = int(1000 * CACHE_SIZE_FACTOR)
EVICTION_TIMEOUT_SECONDS = 60 * 60


_NEXT_STATE_ID = 1


def _gen_state_id():
    global _NEXT_STATE_ID
    s = "X%d" % (_NEXT_STATE_ID,)
    _NEXT_STATE_ID += 1
    return s


class _StateCacheEntry(object):
    __slots__ = ["state", "state_group", "state_id", "prev_group", "delta_ids"]

    def __init__(self, state, state_group, prev_group=None, delta_ids=None):
        self.state = frozendict(state)
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


class StateHandler(object):
    """ Responsible for doing state conflict resolution.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.hs = hs

        # dict of set of event_ids -> _StateCacheEntry.
        self._state_cache = None
        self.resolve_linearizer = Linearizer()

    def start_caching(self):
        logger.debug("start_caching")

        self._state_cache = ExpiringCache(
            cache_name="state_cache",
            clock=self.clock,
            max_len=SIZE_OF_CACHE,
            expiry_ms=EVICTION_TIMEOUT_SECONDS * 1000,
            reset_expiry_on_get=True,
        )

        self._state_cache.start()

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key="",
                          latest_event_ids=None):
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

        logger.info("calling resolve_state_groups from get_current_state")
        ret = yield self.resolve_state_groups(room_id, latest_event_ids)
        state = ret.state

        if event_type:
            event_id = state.get((event_type, state_key))
            event = None
            if event_id:
                event = yield self.store.get_event(event_id, allow_none=True)
            defer.returnValue(event)
            return

        state_map = yield self.store.get_events(state.values(), get_prev_content=False)
        state = {
            key: state_map[e_id] for key, e_id in state.items() if e_id in state_map
        }

        defer.returnValue(state)

    @defer.inlineCallbacks
    def get_current_state_ids(self, room_id, event_type=None, state_key="",
                              latest_event_ids=None):
        if not latest_event_ids:
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)

        logger.info("calling resolve_state_groups from get_current_state_ids")
        ret = yield self.resolve_state_groups(room_id, latest_event_ids)
        state = ret.state

        if event_type:
            defer.returnValue(state.get((event_type, state_key)))
            return

        defer.returnValue(state)

    @defer.inlineCallbacks
    def get_current_user_in_room(self, room_id, latest_event_ids=None):
        if not latest_event_ids:
            latest_event_ids = yield self.store.get_latest_event_ids_in_room(room_id)
        logger.info("calling resolve_state_groups from get_current_user_in_room")
        entry = yield self.resolve_state_groups(room_id, latest_event_ids)
        joined_users = yield self.store.get_joined_users_from_state(
            room_id, entry.state_id, entry.state
        )
        defer.returnValue(joined_users)

    @defer.inlineCallbacks
    def compute_event_context(self, event, old_state=None):
        """ Fills out the context with the `current state` of the graph. The
        `current state` here is defined to be the state of the event graph
        just before the event - i.e. it never includes `event`

        If `event` has `auth_events` then this will also fill out the
        `auth_events` field on `context` from the `current_state`.

        Args:
            event (EventBase)
        Returns:
            an EventContext
        """
        context = EventContext()

        if event.internal_metadata.is_outlier():
            # If this is an outlier, then we know it shouldn't have any current
            # state. Certainly store.get_current_state won't return any, and
            # persisting the event won't store the state group.
            if old_state:
                context.prev_state_ids = {
                    (s.type, s.state_key): s.event_id for s in old_state
                }
                if event.is_state():
                    context.current_state_events = dict(context.prev_state_ids)
                    key = (event.type, event.state_key)
                    context.current_state_events[key] = event.event_id
                else:
                    context.current_state_events = context.prev_state_ids
            else:
                context.current_state_ids = {}
                context.prev_state_ids = {}
            context.prev_state_events = []
            context.state_group = self.store.get_next_state_group()
            defer.returnValue(context)

        if old_state:
            context.prev_state_ids = {
                (s.type, s.state_key): s.event_id for s in old_state
            }
            context.state_group = self.store.get_next_state_group()

            if event.is_state():
                key = (event.type, event.state_key)
                if key in context.prev_state_ids:
                    replaces = context.prev_state_ids[key]
                    if replaces != event.event_id:  # Paranoia check
                        event.unsigned["replaces_state"] = replaces
                context.current_state_ids = dict(context.prev_state_ids)
                context.current_state_ids[key] = event.event_id
            else:
                context.current_state_ids = context.prev_state_ids

            context.prev_state_events = []
            defer.returnValue(context)

        logger.info("calling resolve_state_groups from compute_event_context")
        if event.is_state():
            entry = yield self.resolve_state_groups(
                event.room_id, [e for e, _ in event.prev_events],
                event_type=event.type,
                state_key=event.state_key,
            )
        else:
            entry = yield self.resolve_state_groups(
                event.room_id, [e for e, _ in event.prev_events],
            )

        curr_state = entry.state

        context.prev_state_ids = curr_state
        if event.is_state():
            context.state_group = self.store.get_next_state_group()

            key = (event.type, event.state_key)
            if key in context.prev_state_ids:
                replaces = context.prev_state_ids[key]
                event.unsigned["replaces_state"] = replaces

            context.current_state_ids = dict(context.prev_state_ids)
            context.current_state_ids[key] = event.event_id

            context.prev_group = entry.prev_group
            context.delta_ids = entry.delta_ids
            if context.delta_ids is not None:
                context.delta_ids = dict(context.delta_ids)
                context.delta_ids[key] = event.event_id
        else:
            if entry.state_group is None:
                entry.state_group = self.store.get_next_state_group()
                entry.state_id = entry.state_group

            context.state_group = entry.state_group
            context.current_state_ids = context.prev_state_ids
            context.prev_group = entry.prev_group
            context.delta_ids = entry.delta_ids

        context.prev_state_events = []
        defer.returnValue(context)

    @defer.inlineCallbacks
    @log_function
    def resolve_state_groups(self, room_id, event_ids, event_type=None, state_key=""):
        """ Given a list of event_ids this method fetches the state at each
        event, resolves conflicts between them and returns them.

        Returns:
            a Deferred tuple of (`state_group`, `state`, `prev_state`).
            `state_group` is the name of a state group if one and only one is
            involved. `state` is a map from (type, state_key) to event, and
            `prev_state` is a list of event ids.
        """
        logger.debug("resolve_state_groups event_ids %s", event_ids)

        state_groups_ids = yield self.store.get_state_groups_ids(
            room_id, event_ids
        )

        logger.debug(
            "resolve_state_groups state_groups %s",
            state_groups_ids.keys()
        )

        group_names = frozenset(state_groups_ids.keys())
        if len(group_names) == 1:
            name, state_list = state_groups_ids.items().pop()

            defer.returnValue(_StateCacheEntry(
                state=state_list,
                state_group=name,
                prev_group=name,
                delta_ids={},
            ))

        with (yield self.resolve_linearizer.queue(group_names)):
            if self._state_cache is not None:
                cache = self._state_cache.get(group_names, None)
                if cache:
                    defer.returnValue(cache)

            logger.info(
                "Resolving state for %s with %d groups", room_id, len(state_groups_ids)
            )

            state = {}
            for st in state_groups_ids.values():
                for key, e_id in st.items():
                    state.setdefault(key, set()).add(e_id)

            conflicted_state = {
                k: list(v)
                for k, v in state.items()
                if len(v) > 1
            }

            if conflicted_state:
                logger.info("Resolving conflicted state for %r", room_id)
                state_map = yield self.store.get_events(
                    [e_id for st in state_groups_ids.values() for e_id in st.values()],
                    get_prev_content=False
                )
                state_sets = [
                    [state_map[e_id] for key, e_id in st.items() if e_id in state_map]
                    for st in state_groups_ids.values()
                ]
                new_state, _ = self._resolve_events(
                    state_sets, event_type, state_key
                )
                new_state = {
                    key: e.event_id for key, e in new_state.items()
                }
            else:
                new_state = {
                    key: e_ids.pop() for key, e_ids in state.items()
                }

            state_group = None
            new_state_event_ids = frozenset(new_state.values())
            for sg, events in state_groups_ids.items():
                if new_state_event_ids == frozenset(e_id for e_id in events):
                    state_group = sg
                    break
            if state_group is None:
                # Worker instances don't have access to this method, but we want
                # to set the state_group on the main instance to increase cache
                # hits.
                if hasattr(self.store, "get_next_state_group"):
                    state_group = self.store.get_next_state_group()

            prev_group = None
            delta_ids = None
            for old_group, old_ids in state_groups_ids.items():
                if not set(new_state.iterkeys()) - set(old_ids.iterkeys()):
                    n_delta_ids = {
                        k: v
                        for k, v in new_state.items()
                        if old_ids.get(k) != v
                    }
                    if not delta_ids or len(n_delta_ids) < len(delta_ids):
                        prev_group = old_group
                        delta_ids = n_delta_ids

            cache = _StateCacheEntry(
                state=new_state,
                state_group=state_group,
                prev_group=prev_group,
                delta_ids=delta_ids,
            )

            if self._state_cache is not None:
                self._state_cache[group_names] = cache

            defer.returnValue(cache)

    def resolve_events(self, state_sets, event):
        logger.info(
            "Resolving state for %s with %d groups", event.room_id, len(state_sets)
        )
        if event.is_state():
            return self._resolve_events(
                state_sets, event.type, event.state_key
            )
        else:
            return self._resolve_events(state_sets)

    def _resolve_events(self, state_sets, event_type=None, state_key=""):
        """
        Returns
            (dict[(str, str), synapse.events.FrozenEvent], list[str]): a tuple
            (new_state, prev_states). new_state is a map from (type, state_key)
            to event. prev_states is a list of event_ids.
        """
        with Measure(self.clock, "state._resolve_events"):
            state = {}
            for st in state_sets:
                for e in st:
                    state.setdefault(
                        (e.type, e.state_key),
                        {}
                    )[e.event_id] = e

            unconflicted_state = {
                k: v.values()[0] for k, v in state.items()
                if len(v.values()) == 1
            }

            conflicted_state = {
                k: v.values()
                for k, v in state.items()
                if len(v.values()) > 1
            }

            if event_type:
                prev_states_events = conflicted_state.get(
                    (event_type, state_key), []
                )
                prev_states = [s.event_id for s in prev_states_events]
            else:
                prev_states = []

            auth_events = {
                k: e for k, e in unconflicted_state.items()
                if k[0] in AuthEventTypes
            }

            try:
                resolved_state = self._resolve_state_events(
                    conflicted_state, auth_events
                )
            except:
                logger.exception("Failed to resolve state")
                raise

            new_state = unconflicted_state
            new_state.update(resolved_state)

        return new_state, prev_states

    @log_function
    def _resolve_state_events(self, conflicted_state, auth_events):
        """ This is where we actually decide which of the conflicted state to
        use.

        We resolve conflicts in the following order:
            1. power levels
            2. join rules
            3. memberships
            4. other events.
        """
        resolved_state = {}
        power_key = (EventTypes.PowerLevels, "")
        if power_key in conflicted_state:
            events = conflicted_state[power_key]
            logger.debug("Resolving conflicted power levels %r", events)
            resolved_state[power_key] = self._resolve_auth_events(
                events, auth_events)

        auth_events.update(resolved_state)

        for key, events in conflicted_state.items():
            if key[0] == EventTypes.JoinRules:
                logger.debug("Resolving conflicted join rules %r", events)
                resolved_state[key] = self._resolve_auth_events(
                    events,
                    auth_events
                )

        auth_events.update(resolved_state)

        for key, events in conflicted_state.items():
            if key[0] == EventTypes.Member:
                logger.debug("Resolving conflicted member lists %r", events)
                resolved_state[key] = self._resolve_auth_events(
                    events,
                    auth_events
                )

        auth_events.update(resolved_state)

        for key, events in conflicted_state.items():
            if key not in resolved_state:
                logger.debug("Resolving conflicted state %r:%r", key, events)
                resolved_state[key] = self._resolve_normal_events(
                    events, auth_events
                )

        return resolved_state

    def _resolve_auth_events(self, events, auth_events):
        reverse = [i for i in reversed(self._ordered_events(events))]

        auth_events = dict(auth_events)

        prev_event = reverse[0]
        for event in reverse[1:]:
            auth_events[(prev_event.type, prev_event.state_key)] = prev_event
            try:
                # FIXME: hs.get_auth() is bad style, but we need to do it to
                # get around circular deps.
                # The signatures have already been checked at this point
                self.hs.get_auth().check(event, auth_events, do_sig_check=False)
                prev_event = event
            except AuthError:
                return prev_event

        return event

    def _resolve_normal_events(self, events, auth_events):
        for event in self._ordered_events(events):
            try:
                # FIXME: hs.get_auth() is bad style, but we need to do it to
                # get around circular deps.
                # The signatures have already been checked at this point
                self.hs.get_auth().check(event, auth_events, do_sig_check=False)
                return event
            except AuthError:
                pass

        # Use the last event (the one with the least depth) if they all fail
        # the auth check.
        return event

    def _ordered_events(self, events):
        def key_func(e):
            return -int(e.depth), hashlib.sha1(e.event_id).hexdigest()

        return sorted(events, key=key_func)
