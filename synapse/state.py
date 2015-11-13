# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError
from synapse.api.auth import AuthEventTypes
from synapse.events.snapshot import EventContext

from collections import namedtuple

import logging
import hashlib

logger = logging.getLogger(__name__)


KeyStateTuple = namedtuple("KeyStateTuple", ("context", "type", "state_key"))


SIZE_OF_CACHE = 1000
EVICTION_TIMEOUT_SECONDS = 20


class _StateCacheEntry(object):
    def __init__(self, state, state_group, ts):
        self.state = state
        self.state_group = state_group


class StateHandler(object):
    """ Responsible for doing state conflict resolution.
    """

    def __init__(self, hs):
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.hs = hs

        # dict of set of event_ids -> _StateCacheEntry.
        self._state_cache = None

    def start_caching(self):
        logger.debug("start_caching")

        self._state_cache = ExpiringCache(
            cache_name="state_cache",
            clock=self.clock,
            max_len=SIZE_OF_CACHE,
            expiry_ms=EVICTION_TIMEOUT_SECONDS*1000,
            reset_expiry_on_get=True,
        )

        self._state_cache.start()

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
        """ Retrieves the current state for the room. This is done by
        calling `get_latest_events_in_room` to get the leading edges of the
        event graph and then resolving any of the state conflicts.

        This is equivalent to getting the state of an event that were to send
        next before receiving any new events.

        If `event_type` is specified, then the method returns only the one
        event (or None) with that `event_type` and `state_key`.

        :returns map from (type, state_key) to event
        """
        event_ids = yield self.store.get_latest_event_ids_in_room(room_id)

        cache = None
        if self._state_cache is not None:
            cache = self._state_cache.get(frozenset(event_ids), None)

        if cache:
            cache.ts = self.clock.time_msec()
            state = cache.state
        else:
            res = yield self.resolve_state_groups(room_id, event_ids)
            state = res[1]

        if event_type:
            defer.returnValue(state.get((event_type, state_key)))
            return

        defer.returnValue(state)

    @defer.inlineCallbacks
    def compute_event_context(self, event, old_state=None, outlier=False):
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

        if outlier:
            # If this is an outlier, then we know it shouldn't have any current
            # state. Certainly store.get_current_state won't return any, and
            # persisting the event won't store the state group.
            if old_state:
                context.current_state = {
                    (s.type, s.state_key): s for s in old_state
                }
            else:
                context.current_state = {}
            context.prev_state_events = []
            context.state_group = None
            defer.returnValue(context)

        if old_state:
            context.current_state = {
                (s.type, s.state_key): s for s in old_state
            }
            context.state_group = None

            if event.is_state():
                key = (event.type, event.state_key)
                if key in context.current_state:
                    replaces = context.current_state[key]
                    if replaces.event_id != event.event_id:  # Paranoia check
                        event.unsigned["replaces_state"] = replaces.event_id

            context.prev_state_events = []
            defer.returnValue(context)

        if event.is_state():
            ret = yield self.resolve_state_groups(
                event.room_id, [e for e, _ in event.prev_events],
                event_type=event.type,
                state_key=event.state_key,
            )
        else:
            ret = yield self.resolve_state_groups(
                event.room_id, [e for e, _ in event.prev_events],
            )

        group, curr_state, prev_state = ret

        context.current_state = curr_state
        context.state_group = group if not event.is_state() else None

        if event.is_state():
            key = (event.type, event.state_key)
            if key in context.current_state:
                replaces = context.current_state[key]
                event.unsigned["replaces_state"] = replaces.event_id

        context.prev_state_events = prev_state
        defer.returnValue(context)

    @defer.inlineCallbacks
    @log_function
    def resolve_state_groups(self, room_id, event_ids, event_type=None, state_key=""):
        """ Given a list of event_ids this method fetches the state at each
        event, resolves conflicts between them and returns them.

        :returns a Deferred tuple of (`state_group`, `state`, `prev_state`).
        `state_group` is the name of a state group if one and only one is
        involved. `state` is a map from (type, state_key) to event, and
        `prev_state` is a list of event ids.
        """
        logger.debug("resolve_state_groups event_ids %s", event_ids)

        if self._state_cache is not None:
            cache = self._state_cache.get(frozenset(event_ids), None)
            if cache and cache.state_group:
                cache.ts = self.clock.time_msec()
                prev_state = cache.state.get((event_type, state_key), None)
                if prev_state:
                    prev_state = prev_state.event_id
                    prev_states = [prev_state]
                else:
                    prev_states = []
                defer.returnValue(
                    (cache.state_group, cache.state, prev_states)
                )

        state_groups = yield self.store.get_state_groups(
            room_id, event_ids
        )

        logger.debug(
            "resolve_state_groups state_groups %s",
            state_groups.keys()
        )

        group_names = set(state_groups.keys())
        if len(group_names) == 1:
            name, state_list = state_groups.items().pop()
            state = {
                (e.type, e.state_key): e
                for e in state_list
            }
            prev_state = state.get((event_type, state_key), None)
            if prev_state:
                prev_state = prev_state.event_id
                prev_states = [prev_state]
            else:
                prev_states = []

            if self._state_cache is not None:
                cache = _StateCacheEntry(
                    state=state,
                    state_group=name,
                    ts=self.clock.time_msec()
                )

                self._state_cache[frozenset(event_ids)] = cache

            defer.returnValue((name, state, prev_states))

        new_state, prev_states = self._resolve_events(
            state_groups.values(), event_type, state_key
        )

        if self._state_cache is not None:
            cache = _StateCacheEntry(
                state=new_state,
                state_group=None,
                ts=self.clock.time_msec()
            )

            self._state_cache[frozenset(event_ids)] = cache

        defer.returnValue((None, new_state, prev_states))

    def resolve_events(self, state_sets, event):
        if event.is_state():
            return self._resolve_events(
                state_sets, event.type, event.state_key
            )
        else:
            return self._resolve_events(state_sets)

    def _resolve_events(self, state_sets, event_type=None, state_key=""):
        """
        :returns a tuple (new_state, prev_states). new_state is a map
        from (type, state_key) to event. prev_states is a list of event_ids.
        :rtype: (dict[(str, str), synapse.events.FrozenEvent], list[str])
        """
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
                self.hs.get_auth().check(event, auth_events)
                prev_event = event
            except AuthError:
                return prev_event

        return event

    def _resolve_normal_events(self, events, auth_events):
        for event in self._ordered_events(events):
            try:
                # FIXME: hs.get_auth() is bad style, but we need to do it to
                # get around circular deps.
                self.hs.get_auth().check(event, auth_events)
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
