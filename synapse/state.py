# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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
from synapse.util.async import run_on_reactor
from synapse.api.constants import EventTypes
from synapse.events.snapshot import EventContext

from collections import namedtuple

import logging
import hashlib

logger = logging.getLogger(__name__)


def _get_state_key_from_event(event):
    return event.state_key


KeyStateTuple = namedtuple("KeyStateTuple", ("context", "type", "state_key"))


class StateHandler(object):
    """ Responsible for doing state conflict resolution.
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
        """ Returns the current state for the room as a list. This is done by
        calling `get_latest_events_in_room` to get the leading edges of the
        event graph and then resolving any of the state conflicts.

        This is equivalent to getting the state of an event that were to send
        next before receiving any new events.

        If `event_type` is specified, then the method returns only the one
        event (or None) with that `event_type` and `state_key`.
        """
        events = yield self.store.get_latest_events_in_room(room_id)

        event_ids = [
            e_id
            for e_id, _, _ in events
        ]

        res = yield self.resolve_state_groups(event_ids)

        if event_type:
            defer.returnValue(res[1].get((event_type, state_key)))
            return

        defer.returnValue(res[1].values())

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

        yield run_on_reactor()

        if old_state:
            context.current_state = {
                (s.type, s.state_key): s for s in old_state
            }
            context.state_group = None

            if hasattr(event, "auth_events") and event.auth_events:
                auth_ids = zip(*event.auth_events)[0]
                context.auth_events = {
                    k: v
                    for k, v in context.current_state.items()
                    if v.event_id in auth_ids
                }
            else:
                context.auth_events = {}

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
                [e for e, _ in event.prev_events],
                event_type=event.type,
                state_key=event.state_key,
            )
        else:
            ret = yield self.resolve_state_groups(
                [e for e, _ in event.prev_events],
            )

        group, curr_state, prev_state = ret

        context.current_state = curr_state
        context.state_group = group if not event.is_state() else None

        prev_state = yield self.store.add_event_hashes(
            prev_state
        )

        if event.is_state():
            key = (event.type, event.state_key)
            if key in context.current_state:
                replaces = context.current_state[key]
                event.unsigned["replaces_state"] = replaces.event_id

        if hasattr(event, "auth_events") and event.auth_events:
            auth_ids = zip(*event.auth_events)[0]
            context.auth_events = {
                k: v
                for k, v in context.current_state.items()
                if v.event_id in auth_ids
            }
        else:
            context.auth_events = {}

        context.prev_state_events = prev_state
        defer.returnValue(context)

    @defer.inlineCallbacks
    @log_function
    def resolve_state_groups(self, event_ids, event_type=None, state_key=""):
        """ Given a list of event_ids this method fetches the state at each
        event, resolves conflicts between them and returns them.

        Return format is a tuple: (`state_group`, `state_events`), where the
        first is the name of a state group if one and only one is involved,
        otherwise `None`.
        """
        state_groups = yield self.store.get_state_groups(
            event_ids
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

            defer.returnValue((name, state, prev_states))

        state = {}
        for group, g_state in state_groups.items():
            for s in g_state:
                state.setdefault(
                    (s.type, s.state_key),
                    {}
                )[s.event_id] = s

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

        try:
            new_state = {}
            new_state.update(unconflicted_state)
            for key, events in conflicted_state.items():
                new_state[key] = self._resolve_state_events(events)
        except:
            logger.exception("Failed to resolve state")
            raise

        defer.returnValue((None, new_state, prev_states))

    def _get_power_level_from_event_state(self, event, user_id):
        if hasattr(event, "old_state_events") and event.old_state_events:
            key = (EventTypes.PowerLevels, "", )
            power_level_event = event.old_state_events.get(key)
            level = None
            if power_level_event:
                level = power_level_event.content.get("users", {}).get(
                    user_id
                )
                if not level:
                    level = power_level_event.content.get("users_default", 0)

            return level
        else:
            return 0

    @log_function
    def _resolve_state_events(self, events):
        curr_events = events

        new_powers = [
            self._get_power_level_from_event_state(e, e.user_id)
            for e in curr_events
        ]

        new_powers = [
            int(p) if p else 0 for p in new_powers
        ]

        max_power = max(new_powers)

        curr_events = [
            z[0] for z in zip(curr_events, new_powers)
            if z[1] == max_power
        ]

        if not curr_events:
            raise RuntimeError("Max didn't get a max?")
        elif len(curr_events) == 1:
            return curr_events[0]

        # TODO: For now, just choose the one with the largest event_id.
        return (
            sorted(
                curr_events,
                key=lambda e: hashlib.sha1(
                    e.event_id + e.user_id + e.room_id + e.type
                ).hexdigest()
            )[0]
        )
