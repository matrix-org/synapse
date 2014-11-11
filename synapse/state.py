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
from synapse.api.events.room import RoomPowerLevelsEvent

from collections import namedtuple

import copy
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
    @log_function
    def annotate_state_groups(self, event, old_state=None):
        yield run_on_reactor()

        if old_state:
            event.state_group = None
            event.old_state_events = {
                (s.type, s.state_key): s for s in old_state
            }
            event.state_events = event.old_state_events

            if hasattr(event, "state_key"):
                event.state_events[(event.type, event.state_key)] = event

            defer.returnValue(False)
            return

        if hasattr(event, "outlier") and event.outlier:
            event.state_group = None
            event.old_state_events = None
            event.state_events = {}
            defer.returnValue(False)
            return

        ids = [e for e, _ in event.prev_events]

        ret = yield self.resolve_state_groups(ids)
        state_group, new_state = ret

        event.old_state_events = copy.deepcopy(new_state)

        if hasattr(event, "state_key"):
            key = (event.type, event.state_key)
            if key in new_state:
                event.replaces_state = new_state[key].event_id
            new_state[key] = event
        elif state_group:
            event.state_group = state_group
            event.state_events = new_state
            defer.returnValue(False)

        event.state_group = None
        event.state_events = new_state

        defer.returnValue(hasattr(event, "state_key"))

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
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
    @log_function
    def resolve_state_groups(self, event_ids):
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
            defer.returnValue((name, state))

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

        try:
            new_state = {}
            new_state.update(unconflicted_state)
            for key, events in conflicted_state.items():
                new_state[key] = self._resolve_state_events(events)
        except:
            logger.exception("Failed to resolve state")
            raise

        defer.returnValue((None, new_state))

    def _get_power_level_from_event_state(self, event, user_id):
        if hasattr(event, "old_state_events") and event.old_state_events:
            key = (RoomPowerLevelsEvent.TYPE, "", )
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
