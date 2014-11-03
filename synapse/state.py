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

from synapse.types import EventID

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
        self._replication = hs.get_replication_layer()
        self.server_name = hs.hostname
        self.hs = hs

    @defer.inlineCallbacks
    @log_function
    def handle_new_event(self, event, snapshot):
        """ Given an event this works out if a) we have sufficient power level
        to update the state and b) works out what the prev_state should be.

        Returns:
            Deferred: Resolved with a boolean indicating if we successfully
            updated the state.

        Raised:
            AuthError
        """
        # This needs to be done in a transaction.

        if not hasattr(event, "state_key"):
            return

        # Now I need to fill out the prev state and work out if it has auth
        # (w.r.t. to power levels)

        snapshot.fill_out_prev_events(event)
        yield self.annotate_state_groups(event)

        if event.old_state_events:
            current_state = event.old_state_events.get(
                (event.type, event.state_key)
            )

            if current_state:
                event.prev_state = current_state.event_id

        defer.returnValue(True)

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

        new_state = yield self.resolve_state_groups(
            [e for e, _ in event.prev_events]
        )

        event.old_state_events = copy.deepcopy(new_state)

        if hasattr(event, "state_key"):
            new_state[(event.type, event.state_key)] = event

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
            defer.returnValue(res.get((event_type, state_key)))
            return

        defer.returnValue(res.values())

    @defer.inlineCallbacks
    @log_function
    def resolve_state_groups(self, event_ids):
        state_groups = yield self.store.get_state_groups(
            event_ids
        )

        state = {}
        for group in state_groups:
            for s in group.state:
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
                new_state[key] = yield self._resolve_state_events(events)
        except:
            logger.exception("Failed to resolve state")
            raise

        defer.returnValue(new_state)

    @defer.inlineCallbacks
    @log_function
    def _resolve_state_events(self, events):
        curr_events = events

        new_powers_deferreds = []
        for e in curr_events:
            new_powers_deferreds.append(
                self.store.get_power_level(e.room_id, e.user_id)
            )

        new_powers = yield defer.gatherResults(
            new_powers_deferreds,
            consumeErrors=True
        )

        max_power = max([int(p) for p in new_powers])

        curr_events = [
            z[0] for z in zip(curr_events, new_powers)
            if int(z[1]) == max_power
        ]

        if not curr_events:
            raise RuntimeError("Max didn't get a max?")
        elif len(curr_events) == 1:
            defer.returnValue(curr_events[0])

        # TODO: For now, just choose the one with the largest event_id.
        defer.returnValue(
            sorted(
                curr_events,
                key=lambda e: hashlib.sha1(
                    e.event_id + e.user_id + e.room_id + e.type
                ).hexdigest()
            )[0]
        )
