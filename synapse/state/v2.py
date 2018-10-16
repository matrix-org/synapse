# -*- coding: utf-8 -*-
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

import itertools
import logging

from six import iteritems, itervalues

import networkx

from twisted.internet import defer

from synapse import event_auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError

logger = logging.getLogger(__name__)


@defer.inlineCallbacks
def resolve_events_with_factory(state_sets, event_map, state_map_factory):
    """
    Args:
        state_sets(list): List of dicts of (type, state_key) -> event_id,
            which are the different state groups to resolve.

        event_map(dict[str,FrozenEvent]|None):
            a dict from event_id to event, for any events that we happen to
            have in flight (eg, those currently being persisted). This will be
            used as a starting point fof finding the state we need; any missing
            events will be requested via state_map_factory.

            If None, all events will be fetched via state_map_factory.

        state_map_factory(func): will be called
            with a list of event_ids that are needed, and should return with
            a Deferred of dict of event_id to event.

    Returns
        Deferred[dict[(str, str), str]]:
            a map from (type, state_key) to event_id.
    """

    # First split up the un/conflicted state
    unconflicted_state, conflicted_state = _seperate(state_sets)

    if not conflicted_state:
        defer.returnValue(unconflicted_state)

    # Also fetch all auth events that appear in only some of the state sets'
    # auth chains.
    auth_diff = yield _get_auth_chain_difference(
        state_sets, event_map, state_map_factory,
    )

    full_conflicted_set = set(itertools.chain(
        itertools.chain.from_iterable(itervalues(conflicted_state)),
        auth_diff,
    ))

    for eid in full_conflicted_set:
        if eid not in event_map:
            events = yield state_map_factory([eid])
            event_map.update(events)

    # Get and sort all the power events (kicks/bans/etc)
    power_events = (
        eid for eid in full_conflicted_set
        if _is_power_event(event_map[eid])
    )
    sorted_power_events = _reverse_topological_power_sort(
        power_events,
        event_map,
        full_conflicted_set,
    )

    # Now sequentially auth each one
    resolved_state = yield _iterative_auth_checks(
        sorted_power_events, unconflicted_state, event_map,
        state_map_factory,
    )

    # OK, so we've now resolved the power events. Now sort the remaining
    # events using the mainline of the resolved power level.

    leftover_events = (
        ev_id
        for ev_id in full_conflicted_set
        if ev_id not in sorted_power_events
    )

    pl = resolved_state.get((EventTypes.PowerLevels, ""), None)
    leftover_events = yield _mainline_sort(
        leftover_events, pl, event_map, state_map_factory,
    )

    resolved_state = yield _iterative_auth_checks(
        leftover_events, resolved_state, event_map,
        state_map_factory,
    )

    # We make sure that unconflicted state always still applies.
    resolved_state.update(unconflicted_state)

    defer.returnValue(resolved_state)


def _get_power_level_for_sender(event_id, event_map):
    """Return the power level of the sender of the given event according to
    their auth events.
    """
    event = event_map[event_id]

    for aid, _ in event.auth_events:
        aev = event_map[aid]
        if (aev.type, aev.state_key) == (EventTypes.PowerLevels, ""):
            pl = aev
            break
    else:
        # Check if they're creator
        for aid, _ in event.auth_events:
            aev = event_map[aid]
            if (aev.type, aev.state_key) == (EventTypes.Create, ""):
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


@defer.inlineCallbacks
def _get_auth_chain_difference(state_sets, event_map, state_map_factory):
    """Compare the auth chains of each state set and return the set of events
    that only appear in some but not all of the auth chains.
    """
    common = set(itervalues(state_sets[0])).intersection(
        *(itervalues(s) for s in state_sets[1:])
    )

    auth_sets = []
    for state_set in state_sets:
        auth_ids = set(
            eid
            for key, eid in iteritems(state_set)
            if (key[0] in (
                 EventTypes.Member,
                 EventTypes.ThirdPartyInvite,
            ) or key in (
                (EventTypes.PowerLevels, ''),
                (EventTypes.Create, ''),
                (EventTypes.JoinRules, ''),
            )) and eid not in common
        )

        to_check = auth_ids

        while True:
            added = set()
            for aid in set(to_check):
                auth_event = event_map.get(aid)
                if not auth_event:
                    events = yield state_map_factory([aid])
                    auth_event = events[aid]
                    event_map[aid] = auth_event

                to_add = [
                    eid for eid, _ in auth_event.auth_events
                    if eid not in auth_ids
                    and eid not in common
                ]
                if to_add:
                    added.update(to_add)
                    auth_ids.update(to_add)

            if not added:
                break

            to_check = added

        auth_sets.append(auth_ids)

    intersection = set(auth_sets[0]).intersection(*auth_sets[1:])
    union = set().union(*auth_sets)

    defer.returnValue(union - intersection)


def _seperate(state_sets):
    """Return the unconflicted and conflicted state. This is different than in
    the original algorithm, as this defines a key to be conflicted if one of
    the state sets doesn't have that key.
    """
    unconflicted_state = {}
    conflicted_state = {}

    for key in set(itertools.chain.from_iterable(state_sets)):
        event_ids = set(state_set.get(key) for state_set in state_sets)
        if len(event_ids) == 1:
            unconflicted_state[key] = event_ids.pop()
        else:
            event_ids.discard(None)
            conflicted_state[key] = event_ids

    return unconflicted_state, conflicted_state


def _is_power_event(event):
    """Return whether or not the event is a "power event"
    """
    if (event.type, event.state_key) in (
        (EventTypes.PowerLevels, ""),
        (EventTypes.JoinRules, ""),
        (EventTypes.Create, ""),
    ):
        return True

    if event.type == EventTypes.Member:
        if event.membership in ('leave', 'ban'):
            return event.sender != event.state_key

    return False


def _add_event_and_auth_chain_to_graph(graph, event_id, event_map, auth_diff):
    """Helper function for _reverse_topological_power_sort that add the event
    and its auth chain (that is in the auth diff) to the graph
    """
    graph.add_node(event_id)

    state = [event_id]
    while state:
        eid = state.pop()
        for aid, _ in event_map[event_id].auth_events:
            if aid in auth_diff:
                # We add the reverse edge because we want to do reverse
                # topological ordering
                graph.add_edge(aid, eid)
                if aid not in graph:
                    state.append(aid)


def _reverse_topological_power_sort(event_ids, event_map, auth_diff):
    """Returns a list of the event_ids sorted by reverse topological ordering,
    and then by power level and origin_server_ts
    """

    graph = networkx.DiGraph()
    for event_id in event_ids:
        _add_event_and_auth_chain_to_graph(
            graph, event_id, event_map, auth_diff,
        )

    def _get_power_order(event_id):
        ev = event_map[event_id]
        pl = _get_power_level_for_sender(event_id, event_map)

        return -pl, ev.origin_server_ts, event_id

    it = networkx.algorithms.dag.lexicographical_topological_sort(
        graph,
        key=_get_power_order,
    )
    sorted_events = list(it)

    return sorted_events


@defer.inlineCallbacks
def _iterative_auth_checks(event_ids, base_state, event_map, state_map_factory):
    """Sequentially apply auth checks to each event in given list, updating the
    state as it goes along.
    """
    resolved_state = base_state.copy()

    for event_id in event_ids:
        event = event_map[event_id]

        auth_events = {}
        for aid, _ in event.auth_events:
            if aid not in event_map:
                events = yield state_map_factory([aid])
                event_map.update(events)
            ev = event_map[aid]
            auth_events[(ev.type, ev.state_key)] = ev

        for key in event_auth.auth_types_for_event(event):
            if key in resolved_state:
                auth_events[key] = event_map[resolved_state[key]]

        try:
            event_auth.check(
                event, auth_events,
                do_sig_check=False,
                do_size_check=False
            )

            resolved_state[(event.type, event.state_key)] = event_id
        except AuthError:
            pass

    defer.returnValue(resolved_state)


@defer.inlineCallbacks
def _mainline_sort(event_ids, resolved_power_event_id, event_map,
                   state_map_factory):
    """Returns a sorted list of event_ids sorted by mainline ordering based on
    the given event resolved_power_event_id
    """
    mainline = []
    pl = resolved_power_event_id
    while pl:
        mainline.append(pl)
        if pl not in event_map:
            events = yield state_map_factory([pl])
            event_map.update(events)
        auth_events = event_map[pl].auth_events
        pl = None
        for aid, _ in auth_events:
            if aid not in event_map:
                events = yield state_map_factory([aid])
                event_map.update(events)
            ev = event_map[aid]
            if (ev.type, ev.state_key) == (EventTypes.PowerLevels, ""):
                pl = aid
                break

    mainline_map = {ev_id: i + 1 for i, ev_id in enumerate(reversed(mainline))}

    @defer.inlineCallbacks
    def get_mainline_depth(event):
        if event.event_id in mainline_map:
            defer.returnValue(mainline_map[event.event_id])

        for aid, _ in event.auth_events:
            if aid not in event_map:
                events = yield state_map_factory([aid])
                event_map.update(events)
            aev = event_map[aid]
            if (aev.type, aev.state_key) == (EventTypes.PowerLevels, ""):
                ret = yield get_mainline_depth(aev)
                defer.returnValue(ret + 1)

        defer.returnValue(0)

    event_ids = list(event_ids)

    order_map = {}
    for ev_id in event_ids:
        depth = yield get_mainline_depth(event_map[ev_id])
        order_map[ev_id] = (depth, event_map[ev_id].origin_server_ts, ev_id)

    event_ids.sort(key=lambda ev_id: order_map[ev_id])

    defer.returnValue(event_ids)
