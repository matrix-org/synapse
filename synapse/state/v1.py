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

import hashlib
import logging
from typing import (
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from synapse import event_auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase
from synapse.types import MutableStateMap, StateMap

logger = logging.getLogger(__name__)


POWER_KEY = (EventTypes.PowerLevels, "")


async def resolve_events_with_store(
    room_id: str,
    state_sets: Sequence[StateMap[str]],
    event_map: Optional[Dict[str, EventBase]],
    state_map_factory: Callable[[Iterable[str]], Awaitable[Dict[str, EventBase]]],
) -> StateMap[str]:
    """
    Args:
        room_id: the room we are working in

        state_sets: List of dicts of (type, state_key) -> event_id,
            which are the different state groups to resolve.

        event_map:
            a dict from event_id to event, for any events that we happen to
            have in flight (eg, those currently being persisted). This will be
            used as a starting point for finding the state we need; any missing
            events will be requested via state_map_factory.

            If None, all events will be fetched via state_map_factory.

        state_map_factory: will be called
            with a list of event_ids that are needed, and should return with
            an Awaitable that resolves to a dict of event_id to event.

    Returns:
        A map from (type, state_key) to event_id.
    """
    if len(state_sets) == 1:
        return state_sets[0]

    unconflicted_state, conflicted_state = _seperate(state_sets)

    needed_events = {
        event_id for event_ids in conflicted_state.values() for event_id in event_ids
    }
    needed_event_count = len(needed_events)
    if event_map is not None:
        needed_events -= set(event_map.keys())

    logger.info(
        "Asking for %d/%d conflicted events", len(needed_events), needed_event_count
    )

    # A map from state event id to event. Only includes the state events which
    # are in conflict (and those in event_map).
    state_map = await state_map_factory(needed_events)
    if event_map is not None:
        state_map.update(event_map)

    # everything in the state map should be in the right room
    for event in state_map.values():
        if event.room_id != room_id:
            raise Exception(
                "Attempting to state-resolve for room %s with event %s which is in %s"
                % (
                    room_id,
                    event.event_id,
                    event.room_id,
                )
            )

    # get the ids of the auth events which allow us to authenticate the
    # conflicted state, picking only from the unconflicting state.
    auth_events = _create_auth_events_from_maps(
        unconflicted_state, conflicted_state, state_map
    )

    new_needed_events = set(auth_events.values())
    new_needed_event_count = len(new_needed_events)
    new_needed_events -= needed_events
    if event_map is not None:
        new_needed_events -= set(event_map.keys())

    logger.info(
        "Asking for %d/%d auth events", len(new_needed_events), new_needed_event_count
    )

    state_map_new = await state_map_factory(new_needed_events)
    for event in state_map_new.values():
        if event.room_id != room_id:
            raise Exception(
                "Attempting to state-resolve for room %s with event %s which is in %s"
                % (
                    room_id,
                    event.event_id,
                    event.room_id,
                )
            )

    state_map.update(state_map_new)

    return _resolve_with_state(
        unconflicted_state, conflicted_state, auth_events, state_map
    )


def _seperate(
    state_sets: Iterable[StateMap[str]],
) -> Tuple[MutableStateMap[str], MutableStateMap[Set[str]]]:
    """Takes the state_sets and figures out which keys are conflicted and
    which aren't. i.e., which have multiple different event_ids associated
    with them in different state sets.

    Args:
        state_sets:
            List of dicts of (type, state_key) -> event_id, which are the
            different state groups to resolve.

    Returns:
        A tuple of (unconflicted_state, conflicted_state), where:

        unconflicted_state is a dict mapping (type, state_key)->event_id
        for unconflicted state keys.

        conflicted_state is a dict mapping (type, state_key) to a set of
        event ids for conflicted state keys.
    """
    state_set_iterator = iter(state_sets)
    unconflicted_state = dict(next(state_set_iterator))
    conflicted_state = {}  # type: MutableStateMap[Set[str]]

    for state_set in state_set_iterator:
        for key, value in state_set.items():
            # Check if there is an unconflicted entry for the state key.
            unconflicted_value = unconflicted_state.get(key)
            if unconflicted_value is None:
                # There isn't an unconflicted entry so check if there is a
                # conflicted entry.
                ls = conflicted_state.get(key)
                if ls is None:
                    # There wasn't a conflicted entry so haven't seen this key before.
                    # Therefore it isn't conflicted yet.
                    unconflicted_state[key] = value
                else:
                    # This key is already conflicted, add our value to the conflict set.
                    ls.add(value)
            elif unconflicted_value != value:
                # If the unconflicted value is not the same as our value then we
                # have a new conflict. So move the key from the unconflicted_state
                # to the conflicted state.
                conflicted_state[key] = {value, unconflicted_value}
                unconflicted_state.pop(key, None)

    return unconflicted_state, conflicted_state


def _create_auth_events_from_maps(
    unconflicted_state: StateMap[str],
    conflicted_state: StateMap[Set[str]],
    state_map: Dict[str, EventBase],
) -> StateMap[str]:
    """

    Args:
        unconflicted_state: The unconflicted state map.
        conflicted_state: The conflicted state map.
        state_map:

    Returns:
        A map from state key to event id.
    """
    auth_events = {}
    for event_ids in conflicted_state.values():
        for event_id in event_ids:
            if event_id in state_map:
                keys = event_auth.auth_types_for_event(state_map[event_id])
                for key in keys:
                    if key not in auth_events:
                        auth_event_id = unconflicted_state.get(key, None)
                        if auth_event_id:
                            auth_events[key] = auth_event_id
    return auth_events


def _resolve_with_state(
    unconflicted_state_ids: MutableStateMap[str],
    conflicted_state_ids: StateMap[Set[str]],
    auth_event_ids: StateMap[str],
    state_map: Dict[str, EventBase],
):
    conflicted_state = {}
    for key, event_ids in conflicted_state_ids.items():
        events = [state_map[ev_id] for ev_id in event_ids if ev_id in state_map]
        if len(events) > 1:
            conflicted_state[key] = events
        elif len(events) == 1:
            unconflicted_state_ids[key] = events[0].event_id

    auth_events = {
        key: state_map[ev_id]
        for key, ev_id in auth_event_ids.items()
        if ev_id in state_map
    }

    try:
        resolved_state = _resolve_state_events(conflicted_state, auth_events)
    except Exception:
        logger.exception("Failed to resolve state")
        raise

    new_state = unconflicted_state_ids
    for key, event in resolved_state.items():
        new_state[key] = event.event_id

    return new_state


def _resolve_state_events(
    conflicted_state: StateMap[List[EventBase]], auth_events: MutableStateMap[EventBase]
) -> StateMap[EventBase]:
    """This is where we actually decide which of the conflicted state to
    use.

    We resolve conflicts in the following order:
        1. power levels
        2. join rules
        3. memberships
        4. other events.
    """
    resolved_state = {}
    if POWER_KEY in conflicted_state:
        events = conflicted_state[POWER_KEY]
        logger.debug("Resolving conflicted power levels %r", events)
        resolved_state[POWER_KEY] = _resolve_auth_events(events, auth_events)

    auth_events.update(resolved_state)

    for key, events in conflicted_state.items():
        if key[0] == EventTypes.JoinRules:
            logger.debug("Resolving conflicted join rules %r", events)
            resolved_state[key] = _resolve_auth_events(events, auth_events)

    auth_events.update(resolved_state)

    for key, events in conflicted_state.items():
        if key[0] == EventTypes.Member:
            logger.debug("Resolving conflicted member lists %r", events)
            resolved_state[key] = _resolve_auth_events(events, auth_events)

    auth_events.update(resolved_state)

    for key, events in conflicted_state.items():
        if key not in resolved_state:
            logger.debug("Resolving conflicted state %r:%r", key, events)
            resolved_state[key] = _resolve_normal_events(events, auth_events)

    return resolved_state


def _resolve_auth_events(
    events: List[EventBase], auth_events: StateMap[EventBase]
) -> EventBase:
    reverse = list(reversed(_ordered_events(events)))

    auth_keys = {
        key for event in events for key in event_auth.auth_types_for_event(event)
    }

    new_auth_events = {}
    for key in auth_keys:
        auth_event = auth_events.get(key, None)
        if auth_event:
            new_auth_events[key] = auth_event

    auth_events = new_auth_events

    prev_event = reverse[0]
    for event in reverse[1:]:
        auth_events[(prev_event.type, prev_event.state_key)] = prev_event
        try:
            # The signatures have already been checked at this point
            event_auth.check(
                RoomVersions.V1,
                event,
                auth_events,
                do_sig_check=False,
                do_size_check=False,
            )
            prev_event = event
        except AuthError:
            return prev_event

    return event


def _resolve_normal_events(
    events: List[EventBase], auth_events: StateMap[EventBase]
) -> EventBase:
    for event in _ordered_events(events):
        try:
            # The signatures have already been checked at this point
            event_auth.check(
                RoomVersions.V1,
                event,
                auth_events,
                do_sig_check=False,
                do_size_check=False,
            )
            return event
        except AuthError:
            pass

    # Use the last event (the one with the least depth) if they all fail
    # the auth check.
    return event


def _ordered_events(events: Iterable[EventBase]) -> List[EventBase]:
    def key_func(e):
        # we have to use utf-8 rather than ascii here because it turns out we allow
        # people to send us events with non-ascii event IDs :/
        return -int(e.depth), hashlib.sha1(e.event_id.encode("utf-8")).hexdigest()

    return sorted(events, key=key_func)
