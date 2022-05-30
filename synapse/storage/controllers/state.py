# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import (
    TYPE_CHECKING,
    Awaitable,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Tuple,
)

from synapse.events import EventBase
from synapse.storage.state import StateFilter
from synapse.storage.util.partial_state_events_tracker import PartialStateEventsTracker
from synapse.types import MutableStateMap, StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases import Databases

logger = logging.getLogger(__name__)


class StateGroupStorageController:
    """High level interface to fetching state for event."""

    def __init__(self, hs: "HomeServer", stores: "Databases"):
        self._is_mine_id = hs.is_mine_id
        self.stores = stores
        self._partial_state_events_tracker = PartialStateEventsTracker(stores.main)

    def notify_event_un_partial_stated(self, event_id: str) -> None:
        self._partial_state_events_tracker.notify_un_partial_stated(event_id)

    async def get_state_group_delta(
        self, state_group: int
    ) -> Tuple[Optional[int], Optional[StateMap[str]]]:
        """Given a state group try to return a previous group and a delta between
        the old and the new.

        Args:
            state_group: The state group used to retrieve state deltas.

        Returns:
            A tuple of the previous group and a state map of the event IDs which
            make up the delta between the old and new state groups.
        """

        state_group_delta = await self.stores.state.get_state_group_delta(state_group)
        return state_group_delta.prev_group, state_group_delta.delta_ids

    async def get_state_groups_ids(
        self, _room_id: str, event_ids: Collection[str]
    ) -> Dict[int, MutableStateMap[str]]:
        """Get the event IDs of all the state for the state groups for the given events

        Args:
            _room_id: id of the room for these events
            event_ids: ids of the events

        Returns:
            dict of state_group_id -> (dict of (type, state_key) -> event id)

        Raises:
            RuntimeError if we don't have a state group for one or more of the events
               (ie they are outliers or unknown)
        """
        if not event_ids:
            return {}

        event_to_groups = await self.get_state_group_for_events(event_ids)

        groups = set(event_to_groups.values())
        group_to_state = await self.stores.state._get_state_for_groups(groups)

        return group_to_state

    async def get_state_ids_for_group(
        self, state_group: int, state_filter: Optional[StateFilter] = None
    ) -> StateMap[str]:
        """Get the event IDs of all the state in the given state group

        Args:
            state_group: A state group for which we want to get the state IDs.
            state_filter: specifies the type of state event to fetch from DB, example: EventTypes.JoinRules

        Returns:
            Resolves to a map of (type, state_key) -> event_id
        """
        group_to_state = await self.get_state_for_groups((state_group,), state_filter)

        return group_to_state[state_group]

    async def get_state_groups(
        self, room_id: str, event_ids: Collection[str]
    ) -> Dict[int, List[EventBase]]:
        """Get the state groups for the given list of event_ids

        Args:
            room_id: ID of the room for these events.
            event_ids: The event IDs to retrieve state for.

        Returns:
            dict of state_group_id -> list of state events.
        """
        if not event_ids:
            return {}

        group_to_ids = await self.get_state_groups_ids(room_id, event_ids)

        state_event_map = await self.stores.main.get_events(
            [
                ev_id
                for group_ids in group_to_ids.values()
                for ev_id in group_ids.values()
            ],
            get_prev_content=False,
        )

        return {
            group: [
                state_event_map[v]
                for v in event_id_map.values()
                if v in state_event_map
            ]
            for group, event_id_map in group_to_ids.items()
        }

    def _get_state_groups_from_groups(
        self, groups: List[int], state_filter: StateFilter
    ) -> Awaitable[Dict[int, StateMap[str]]]:
        """Returns the state groups for a given set of groups, filtering on
        types of state events.

        Args:
            groups: list of state group IDs to query
            state_filter: The state filter used to fetch state
                from the database.

        Returns:
            Dict of state group to state map.
        """

        return self.stores.state._get_state_groups_from_groups(groups, state_filter)

    async def get_state_for_events(
        self, event_ids: Collection[str], state_filter: Optional[StateFilter] = None
    ) -> Dict[str, StateMap[EventBase]]:
        """Given a list of event_ids and type tuples, return a list of state
        dicts for each event.

        Args:
            event_ids: The events to fetch the state of.
            state_filter: The state filter used to fetch state.

        Returns:
            A dict of (event_id) -> (type, state_key) -> [state_events]

        Raises:
            RuntimeError if we don't have a state group for one or more of the events
               (ie they are outliers or unknown)
        """
        await_full_state = True
        if state_filter and not state_filter.must_await_full_state(self._is_mine_id):
            await_full_state = False

        event_to_groups = await self.get_state_group_for_events(
            event_ids, await_full_state=await_full_state
        )

        groups = set(event_to_groups.values())
        group_to_state = await self.stores.state._get_state_for_groups(
            groups, state_filter or StateFilter.all()
        )

        state_event_map = await self.stores.main.get_events(
            [ev_id for sd in group_to_state.values() for ev_id in sd.values()],
            get_prev_content=False,
        )

        event_to_state = {
            event_id: {
                k: state_event_map[v]
                for k, v in group_to_state[group].items()
                if v in state_event_map
            }
            for event_id, group in event_to_groups.items()
        }

        return {event: event_to_state[event] for event in event_ids}

    async def get_state_ids_for_events(
        self,
        event_ids: Collection[str],
        state_filter: Optional[StateFilter] = None,
    ) -> Dict[str, StateMap[str]]:
        """
        Get the state dicts corresponding to a list of events, containing the event_ids
        of the state events (as opposed to the events themselves)

        Args:
            event_ids: events whose state should be returned
            state_filter: The state filter used to fetch state from the database.

        Returns:
            A dict from event_id -> (type, state_key) -> event_id

        Raises:
            RuntimeError if we don't have a state group for one or more of the events
                (ie they are outliers or unknown)
        """
        await_full_state = True
        if state_filter and not state_filter.must_await_full_state(self._is_mine_id):
            await_full_state = False

        event_to_groups = await self.get_state_group_for_events(
            event_ids, await_full_state=await_full_state
        )

        groups = set(event_to_groups.values())
        group_to_state = await self.stores.state._get_state_for_groups(
            groups, state_filter or StateFilter.all()
        )

        event_to_state = {
            event_id: group_to_state[group]
            for event_id, group in event_to_groups.items()
        }

        return {event: event_to_state[event] for event in event_ids}

    async def get_state_for_event(
        self, event_id: str, state_filter: Optional[StateFilter] = None
    ) -> StateMap[EventBase]:
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id: event whose state should be returned
            state_filter: The state filter used to fetch state from the database.

        Returns:
            A dict from (type, state_key) -> state_event

        Raises:
            RuntimeError if we don't have a state group for the event (ie it is an
                outlier or is unknown)
        """
        state_map = await self.get_state_for_events(
            [event_id], state_filter or StateFilter.all()
        )
        return state_map[event_id]

    async def get_state_ids_for_event(
        self, event_id: str, state_filter: Optional[StateFilter] = None
    ) -> StateMap[str]:
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id: event whose state should be returned
            state_filter: The state filter used to fetch state from the database.

        Returns:
            A dict from (type, state_key) -> state_event_id

        Raises:
            RuntimeError if we don't have a state group for the event (ie it is an
                outlier or is unknown)
        """
        state_map = await self.get_state_ids_for_events(
            [event_id], state_filter or StateFilter.all()
        )
        return state_map[event_id]

    def get_state_for_groups(
        self, groups: Iterable[int], state_filter: Optional[StateFilter] = None
    ) -> Awaitable[Dict[int, MutableStateMap[str]]]:
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key

        Args:
            groups: list of state groups for which we want to get the state.
            state_filter: The state filter used to fetch state.
                from the database.

        Returns:
            Dict of state group to state map.
        """
        return self.stores.state._get_state_for_groups(
            groups, state_filter or StateFilter.all()
        )

    async def get_state_group_for_events(
        self,
        event_ids: Collection[str],
        await_full_state: bool = True,
    ) -> Mapping[str, int]:
        """Returns mapping event_id -> state_group

        Args:
            event_ids: events to get state groups for
            await_full_state: if true, will block if we do not yet have complete
               state at these events.
        """
        if await_full_state:
            await self._partial_state_events_tracker.await_full_state(event_ids)

        return await self.stores.main._get_state_group_for_events(event_ids)

    async def store_state_group(
        self,
        event_id: str,
        room_id: str,
        prev_group: Optional[int],
        delta_ids: Optional[StateMap[str]],
        current_state_ids: StateMap[str],
    ) -> int:
        """Store a new set of state, returning a newly assigned state group.

        Args:
            event_id: The event ID for which the state was calculated.
            room_id: ID of the room for which the state was calculated.
            prev_group: A previous state group for the room, optional.
            delta_ids: The delta between state at `prev_group` and
                `current_state_ids`, if `prev_group` was given. Same format as
                `current_state_ids`.
            current_state_ids: The state to store. Map of (type, state_key)
                to event_id.

        Returns:
            The state group ID
        """
        return await self.stores.state.store_state_group(
            event_id, room_id, prev_group, delta_ids, current_state_ids
        )
