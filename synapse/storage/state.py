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
    Set,
    Tuple,
    TypeVar,
)

import attr
from frozendict import frozendict

from synapse.api.constants import EventTypes
from synapse.events import EventBase
from synapse.types import MutableStateMap, StateKey, StateMap

if TYPE_CHECKING:
    from typing import FrozenSet  # noqa: used within quoted type hint; flake8 sad

    from synapse.server import HomeServer
    from synapse.storage.databases import Databases

logger = logging.getLogger(__name__)

# Used for generic functions below
T = TypeVar("T")


@attr.s(slots=True, frozen=True, auto_attribs=True)
class StateFilter:
    """A filter used when querying for state.

    Attributes:
        types: Map from type to set of state keys (or None). This specifies
            which state_keys for the given type to fetch from the DB. If None
            then all events with that type are fetched. If the set is empty
            then no events with that type are fetched.
        include_others: Whether to fetch events with types that do not
            appear in `types`.
    """

    types: "frozendict[str, Optional[FrozenSet[str]]]"
    include_others: bool = False

    def __attrs_post_init__(self):
        # If `include_others` is set we canonicalise the filter by removing
        # wildcards from the types dictionary
        if self.include_others:
            # this is needed to work around the fact that StateFilter is frozen
            object.__setattr__(
                self,
                "types",
                frozendict({k: v for k, v in self.types.items() if v is not None}),
            )

    @staticmethod
    def all() -> "StateFilter":
        """Returns a filter that fetches everything.

        Returns:
            The state filter.
        """
        return _ALL_STATE_FILTER

    @staticmethod
    def none() -> "StateFilter":
        """Returns a filter that fetches nothing.

        Returns:
            The new state filter.
        """
        return _NONE_STATE_FILTER

    @staticmethod
    def from_types(types: Iterable[Tuple[str, Optional[str]]]) -> "StateFilter":
        """Creates a filter that only fetches the given types

        Args:
            types: A list of type and state keys to fetch. A state_key of None
                fetches everything for that type

        Returns:
            The new state filter.
        """
        type_dict: Dict[str, Optional[Set[str]]] = {}
        for typ, s in types:
            if typ in type_dict:
                if type_dict[typ] is None:
                    continue

            if s is None:
                type_dict[typ] = None
                continue

            type_dict.setdefault(typ, set()).add(s)  # type: ignore

        return StateFilter(
            types=frozendict(
                (k, frozenset(v) if v is not None else None)
                for k, v in type_dict.items()
            )
        )

    @staticmethod
    def from_lazy_load_member_list(members: Iterable[str]) -> "StateFilter":
        """Creates a filter that returns all non-member events, plus the member
        events for the given users

        Args:
            members: Set of user IDs

        Returns:
            The new state filter
        """
        return StateFilter(
            types=frozendict({EventTypes.Member: frozenset(members)}),
            include_others=True,
        )

    @staticmethod
    def freeze(types: Mapping[str, Optional[Collection[str]]], include_others: bool):
        """
        Returns a (frozen) StateFilter with the same contents as the parameters
        specified here, which can be made of mutable types.
        """
        types_with_frozen_values: Dict[str, Optional[FrozenSet[str]]] = {}
        for state_types, state_keys in types.items():
            if state_keys is not None:
                types_with_frozen_values[state_types] = frozenset(state_keys)
            else:
                types_with_frozen_values[state_types] = None

        return StateFilter(
            frozendict(types_with_frozen_values), include_others=include_others
        )

    def return_expanded(self) -> "StateFilter":
        """Creates a new StateFilter where type wild cards have been removed
        (except for memberships). The returned filter is a superset of the
        current one, i.e. anything that passes the current filter will pass
        the returned filter.

        This helps the caching as the DictionaryCache knows if it has *all* the
        state, but does not know if it has all of the keys of a particular type,
        which makes wildcard lookups expensive unless we have a complete cache.
        Hence, if we are doing a wildcard lookup, populate the cache fully so
        that we can do an efficient lookup next time.

        Note that since we have two caches, one for membership events and one for
        other events, we can be a bit more clever than simply returning
        `StateFilter.all()` if `has_wildcards()` is True.

        We return a StateFilter where:
            1. the list of membership events to return is the same
            2. if there is a wildcard that matches non-member events we
               return all non-member events

        Returns:
            The new state filter.
        """

        if self.is_full():
            # If we're going to return everything then there's nothing to do
            return self

        if not self.has_wildcards():
            # If there are no wild cards, there's nothing to do
            return self

        if EventTypes.Member in self.types:
            get_all_members = self.types[EventTypes.Member] is None
        else:
            get_all_members = self.include_others

        has_non_member_wildcard = self.include_others or any(
            state_keys is None
            for t, state_keys in self.types.items()
            if t != EventTypes.Member
        )

        if not has_non_member_wildcard:
            # If there are no non-member wild cards we can just return ourselves
            return self

        if get_all_members:
            # We want to return everything.
            return StateFilter.all()
        elif EventTypes.Member in self.types:
            # We want to return all non-members, but only particular
            # memberships
            return StateFilter(
                types=frozendict({EventTypes.Member: self.types[EventTypes.Member]}),
                include_others=True,
            )
        else:
            # We want to return all non-members
            return _ALL_NON_MEMBER_STATE_FILTER

    def make_sql_filter_clause(self) -> Tuple[str, List[str]]:
        """Converts the filter to an SQL clause.

        For example:

            f = StateFilter.from_types([("m.room.create", "")])
            clause, args = f.make_sql_filter_clause()
            clause == "(type = ? AND state_key = ?)"
            args == ['m.room.create', '']


        Returns:
            The SQL string (may be empty) and arguments. An empty SQL string is
            returned when the filter matches everything (i.e. is "full").
        """

        where_clause = ""
        where_args: List[str] = []

        if self.is_full():
            return where_clause, where_args

        if not self.include_others and not self.types:
            # i.e. this is an empty filter, so we need to return a clause that
            # will match nothing
            return "1 = 2", []

        # First we build up a lost of clauses for each type/state_key combo
        clauses = []
        for etype, state_keys in self.types.items():
            if state_keys is None:
                clauses.append("(type = ?)")
                where_args.append(etype)
                continue

            for state_key in state_keys:
                clauses.append("(type = ? AND state_key = ?)")
                where_args.extend((etype, state_key))

        # This will match anything that appears in `self.types`
        where_clause = " OR ".join(clauses)

        # If we want to include stuff that's not in the types dict then we add
        # a `OR type NOT IN (...)` clause to the end.
        if self.include_others:
            if where_clause:
                where_clause += " OR "

            where_clause += "type NOT IN (%s)" % (",".join(["?"] * len(self.types)),)
            where_args.extend(self.types)

        return where_clause, where_args

    def max_entries_returned(self) -> Optional[int]:
        """Returns the maximum number of entries this filter will return if
        known, otherwise returns None.

        For example a simple state filter asking for `("m.room.create", "")`
        will return 1, whereas the default state filter will return None.

        This is used to bail out early if the right number of entries have been
        fetched.
        """
        if self.has_wildcards():
            return None

        return len(self.concrete_types())

    def filter_state(self, state_dict: StateMap[T]) -> MutableStateMap[T]:
        """Returns the state filtered with by this StateFilter.

        Args:
            state: The state map to filter

        Returns:
            The filtered state map.
            This is a copy, so it's safe to mutate.
        """
        if self.is_full():
            return dict(state_dict)

        filtered_state = {}
        for k, v in state_dict.items():
            typ, state_key = k
            if typ in self.types:
                state_keys = self.types[typ]
                if state_keys is None or state_key in state_keys:
                    filtered_state[k] = v
            elif self.include_others:
                filtered_state[k] = v

        return filtered_state

    def is_full(self) -> bool:
        """Whether this filter fetches everything or not

        Returns:
            True if the filter fetches everything.
        """
        return self.include_others and not self.types

    def has_wildcards(self) -> bool:
        """Whether the filter includes wildcards or is attempting to fetch
        specific state.

        Returns:
            True if the filter includes wildcards.
        """

        return self.include_others or any(
            state_keys is None for state_keys in self.types.values()
        )

    def concrete_types(self) -> List[Tuple[str, str]]:
        """Returns a list of concrete type/state_keys (i.e. not None) that
        will be fetched. This will be a complete list if `has_wildcards`
        returns False, but otherwise will be a subset (or even empty).

        Returns:
            A list of type/state_keys tuples.
        """
        return [
            (t, s)
            for t, state_keys in self.types.items()
            if state_keys is not None
            for s in state_keys
        ]

    def get_member_split(self) -> Tuple["StateFilter", "StateFilter"]:
        """Return the filter split into two: one which assumes it's exclusively
        matching against member state, and one which assumes it's matching
        against non member state.

        This is useful due to the returned filters giving correct results for
        `is_full()`, `has_wildcards()`, etc, when operating against maps that
        either exclusively contain member events or only contain non-member
        events. (Which is the case when dealing with the member vs non-member
        state caches).

        Returns:
            The member and non member filters
        """

        if EventTypes.Member in self.types:
            state_keys = self.types[EventTypes.Member]
            if state_keys is None:
                member_filter = StateFilter.all()
            else:
                member_filter = StateFilter(frozendict({EventTypes.Member: state_keys}))
        elif self.include_others:
            member_filter = StateFilter.all()
        else:
            member_filter = StateFilter.none()

        non_member_filter = StateFilter(
            types=frozendict(
                {k: v for k, v in self.types.items() if k != EventTypes.Member}
            ),
            include_others=self.include_others,
        )

        return member_filter, non_member_filter

    def _decompose_into_four_parts(
        self,
    ) -> Tuple[Tuple[bool, Set[str]], Tuple[Set[str], Set[StateKey]]]:
        """
        Decomposes this state filter into 4 constituent parts, which can be
        thought of as this:
            all? - minus_wildcards + plus_wildcards + plus_state_keys

        where
        * all represents ALL state
        * minus_wildcards represents entire state types to remove
        * plus_wildcards represents entire state types to add
        * plus_state_keys represents individual state keys to add

        See `recompose_from_four_parts` for the other direction of this
        correspondence.
        """
        is_all = self.include_others
        excluded_types: Set[str] = {t for t in self.types if is_all}
        wildcard_types: Set[str] = {t for t, s in self.types.items() if s is None}
        concrete_keys: Set[StateKey] = set(self.concrete_types())

        return (is_all, excluded_types), (wildcard_types, concrete_keys)

    @staticmethod
    def _recompose_from_four_parts(
        all_part: bool,
        minus_wildcards: Set[str],
        plus_wildcards: Set[str],
        plus_state_keys: Set[StateKey],
    ) -> "StateFilter":
        """
        Recomposes a state filter from 4 parts.

        See `decompose_into_four_parts` (the other direction of this
        correspondence) for descriptions on each of the parts.
        """

        # {state type -> set of state keys OR None for wildcard}
        # (The same structure as that of a StateFilter.)
        new_types: Dict[str, Optional[Set[str]]] = {}

        # if we start with all, insert the excluded statetypes as empty sets
        # to prevent them from being included
        if all_part:
            new_types.update({state_type: set() for state_type in minus_wildcards})

        # insert the plus wildcards
        new_types.update({state_type: None for state_type in plus_wildcards})

        # insert the specific state keys
        for state_type, state_key in plus_state_keys:
            if state_type in new_types:
                entry = new_types[state_type]
                if entry is not None:
                    entry.add(state_key)
            elif not all_part:
                # don't insert if the entire type is already included by
                # include_others as this would actually shrink the state allowed
                # by this filter.
                new_types[state_type] = {state_key}

        return StateFilter.freeze(new_types, include_others=all_part)

    def approx_difference(self, other: "StateFilter") -> "StateFilter":
        """
        Returns a state filter which represents `self - other`.

        This is useful for determining what state remains to be pulled out of the
        database if we want the state included by `self` but already have the state
        included by `other`.

        The returned state filter
        - MUST include all state events that are included by this filter (`self`)
          unless they are included by `other`;
        - MUST NOT include state events not included by this filter (`self`); and
        - MAY be an over-approximation: the returned state filter
          MAY additionally include some state events from `other`.

        This implementation attempts to return the narrowest such state filter.
        In the case that `self` contains wildcards for state types where
        `other` contains specific state keys, an approximation must be made:
        the returned state filter keeps the wildcard, as state filters are not
        able to express 'all state keys except some given examples'.
        e.g.
            StateFilter(m.room.member -> None (wildcard))
                minus
            StateFilter(m.room.member -> {'@wombat:example.org'})
                is approximated as
            StateFilter(m.room.member -> None (wildcard))
        """

        # We first transform self and other into an alternative representation:
        #   - whether or not they include all events to begin with ('all')
        #   - if so, which event types are excluded? ('excludes')
        #   - which entire event types to include ('wildcards')
        #   - which concrete state keys to include ('concrete state keys')
        (self_all, self_excludes), (
            self_wildcards,
            self_concrete_keys,
        ) = self._decompose_into_four_parts()
        (other_all, other_excludes), (
            other_wildcards,
            other_concrete_keys,
        ) = other._decompose_into_four_parts()

        # Start with an estimate of the difference based on self
        new_all = self_all
        # Wildcards from the other can be added to the exclusion filter
        new_excludes = self_excludes | other_wildcards
        # We remove wildcards that appeared as wildcards in the other
        new_wildcards = self_wildcards - other_wildcards
        # We filter out the concrete state keys that appear in the other
        # as wildcards or concrete state keys.
        new_concrete_keys = {
            (state_type, state_key)
            for (state_type, state_key) in self_concrete_keys
            if state_type not in other_wildcards
        } - other_concrete_keys

        if other_all:
            if self_all:
                # If self starts with all, then we add as wildcards any
                # types which appear in the other's exclusion filter (but
                # aren't in the self exclusion filter). This is as the other
                # filter will return everything BUT the types in its exclusion, so
                # we need to add those excluded types that also match the self
                # filter as wildcard types in the new filter.
                new_wildcards |= other_excludes.difference(self_excludes)

            # If other is an `include_others` then the difference isn't.
            new_all = False
            # (We have no need for excludes when we don't start with all, as there
            #  is nothing to exclude.)
            new_excludes = set()

            # We also filter out all state types that aren't in the exclusion
            # list of the other.
            new_wildcards &= other_excludes
            new_concrete_keys = {
                (state_type, state_key)
                for (state_type, state_key) in new_concrete_keys
                if state_type in other_excludes
            }

        # Transform our newly-constructed state filter from the alternative
        # representation back into the normal StateFilter representation.
        return StateFilter._recompose_from_four_parts(
            new_all, new_excludes, new_wildcards, new_concrete_keys
        )


_ALL_STATE_FILTER = StateFilter(types=frozendict(), include_others=True)
_ALL_NON_MEMBER_STATE_FILTER = StateFilter(
    types=frozendict({EventTypes.Member: frozenset()}), include_others=True
)
_NONE_STATE_FILTER = StateFilter(types=frozendict(), include_others=False)


class StateGroupStorage:
    """High level interface to fetching state for event."""

    def __init__(self, hs: "HomeServer", stores: "Databases"):
        self.stores = stores

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
        """
        if not event_ids:
            return {}

        event_to_groups = await self.stores.main._get_state_group_for_events(event_ids)

        groups = set(event_to_groups.values())
        group_to_state = await self.stores.state._get_state_for_groups(groups)

        return group_to_state

    async def get_state_ids_for_group(self, state_group: int) -> StateMap[str]:
        """Get the event IDs of all the state in the given state group

        Args:
            state_group: A state group for which we want to get the state IDs.

        Returns:
            Resolves to a map of (type, state_key) -> event_id
        """
        group_to_state = await self._get_state_for_groups((state_group,))

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
        """
        event_to_groups = await self.stores.main._get_state_group_for_events(event_ids)

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
        self, event_ids: Collection[str], state_filter: Optional[StateFilter] = None
    ) -> Dict[str, StateMap[str]]:
        """
        Get the state dicts corresponding to a list of events, containing the event_ids
        of the state events (as opposed to the events themselves)

        Args:
            event_ids: events whose state should be returned
            state_filter: The state filter used to fetch state from the database.

        Returns:
            A dict from event_id -> (type, state_key) -> event_id
        """
        event_to_groups = await self.stores.main._get_state_group_for_events(event_ids)

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
        """
        state_map = await self.get_state_ids_for_events(
            [event_id], state_filter or StateFilter.all()
        )
        return state_map[event_id]

    def _get_state_for_groups(
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
