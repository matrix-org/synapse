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

import logging
from typing import Iterable, List, TypeVar

from six import iteritems, itervalues

import attr

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.types import StateMap

logger = logging.getLogger(__name__)

# Used for generic functions below
T = TypeVar("T")


@attr.s(slots=True)
class StateFilter(object):
    """A filter used when querying for state.

    Attributes:
        types (dict[str, set[str]|None]): Map from type to set of state keys (or
            None). This specifies which state_keys for the given type to fetch
            from the DB. If None then all events with that type are fetched. If
            the set is empty then no events with that type are fetched.
        include_others (bool): Whether to fetch events with types that do not
            appear in `types`.
    """

    types = attr.ib()
    include_others = attr.ib(default=False)

    def __attrs_post_init__(self):
        # If `include_others` is set we canonicalise the filter by removing
        # wildcards from the types dictionary
        if self.include_others:
            self.types = {k: v for k, v in iteritems(self.types) if v is not None}

    @staticmethod
    def all():
        """Creates a filter that fetches everything.

        Returns:
            StateFilter
        """
        return StateFilter(types={}, include_others=True)

    @staticmethod
    def none():
        """Creates a filter that fetches nothing.

        Returns:
            StateFilter
        """
        return StateFilter(types={}, include_others=False)

    @staticmethod
    def from_types(types):
        """Creates a filter that only fetches the given types

        Args:
            types (Iterable[tuple[str, str|None]]): A list of type and state
                keys to fetch. A state_key of None fetches everything for
                that type

        Returns:
            StateFilter
        """
        type_dict = {}
        for typ, s in types:
            if typ in type_dict:
                if type_dict[typ] is None:
                    continue

            if s is None:
                type_dict[typ] = None
                continue

            type_dict.setdefault(typ, set()).add(s)

        return StateFilter(types=type_dict)

    @staticmethod
    def from_lazy_load_member_list(members):
        """Creates a filter that returns all non-member events, plus the member
        events for the given users

        Args:
            members (iterable[str]): Set of user IDs

        Returns:
            StateFilter
        """
        return StateFilter(types={EventTypes.Member: set(members)}, include_others=True)

    def return_expanded(self):
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
            StateFilter
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
            for t, state_keys in iteritems(self.types)
            if t != EventTypes.Member
        )

        if not has_non_member_wildcard:
            # If there are no non-member wild cards we can just return ourselves
            return self

        if get_all_members:
            # We want to return everything.
            return StateFilter.all()
        else:
            # We want to return all non-members, but only particular
            # memberships
            return StateFilter(
                types={EventTypes.Member: self.types[EventTypes.Member]},
                include_others=True,
            )

    def make_sql_filter_clause(self):
        """Converts the filter to an SQL clause.

        For example:

            f = StateFilter.from_types([("m.room.create", "")])
            clause, args = f.make_sql_filter_clause()
            clause == "(type = ? AND state_key = ?)"
            args == ['m.room.create', '']


        Returns:
            tuple[str, list]: The SQL string (may be empty) and arguments. An
            empty SQL string is returned when the filter matches everything
            (i.e. is "full").
        """

        where_clause = ""
        where_args = []

        if self.is_full():
            return where_clause, where_args

        if not self.include_others and not self.types:
            # i.e. this is an empty filter, so we need to return a clause that
            # will match nothing
            return "1 = 2", []

        # First we build up a lost of clauses for each type/state_key combo
        clauses = []
        for etype, state_keys in iteritems(self.types):
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

    def max_entries_returned(self):
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

    def filter_state(self, state_dict: StateMap[T]) -> StateMap[T]:
        """Returns the state filtered with by this StateFilter

        Args:
            state: The state map to filter

        Returns:
            The filtered state map
        """
        if self.is_full():
            return dict(state_dict)

        filtered_state = {}
        for k, v in iteritems(state_dict):
            typ, state_key = k
            if typ in self.types:
                state_keys = self.types[typ]
                if state_keys is None or state_key in state_keys:
                    filtered_state[k] = v
            elif self.include_others:
                filtered_state[k] = v

        return filtered_state

    def is_full(self):
        """Whether this filter fetches everything or not

        Returns:
            bool
        """
        return self.include_others and not self.types

    def has_wildcards(self):
        """Whether the filter includes wildcards or is attempting to fetch
        specific state.

        Returns:
            bool
        """

        return self.include_others or any(
            state_keys is None for state_keys in itervalues(self.types)
        )

    def concrete_types(self):
        """Returns a list of concrete type/state_keys (i.e. not None) that
        will be fetched. This will be a complete list if `has_wildcards`
        returns False, but otherwise will be a subset (or even empty).

        Returns:
            list[tuple[str,str]]
        """
        return [
            (t, s)
            for t, state_keys in iteritems(self.types)
            if state_keys is not None
            for s in state_keys
        ]

    def get_member_split(self):
        """Return the filter split into two: one which assumes it's exclusively
        matching against member state, and one which assumes it's matching
        against non member state.

        This is useful due to the returned filters giving correct results for
        `is_full()`, `has_wildcards()`, etc, when operating against maps that
        either exclusively contain member events or only contain non-member
        events. (Which is the case when dealing with the member vs non-member
        state caches).

        Returns:
            tuple[StateFilter, StateFilter]: The member and non member filters
        """

        if EventTypes.Member in self.types:
            state_keys = self.types[EventTypes.Member]
            if state_keys is None:
                member_filter = StateFilter.all()
            else:
                member_filter = StateFilter({EventTypes.Member: state_keys})
        elif self.include_others:
            member_filter = StateFilter.all()
        else:
            member_filter = StateFilter.none()

        non_member_filter = StateFilter(
            types={k: v for k, v in iteritems(self.types) if k != EventTypes.Member},
            include_others=self.include_others,
        )

        return member_filter, non_member_filter


class StateGroupStorage(object):
    """High level interface to fetching state for event.
    """

    def __init__(self, hs, stores):
        self.stores = stores

    def get_state_group_delta(self, state_group: int):
        """Given a state group try to return a previous group and a delta between
        the old and the new.

        Returns:
            Deferred[Tuple[Optional[int], Optional[StateMap[str]]]]:
                (prev_group, delta_ids)
        """

        return self.stores.state.get_state_group_delta(state_group)

    @defer.inlineCallbacks
    def get_state_groups_ids(self, _room_id, event_ids):
        """Get the event IDs of all the state for the state groups for the given events

        Args:
            _room_id (str): id of the room for these events
            event_ids (iterable[str]): ids of the events

        Returns:
            Deferred[dict[int, StateMap[str]]]:
                dict of state_group_id -> (dict of (type, state_key) -> event id)
        """
        if not event_ids:
            return {}

        event_to_groups = yield self.stores.main._get_state_group_for_events(event_ids)

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self.stores.state._get_state_for_groups(groups)

        return group_to_state

    @defer.inlineCallbacks
    def get_state_ids_for_group(self, state_group):
        """Get the event IDs of all the state in the given state group

        Args:
            state_group (int)

        Returns:
            Deferred[dict]: Resolves to a map of (type, state_key) -> event_id
        """
        group_to_state = yield self._get_state_for_groups((state_group,))

        return group_to_state[state_group]

    @defer.inlineCallbacks
    def get_state_groups(self, room_id, event_ids):
        """ Get the state groups for the given list of event_ids
        Returns:
            Deferred[dict[int, list[EventBase]]]:
                dict of state_group_id -> list of state events.
        """
        if not event_ids:
            return {}

        group_to_ids = yield self.get_state_groups_ids(room_id, event_ids)

        state_event_map = yield self.stores.main.get_events(
            [
                ev_id
                for group_ids in itervalues(group_to_ids)
                for ev_id in itervalues(group_ids)
            ],
            get_prev_content=False,
        )

        return {
            group: [
                state_event_map[v]
                for v in itervalues(event_id_map)
                if v in state_event_map
            ]
            for group, event_id_map in iteritems(group_to_ids)
        }

    def _get_state_groups_from_groups(
        self, groups: List[int], state_filter: StateFilter
    ):
        """Returns the state groups for a given set of groups, filtering on
        types of state events.

        Args:
            groups: list of state group IDs to query
            state_filter: The state filter used to fetch state
                from the database.
        Returns:
            Deferred[Dict[int, StateMap[str]]]: Dict of state group to state map.
        """

        return self.stores.state._get_state_groups_from_groups(groups, state_filter)

    @defer.inlineCallbacks
    def get_state_for_events(self, event_ids, state_filter=StateFilter.all()):
        """Given a list of event_ids and type tuples, return a list of state
        dicts for each event.
        Args:
            event_ids (list[string])
            state_filter (StateFilter): The state filter used to fetch state
                from the database.
        Returns:
            deferred: A dict of (event_id) -> (type, state_key) -> [state_events]
        """
        event_to_groups = yield self.stores.main._get_state_group_for_events(event_ids)

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self.stores.state._get_state_for_groups(
            groups, state_filter
        )

        state_event_map = yield self.stores.main.get_events(
            [ev_id for sd in itervalues(group_to_state) for ev_id in itervalues(sd)],
            get_prev_content=False,
        )

        event_to_state = {
            event_id: {
                k: state_event_map[v]
                for k, v in iteritems(group_to_state[group])
                if v in state_event_map
            }
            for event_id, group in iteritems(event_to_groups)
        }

        return {event: event_to_state[event] for event in event_ids}

    @defer.inlineCallbacks
    def get_state_ids_for_events(self, event_ids, state_filter=StateFilter.all()):
        """
        Get the state dicts corresponding to a list of events, containing the event_ids
        of the state events (as opposed to the events themselves)

        Args:
            event_ids(list(str)): events whose state should be returned
            state_filter (StateFilter): The state filter used to fetch state
                from the database.

        Returns:
            A deferred dict from event_id -> (type, state_key) -> event_id
        """
        event_to_groups = yield self.stores.main._get_state_group_for_events(event_ids)

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self.stores.state._get_state_for_groups(
            groups, state_filter
        )

        event_to_state = {
            event_id: group_to_state[group]
            for event_id, group in iteritems(event_to_groups)
        }

        return {event: event_to_state[event] for event in event_ids}

    @defer.inlineCallbacks
    def get_state_for_event(self, event_id, state_filter=StateFilter.all()):
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id(str): event whose state should be returned
            state_filter (StateFilter): The state filter used to fetch state
                from the database.

        Returns:
            A deferred dict from (type, state_key) -> state_event
        """
        state_map = yield self.get_state_for_events([event_id], state_filter)
        return state_map[event_id]

    @defer.inlineCallbacks
    def get_state_ids_for_event(self, event_id, state_filter=StateFilter.all()):
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id(str): event whose state should be returned
            state_filter (StateFilter): The state filter used to fetch state
                from the database.

        Returns:
            A deferred dict from (type, state_key) -> state_event
        """
        state_map = yield self.get_state_ids_for_events([event_id], state_filter)
        return state_map[event_id]

    def _get_state_for_groups(
        self, groups: Iterable[int], state_filter: StateFilter = StateFilter.all()
    ):
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key

        Args:
            groups (iterable[int]): list of state groups for which we want
                to get the state.
            state_filter (StateFilter): The state filter used to fetch state
                from the database.
        Returns:
            Deferred[dict[int, StateMap[str]]]: Dict of state group to state map.
        """
        return self.stores.state._get_state_for_groups(groups, state_filter)

    def store_state_group(
        self, event_id, room_id, prev_group, delta_ids, current_state_ids
    ):
        """Store a new set of state, returning a newly assigned state group.

        Args:
            event_id (str): The event ID for which the state was calculated
            room_id (str)
            prev_group (int|None): A previous state group for the room, optional.
            delta_ids (dict|None): The delta between state at `prev_group` and
                `current_state_ids`, if `prev_group` was given. Same format as
                `current_state_ids`.
            current_state_ids (dict): The state to store. Map of (type, state_key)
                to event_id.

        Returns:
            Deferred[int]: The state group ID
        """
        return self.stores.state.store_state_group(
            event_id, room_id, prev_group, delta_ids, current_state_ids
        )
