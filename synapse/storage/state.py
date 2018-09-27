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
from collections import namedtuple

from six import iteritems, itervalues
from six.moves import range

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import NotFoundError
from synapse.storage._base import SQLBaseStore
from synapse.storage.background_updates import BackgroundUpdateStore
from synapse.storage.engines import PostgresEngine
from synapse.storage.events_worker import EventsWorkerStore
from synapse.util.caches import get_cache_factor_for, intern_string
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.caches.dictionary_cache import DictionaryCache
from synapse.util.stringutils import to_ascii

logger = logging.getLogger(__name__)


MAX_STATE_DELTA_HOPS = 100


class _GetStateGroupDelta(namedtuple("_GetStateGroupDelta", ("prev_group", "delta_ids"))):
    """Return type of get_state_group_delta that implements __len__, which lets
    us use the itrable flag when caching
    """
    __slots__ = []

    def __len__(self):
        return len(self.delta_ids) if self.delta_ids else 0


# this inherits from EventsWorkerStore because it calls self.get_events
class StateGroupWorkerStore(EventsWorkerStore, SQLBaseStore):
    """The parts of StateGroupStore that can be called from workers.
    """

    STATE_GROUP_DEDUPLICATION_UPDATE_NAME = "state_group_state_deduplication"
    STATE_GROUP_INDEX_UPDATE_NAME = "state_group_state_type_index"
    CURRENT_STATE_INDEX_UPDATE_NAME = "current_state_members_idx"

    def __init__(self, db_conn, hs):
        super(StateGroupWorkerStore, self).__init__(db_conn, hs)

        # Originally the state store used a single DictionaryCache to cache the
        # event IDs for the state types in a given state group to avoid hammering
        # on the state_group* tables.
        #
        # The point of using a DictionaryCache is that it can cache a subset
        # of the state events for a given state group (i.e. a subset of the keys for a
        # given dict which is an entry in the cache for a given state group ID).
        #
        # However, this poses problems when performing complicated queries
        # on the store - for instance: "give me all the state for this group, but
        # limit members to this subset of users", as DictionaryCache's API isn't
        # rich enough to say "please cache any of these fields, apart from this subset".
        # This is problematic when lazy loading members, which requires this behaviour,
        # as without it the cache has no choice but to speculatively load all
        # state events for the group, which negates the efficiency being sought.
        #
        # Rather than overcomplicating DictionaryCache's API, we instead split the
        # state_group_cache into two halves - one for tracking non-member events,
        # and the other for tracking member_events.  This means that lazy loading
        # queries can be made in a cache-friendly manner by querying both caches
        # separately and then merging the result.  So for the example above, you
        # would query the members cache for a specific subset of state keys
        # (which DictionaryCache will handle efficiently and fine) and the non-members
        # cache for all state (which DictionaryCache will similarly handle fine)
        # and then just merge the results together.
        #
        # We size the non-members cache to be smaller than the members cache as the
        # vast majority of state in Matrix (today) is member events.

        self._state_group_cache = DictionaryCache(
            "*stateGroupCache*",
            # TODO: this hasn't been tuned yet
            50000 * get_cache_factor_for("stateGroupCache")
        )
        self._state_group_members_cache = DictionaryCache(
            "*stateGroupMembersCache*",
            500000 * get_cache_factor_for("stateGroupMembersCache")
        )

    @defer.inlineCallbacks
    def get_room_version(self, room_id):
        """Get the room_version of a given room

        Args:
            room_id (str)

        Returns:
            Deferred[str]

        Raises:
            NotFoundError if the room is unknown
        """
        # for now we do this by looking at the create event. We may want to cache this
        # more intelligently in future.
        state_ids = yield self.get_current_state_ids(room_id)
        create_id = state_ids.get((EventTypes.Create, ""))

        if not create_id:
            raise NotFoundError("Unknown room")

        create_event = yield self.get_event(create_id)
        defer.returnValue(create_event.content.get("room_version", "1"))

    @cached(max_entries=100000, iterable=True)
    def get_current_state_ids(self, room_id):
        """Get the current state event ids for a room based on the
        current_state_events table.

        Args:
            room_id (str)

        Returns:
            deferred: dict of (type, state_key) -> event_id
        """
        def _get_current_state_ids_txn(txn):
            txn.execute(
                """SELECT type, state_key, event_id FROM current_state_events
                WHERE room_id = ?
                """,
                (room_id,)
            )

            return {
                (intern_string(r[0]), intern_string(r[1])): to_ascii(r[2]) for r in txn
            }

        return self.runInteraction(
            "get_current_state_ids",
            _get_current_state_ids_txn,
        )

    # FIXME: how should this be cached?
    def get_filtered_current_state_ids(self, room_id, types, filtered_types=None):
        """Get the current state event of a given type for a room based on the
        current_state_events table.  This may not be as up-to-date as the result
        of doing a fresh state resolution as per state_handler.get_current_state
        Args:
            room_id (str)
            types (list[(Str, (Str|None))]): List of (type, state_key) tuples
                which are used to filter the state fetched. `state_key` may be
                None, which matches any `state_key`
            filtered_types (list[Str]|None): List of types to apply the above filter to.
        Returns:
            deferred: dict of (type, state_key) -> event
        """

        include_other_types = False if filtered_types is None else True

        def _get_filtered_current_state_ids_txn(txn):
            results = {}
            sql = """SELECT type, state_key, event_id FROM current_state_events
                     WHERE room_id = ? %s"""
            # Turns out that postgres doesn't like doing a list of OR's and
            # is about 1000x slower, so we just issue a query for each specific
            # type seperately.
            if types:
                clause_to_args = [
                    (
                        "AND type = ? AND state_key = ?",
                        (etype, state_key)
                    ) if state_key is not None else (
                        "AND type = ?",
                        (etype,)
                    )
                    for etype, state_key in types
                ]

                if include_other_types:
                    unique_types = set(filtered_types)
                    clause_to_args.append(
                        (
                            "AND type <> ? " * len(unique_types),
                            list(unique_types)
                        )
                    )
            else:
                # If types is None we fetch all the state, and so just use an
                # empty where clause with no extra args.
                clause_to_args = [("", [])]
            for where_clause, where_args in clause_to_args:
                args = [room_id]
                args.extend(where_args)
                txn.execute(sql % (where_clause,), args)
                for row in txn:
                    typ, state_key, event_id = row
                    key = (intern_string(typ), intern_string(state_key))
                    results[key] = event_id
            return results

        return self.runInteraction(
            "get_filtered_current_state_ids",
            _get_filtered_current_state_ids_txn,
        )

    @cached(max_entries=10000, iterable=True)
    def get_state_group_delta(self, state_group):
        """Given a state group try to return a previous group and a delta between
        the old and the new.

        Returns:
            (prev_group, delta_ids), where both may be None.
        """
        def _get_state_group_delta_txn(txn):
            prev_group = self._simple_select_one_onecol_txn(
                txn,
                table="state_group_edges",
                keyvalues={
                    "state_group": state_group,
                },
                retcol="prev_state_group",
                allow_none=True,
            )

            if not prev_group:
                return _GetStateGroupDelta(None, None)

            delta_ids = self._simple_select_list_txn(
                txn,
                table="state_groups_state",
                keyvalues={
                    "state_group": state_group,
                },
                retcols=("type", "state_key", "event_id",)
            )

            return _GetStateGroupDelta(prev_group, {
                (row["type"], row["state_key"]): row["event_id"]
                for row in delta_ids
            })
        return self.runInteraction(
            "get_state_group_delta",
            _get_state_group_delta_txn,
        )

    @defer.inlineCallbacks
    def get_state_groups_ids(self, _room_id, event_ids):
        """Get the event IDs of all the state for the state groups for the given events

        Args:
            _room_id (str): id of the room for these events
            event_ids (iterable[str]): ids of the events

        Returns:
            Deferred[dict[int, dict[tuple[str, str], str]]]:
                dict of state_group_id -> (dict of (type, state_key) -> event id)
        """
        if not event_ids:
            defer.returnValue({})

        event_to_groups = yield self._get_state_group_for_events(
            event_ids,
        )

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self._get_state_for_groups(groups)

        defer.returnValue(group_to_state)

    @defer.inlineCallbacks
    def get_state_ids_for_group(self, state_group):
        """Get the event IDs of all the state in the given state group

        Args:
            state_group (int)

        Returns:
            Deferred[dict]: Resolves to a map of (type, state_key) -> event_id
        """
        group_to_state = yield self._get_state_for_groups((state_group,))

        defer.returnValue(group_to_state[state_group])

    @defer.inlineCallbacks
    def get_state_groups(self, room_id, event_ids):
        """ Get the state groups for the given list of event_ids

        Returns:
            Deferred[dict[int, list[EventBase]]]:
                dict of state_group_id -> list of state events.
        """
        if not event_ids:
            defer.returnValue({})

        group_to_ids = yield self.get_state_groups_ids(room_id, event_ids)

        state_event_map = yield self.get_events(
            [
                ev_id for group_ids in itervalues(group_to_ids)
                for ev_id in itervalues(group_ids)
            ],
            get_prev_content=False
        )

        defer.returnValue({
            group: [
                state_event_map[v] for v in itervalues(event_id_map)
                if v in state_event_map
            ]
            for group, event_id_map in iteritems(group_to_ids)
        })

    @defer.inlineCallbacks
    def _get_state_groups_from_groups(self, groups, types, members=None):
        """Returns the state groups for a given set of groups, filtering on
        types of state events.

        Args:
            groups(list[int]): list of state group IDs to query
            types (Iterable[str, str|None]|None): list of 2-tuples of the form
                (`type`, `state_key`), where a `state_key` of `None` matches all
                state_keys for the `type`. If None, all types are returned.
            members (bool|None): If not None, then, in addition to any filtering
                implied by types, the results are also filtered to only include
                member events (if True), or to exclude member events (if False)

        Returns:
        Returns:
            Deferred[dict[int, dict[tuple[str, str], str]]]:
                dict of state_group_id -> (dict of (type, state_key) -> event id)
        """
        results = {}

        chunks = [groups[i:i + 100] for i in range(0, len(groups), 100)]
        for chunk in chunks:
            res = yield self.runInteraction(
                "_get_state_groups_from_groups",
                self._get_state_groups_from_groups_txn, chunk, types, members,
            )
            results.update(res)

        defer.returnValue(results)

    def _get_state_groups_from_groups_txn(
        self, txn, groups, types=None, members=None,
    ):
        results = {group: {} for group in groups}

        if types is not None:
            types = list(set(types))  # deduplicate types list

        if isinstance(self.database_engine, PostgresEngine):
            # Temporarily disable sequential scans in this transaction. This is
            # a temporary hack until we can add the right indices in
            txn.execute("SET LOCAL enable_seqscan=off")

            # The below query walks the state_group tree so that the "state"
            # table includes all state_groups in the tree. It then joins
            # against `state_groups_state` to fetch the latest state.
            # It assumes that previous state groups are always numerically
            # lesser.
            # The PARTITION is used to get the event_id in the greatest state
            # group for the given type, state_key.
            # This may return multiple rows per (type, state_key), but last_value
            # should be the same.
            sql = ("""
                WITH RECURSIVE state(state_group) AS (
                    VALUES(?::bigint)
                    UNION ALL
                    SELECT prev_state_group FROM state_group_edges e, state s
                    WHERE s.state_group = e.state_group
                )
                SELECT type, state_key, last_value(event_id) OVER (
                    PARTITION BY type, state_key ORDER BY state_group ASC
                    ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                ) AS event_id FROM state_groups_state
                WHERE state_group IN (
                    SELECT state_group FROM state
                )
                %s
            """)

            if members is True:
                sql += " AND type = '%s'" % (EventTypes.Member,)
            elif members is False:
                sql += " AND type <> '%s'" % (EventTypes.Member,)

            # Turns out that postgres doesn't like doing a list of OR's and
            # is about 1000x slower, so we just issue a query for each specific
            # type seperately.
            if types is not None:
                clause_to_args = [
                    (
                        "AND type = ? AND state_key = ?",
                        (etype, state_key)
                    ) if state_key is not None else (
                        "AND type = ?",
                        (etype,)
                    )
                    for etype, state_key in types
                ]
            else:
                # If types is None we fetch all the state, and so just use an
                # empty where clause with no extra args.
                clause_to_args = [("", [])]

            for where_clause, where_args in clause_to_args:
                for group in groups:
                    args = [group]
                    args.extend(where_args)

                    txn.execute(sql % (where_clause,), args)
                    for row in txn:
                        typ, state_key, event_id = row
                        key = (typ, state_key)
                        results[group][key] = event_id
        else:
            where_args = []
            where_clauses = []
            wildcard_types = False
            if types is not None:
                for typ in types:
                    if typ[1] is None:
                        where_clauses.append("(type = ?)")
                        where_args.append(typ[0])
                        wildcard_types = True
                    else:
                        where_clauses.append("(type = ? AND state_key = ?)")
                        where_args.extend([typ[0], typ[1]])

                where_clause = "AND (%s)" % (" OR ".join(where_clauses))
            else:
                where_clause = ""

            if members is True:
                where_clause += " AND type = '%s'" % EventTypes.Member
            elif members is False:
                where_clause += " AND type <> '%s'" % EventTypes.Member

            # We don't use WITH RECURSIVE on sqlite3 as there are distributions
            # that ship with an sqlite3 version that doesn't support it (e.g. wheezy)
            for group in groups:
                next_group = group

                while next_group:
                    # We did this before by getting the list of group ids, and
                    # then passing that list to sqlite to get latest event for
                    # each (type, state_key). However, that was terribly slow
                    # without the right indices (which we can't add until
                    # after we finish deduping state, which requires this func)
                    args = [next_group]
                    if types:
                        args.extend(where_args)

                    txn.execute(
                        "SELECT type, state_key, event_id FROM state_groups_state"
                        " WHERE state_group = ? %s" % (where_clause,),
                        args
                    )
                    results[group].update(
                        ((typ, state_key), event_id)
                        for typ, state_key, event_id in txn
                        if (typ, state_key) not in results[group]
                    )

                    # If the number of entries in the (type,state_key)->event_id dict
                    # matches the number of (type,state_keys) types we were searching
                    # for, then we must have found them all, so no need to go walk
                    # further down the tree... UNLESS our types filter contained
                    # wildcards (i.e. Nones) in which case we have to do an exhaustive
                    # search
                    if (
                        types is not None and
                        not wildcard_types and
                        len(results[group]) == len(types)
                    ):
                        break

                    next_group = self._simple_select_one_onecol_txn(
                        txn,
                        table="state_group_edges",
                        keyvalues={"state_group": next_group},
                        retcol="prev_state_group",
                        allow_none=True,
                    )

        return results

    @defer.inlineCallbacks
    def get_state_for_events(self, event_ids, types, filtered_types=None):
        """Given a list of event_ids and type tuples, return a list of state
        dicts for each event. The state dicts will only have the type/state_keys
        that are in the `types` list.

        Args:
            event_ids (list[string])
            types (list[(str, str|None)]|None): List of (type, state_key) tuples
                which are used to filter the state fetched. If `state_key` is None,
                all events are returned of the given type.
                May be None, which matches any key.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            deferred: A dict of (event_id) -> (type, state_key) -> [state_events]
        """
        event_to_groups = yield self._get_state_group_for_events(
            event_ids,
        )

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self._get_state_for_groups(groups, types, filtered_types)

        state_event_map = yield self.get_events(
            [ev_id for sd in itervalues(group_to_state) for ev_id in itervalues(sd)],
            get_prev_content=False
        )

        event_to_state = {
            event_id: {
                k: state_event_map[v]
                for k, v in iteritems(group_to_state[group])
                if v in state_event_map
            }
            for event_id, group in iteritems(event_to_groups)
        }

        defer.returnValue({event: event_to_state[event] for event in event_ids})

    @defer.inlineCallbacks
    def get_state_ids_for_events(self, event_ids, types=None, filtered_types=None):
        """
        Get the state dicts corresponding to a list of events, containing the event_ids
        of the state events (as opposed to the events themselves)

        Args:
            event_ids(list(str)): events whose state should be returned
            types(list[(str, str|None)]|None): List of (type, state_key) tuples
                which are used to filter the state fetched. If `state_key` is None,
                all events are returned of the given type.
                May be None, which matches any key.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            A deferred dict from event_id -> (type, state_key) -> event_id
        """
        event_to_groups = yield self._get_state_group_for_events(
            event_ids,
        )

        groups = set(itervalues(event_to_groups))
        group_to_state = yield self._get_state_for_groups(groups, types, filtered_types)

        event_to_state = {
            event_id: group_to_state[group]
            for event_id, group in iteritems(event_to_groups)
        }

        defer.returnValue({event: event_to_state[event] for event in event_ids})

    @defer.inlineCallbacks
    def get_state_for_event(self, event_id, types=None, filtered_types=None):
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id(str): event whose state should be returned
            types(list[(str, str|None)]|None): List of (type, state_key) tuples
                which are used to filter the state fetched. If `state_key` is None,
                all events are returned of the given type.
                May be None, which matches any key.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            A deferred dict from (type, state_key) -> state_event
        """
        state_map = yield self.get_state_for_events([event_id], types, filtered_types)
        defer.returnValue(state_map[event_id])

    @defer.inlineCallbacks
    def get_state_ids_for_event(self, event_id, types=None, filtered_types=None):
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id(str): event whose state should be returned
            types(list[(str, str|None)]|None): List of (type, state_key) tuples
                which are used to filter the state fetched. If `state_key` is None,
                all events are returned of the given type.
                May be None, which matches any key.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            A deferred dict from (type, state_key) -> state_event
        """
        state_map = yield self.get_state_ids_for_events([event_id], types, filtered_types)
        defer.returnValue(state_map[event_id])

    @cached(max_entries=50000)
    def _get_state_group_for_event(self, event_id):
        return self._simple_select_one_onecol(
            table="event_to_state_groups",
            keyvalues={
                "event_id": event_id,
            },
            retcol="state_group",
            allow_none=True,
            desc="_get_state_group_for_event",
        )

    @cachedList(cached_method_name="_get_state_group_for_event",
                list_name="event_ids", num_args=1, inlineCallbacks=True)
    def _get_state_group_for_events(self, event_ids):
        """Returns mapping event_id -> state_group
        """
        rows = yield self._simple_select_many_batch(
            table="event_to_state_groups",
            column="event_id",
            iterable=event_ids,
            keyvalues={},
            retcols=("event_id", "state_group",),
            desc="_get_state_group_for_events",
        )

        defer.returnValue({row["event_id"]: row["state_group"] for row in rows})

    def _get_some_state_from_cache(self, cache, group, types, filtered_types=None):
        """Checks if group is in cache. See `_get_state_for_groups`

        Args:
            cache(DictionaryCache): the state group cache to use
            group(int): The state group to lookup
            types(list[str, str|None]): List of 2-tuples of the form
                (`type`, `state_key`), where a `state_key` of `None` matches all
                state_keys for the `type`.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns 2-tuple (`state_dict`, `got_all`).
        `got_all` is a bool indicating if we successfully retrieved all
        requests state from the cache, if False we need to query the DB for the
        missing state.
        """
        is_all, known_absent, state_dict_ids = cache.get(group)

        type_to_key = {}

        # tracks whether any of our requested types are missing from the cache
        missing_types = False

        for typ, state_key in types:
            key = (typ, state_key)

            if (
                state_key is None or
                (filtered_types is not None and typ not in filtered_types)
            ):
                type_to_key[typ] = None
                # we mark the type as missing from the cache because
                # when the cache was populated it might have been done with a
                # restricted set of state_keys, so the wildcard will not work
                # and the cache may be incomplete.
                missing_types = True
            else:
                if type_to_key.get(typ, object()) is not None:
                    type_to_key.setdefault(typ, set()).add(state_key)

                if key not in state_dict_ids and key not in known_absent:
                    missing_types = True

        sentinel = object()

        def include(typ, state_key):
            valid_state_keys = type_to_key.get(typ, sentinel)
            if valid_state_keys is sentinel:
                return filtered_types is not None and typ not in filtered_types
            if valid_state_keys is None:
                return True
            if state_key in valid_state_keys:
                return True
            return False

        got_all = is_all
        if not got_all:
            # the cache is incomplete. We may still have got all the results we need, if
            # we don't have any wildcards in the match list.
            if not missing_types and filtered_types is None:
                got_all = True

        return {
            k: v for k, v in iteritems(state_dict_ids)
            if include(k[0], k[1])
        }, got_all

    def _get_all_state_from_cache(self, cache, group):
        """Checks if group is in cache. See `_get_state_for_groups`

        Returns 2-tuple (`state_dict`, `got_all`). `got_all` is a bool
        indicating if we successfully retrieved all requests state from the
        cache, if False we need to query the DB for the missing state.

        Args:
            cache(DictionaryCache): the state group cache to use
            group: The state group to lookup
        """
        is_all, _, state_dict_ids = cache.get(group)

        return state_dict_ids, is_all

    @defer.inlineCallbacks
    def _get_state_for_groups(self, groups, types=None, filtered_types=None):
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key

        Args:
            groups (iterable[int]): list of state groups for which we want
                to get the state.
            types (None|iterable[(str, None|str)]):
                indicates the state type/keys required. If None, the whole
                state is fetched and returned.

                Otherwise, each entry should be a `(type, state_key)` tuple to
                include in the response. A `state_key` of None is a wildcard
                meaning that we require all state with that type.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            Deferred[dict[int, dict[tuple[str, str], str]]]:
                dict of state_group_id -> (dict of (type, state_key) -> event id)
        """
        if types is not None:
            non_member_types = [t for t in types if t[0] != EventTypes.Member]

            if filtered_types is not None and EventTypes.Member not in filtered_types:
                # we want all of the membership events
                member_types = None
            else:
                member_types = [t for t in types if t[0] == EventTypes.Member]

        else:
            non_member_types = None
            member_types = None

        non_member_state = yield self._get_state_for_groups_using_cache(
            groups, self._state_group_cache, non_member_types, filtered_types,
        )
        # XXX: we could skip this entirely if member_types is []
        member_state = yield self._get_state_for_groups_using_cache(
            # we set filtered_types=None as member_state only ever contain members.
            groups, self._state_group_members_cache, member_types, None,
        )

        state = non_member_state
        for group in groups:
            state[group].update(member_state[group])

        defer.returnValue(state)

    @defer.inlineCallbacks
    def _get_state_for_groups_using_cache(
        self, groups, cache, types=None, filtered_types=None
    ):
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key, querying from a specific cache.

        Args:
            groups (iterable[int]): list of state groups for which we want
                to get the state.
            cache (DictionaryCache): the cache of group ids to state dicts which
                we will pass through - either the normal state cache or the specific
                members state cache.
            types (None|iterable[(str, None|str)]):
                indicates the state type/keys required. If None, the whole
                state is fetched and returned.

                Otherwise, each entry should be a `(type, state_key)` tuple to
                include in the response. A `state_key` of None is a wildcard
                meaning that we require all state with that type.
            filtered_types(list[str]|None): Only apply filtering via `types` to this
                list of event types.  Other types of events are returned unfiltered.
                If None, `types` filtering is applied to all events.

        Returns:
            Deferred[dict[int, dict[tuple[str, str], str]]]:
                dict of state_group_id -> (dict of (type, state_key) -> event id)
        """
        if types:
            types = frozenset(types)
        results = {}
        missing_groups = []
        if types is not None:
            for group in set(groups):
                state_dict_ids, got_all = self._get_some_state_from_cache(
                    cache, group, types, filtered_types
                )
                results[group] = state_dict_ids

                if not got_all:
                    missing_groups.append(group)
        else:
            for group in set(groups):
                state_dict_ids, got_all = self._get_all_state_from_cache(
                    cache, group
                )

                results[group] = state_dict_ids

                if not got_all:
                    missing_groups.append(group)

        if missing_groups:
            # Okay, so we have some missing_types, let's fetch them.
            cache_seq_num = cache.sequence

            # the DictionaryCache knows if it has *all* the state, but
            # does not know if it has all of the keys of a particular type,
            # which makes wildcard lookups expensive unless we have a complete
            # cache. Hence, if we are doing a wildcard lookup, populate the
            # cache fully so that we can do an efficient lookup next time.

            if filtered_types or (types and any(k is None for (t, k) in types)):
                types_to_fetch = None
            else:
                types_to_fetch = types

            group_to_state_dict = yield self._get_state_groups_from_groups(
                missing_groups, types_to_fetch, cache == self._state_group_members_cache,
            )

            for group, group_state_dict in iteritems(group_to_state_dict):
                state_dict = results[group]

                # update the result, filtering by `types`.
                if types:
                    for k, v in iteritems(group_state_dict):
                        (typ, _) = k
                        if (
                            (k in types or (typ, None) in types) or
                            (filtered_types and typ not in filtered_types)
                        ):
                            state_dict[k] = v
                else:
                    state_dict.update(group_state_dict)

                # update the cache with all the things we fetched from the
                # database.
                cache.update(
                    cache_seq_num,
                    key=group,
                    value=group_state_dict,
                    fetched_keys=types_to_fetch,
                )

        defer.returnValue(results)

    def store_state_group(self, event_id, room_id, prev_group, delta_ids,
                          current_state_ids):
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
        def _store_state_group_txn(txn):
            if current_state_ids is None:
                # AFAIK, this can never happen
                raise Exception("current_state_ids cannot be None")

            state_group = self.database_engine.get_next_state_group_id(txn)

            self._simple_insert_txn(
                txn,
                table="state_groups",
                values={
                    "id": state_group,
                    "room_id": room_id,
                    "event_id": event_id,
                },
            )

            # We persist as a delta if we can, while also ensuring the chain
            # of deltas isn't tooo long, as otherwise read performance degrades.
            if prev_group:
                is_in_db = self._simple_select_one_onecol_txn(
                    txn,
                    table="state_groups",
                    keyvalues={"id": prev_group},
                    retcol="id",
                    allow_none=True,
                )
                if not is_in_db:
                    raise Exception(
                        "Trying to persist state with unpersisted prev_group: %r"
                        % (prev_group,)
                    )

                potential_hops = self._count_state_group_hops_txn(
                    txn, prev_group
                )
            if prev_group and potential_hops < MAX_STATE_DELTA_HOPS:
                self._simple_insert_txn(
                    txn,
                    table="state_group_edges",
                    values={
                        "state_group": state_group,
                        "prev_state_group": prev_group,
                    },
                )

                self._simple_insert_many_txn(
                    txn,
                    table="state_groups_state",
                    values=[
                        {
                            "state_group": state_group,
                            "room_id": room_id,
                            "type": key[0],
                            "state_key": key[1],
                            "event_id": state_id,
                        }
                        for key, state_id in iteritems(delta_ids)
                    ],
                )
            else:
                self._simple_insert_many_txn(
                    txn,
                    table="state_groups_state",
                    values=[
                        {
                            "state_group": state_group,
                            "room_id": room_id,
                            "type": key[0],
                            "state_key": key[1],
                            "event_id": state_id,
                        }
                        for key, state_id in iteritems(current_state_ids)
                    ],
                )

            # Prefill the state group caches with this group.
            # It's fine to use the sequence like this as the state group map
            # is immutable. (If the map wasn't immutable then this prefill could
            # race with another update)

            current_member_state_ids = {
                s: ev
                for (s, ev) in iteritems(current_state_ids)
                if s[0] == EventTypes.Member
            }
            txn.call_after(
                self._state_group_members_cache.update,
                self._state_group_members_cache.sequence,
                key=state_group,
                value=dict(current_member_state_ids),
            )

            current_non_member_state_ids = {
                s: ev
                for (s, ev) in iteritems(current_state_ids)
                if s[0] != EventTypes.Member
            }
            txn.call_after(
                self._state_group_cache.update,
                self._state_group_cache.sequence,
                key=state_group,
                value=dict(current_non_member_state_ids),
            )

            return state_group

        return self.runInteraction("store_state_group", _store_state_group_txn)

    def _count_state_group_hops_txn(self, txn, state_group):
        """Given a state group, count how many hops there are in the tree.

        This is used to ensure the delta chains don't get too long.
        """
        if isinstance(self.database_engine, PostgresEngine):
            sql = ("""
                WITH RECURSIVE state(state_group) AS (
                    VALUES(?::bigint)
                    UNION ALL
                    SELECT prev_state_group FROM state_group_edges e, state s
                    WHERE s.state_group = e.state_group
                )
                SELECT count(*) FROM state;
            """)

            txn.execute(sql, (state_group,))
            row = txn.fetchone()
            if row and row[0]:
                return row[0]
            else:
                return 0
        else:
            # We don't use WITH RECURSIVE on sqlite3 as there are distributions
            # that ship with an sqlite3 version that doesn't support it (e.g. wheezy)
            next_group = state_group
            count = 0

            while next_group:
                next_group = self._simple_select_one_onecol_txn(
                    txn,
                    table="state_group_edges",
                    keyvalues={"state_group": next_group},
                    retcol="prev_state_group",
                    allow_none=True,
                )
                if next_group:
                    count += 1

            return count


class StateStore(StateGroupWorkerStore, BackgroundUpdateStore):
    """ Keeps track of the state at a given event.

    This is done by the concept of `state groups`. Every event is a assigned
    a state group (identified by an arbitrary string), which references a
    collection of state events. The current state of an event is then the
    collection of state events referenced by the event's state group.

    Hence, every change in the current state causes a new state group to be
    generated. However, if no change happens (e.g., if we get a message event
    with only one parent it inherits the state group from its parent.)

    There are three tables:
      * `state_groups`: Stores group name, first event with in the group and
        room id.
      * `event_to_state_groups`: Maps events to state groups.
      * `state_groups_state`: Maps state group to state events.
    """

    STATE_GROUP_DEDUPLICATION_UPDATE_NAME = "state_group_state_deduplication"
    STATE_GROUP_INDEX_UPDATE_NAME = "state_group_state_type_index"
    CURRENT_STATE_INDEX_UPDATE_NAME = "current_state_members_idx"

    def __init__(self, db_conn, hs):
        super(StateStore, self).__init__(db_conn, hs)
        self.register_background_update_handler(
            self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME,
            self._background_deduplicate_state,
        )
        self.register_background_update_handler(
            self.STATE_GROUP_INDEX_UPDATE_NAME,
            self._background_index_state,
        )
        self.register_background_index_update(
            self.CURRENT_STATE_INDEX_UPDATE_NAME,
            index_name="current_state_events_member_index",
            table="current_state_events",
            columns=["state_key"],
            where_clause="type='m.room.member'",
        )

    def _store_event_state_mappings_txn(self, txn, events_and_contexts):
        state_groups = {}
        for event, context in events_and_contexts:
            if event.internal_metadata.is_outlier():
                continue

            # if the event was rejected, just give it the same state as its
            # predecessor.
            if context.rejected:
                state_groups[event.event_id] = context.prev_group
                continue

            state_groups[event.event_id] = context.state_group

        self._simple_insert_many_txn(
            txn,
            table="event_to_state_groups",
            values=[
                {
                    "state_group": state_group_id,
                    "event_id": event_id,
                }
                for event_id, state_group_id in iteritems(state_groups)
            ],
        )

        for event_id, state_group_id in iteritems(state_groups):
            txn.call_after(
                self._get_state_group_for_event.prefill,
                (event_id,), state_group_id
            )

    @defer.inlineCallbacks
    def _background_deduplicate_state(self, progress, batch_size):
        """This background update will slowly deduplicate state by reencoding
        them as deltas.
        """
        last_state_group = progress.get("last_state_group", 0)
        rows_inserted = progress.get("rows_inserted", 0)
        max_group = progress.get("max_group", None)

        BATCH_SIZE_SCALE_FACTOR = 100

        batch_size = max(1, int(batch_size / BATCH_SIZE_SCALE_FACTOR))

        if max_group is None:
            rows = yield self._execute(
                "_background_deduplicate_state", None,
                "SELECT coalesce(max(id), 0) FROM state_groups",
            )
            max_group = rows[0][0]

        def reindex_txn(txn):
            new_last_state_group = last_state_group
            for count in range(batch_size):
                txn.execute(
                    "SELECT id, room_id FROM state_groups"
                    " WHERE ? < id AND id <= ?"
                    " ORDER BY id ASC"
                    " LIMIT 1",
                    (new_last_state_group, max_group,)
                )
                row = txn.fetchone()
                if row:
                    state_group, room_id = row

                if not row or not state_group:
                    return True, count

                txn.execute(
                    "SELECT state_group FROM state_group_edges"
                    " WHERE state_group = ?",
                    (state_group,)
                )

                # If we reach a point where we've already started inserting
                # edges we should stop.
                if txn.fetchall():
                    return True, count

                txn.execute(
                    "SELECT coalesce(max(id), 0) FROM state_groups"
                    " WHERE id < ? AND room_id = ?",
                    (state_group, room_id,)
                )
                prev_group, = txn.fetchone()
                new_last_state_group = state_group

                if prev_group:
                    potential_hops = self._count_state_group_hops_txn(
                        txn, prev_group
                    )
                    if potential_hops >= MAX_STATE_DELTA_HOPS:
                        # We want to ensure chains are at most this long,#
                        # otherwise read performance degrades.
                        continue

                    prev_state = self._get_state_groups_from_groups_txn(
                        txn, [prev_group], types=None
                    )
                    prev_state = prev_state[prev_group]

                    curr_state = self._get_state_groups_from_groups_txn(
                        txn, [state_group], types=None
                    )
                    curr_state = curr_state[state_group]

                    if not set(prev_state.keys()) - set(curr_state.keys()):
                        # We can only do a delta if the current has a strict super set
                        # of keys

                        delta_state = {
                            key: value for key, value in iteritems(curr_state)
                            if prev_state.get(key, None) != value
                        }

                        self._simple_delete_txn(
                            txn,
                            table="state_group_edges",
                            keyvalues={
                                "state_group": state_group,
                            }
                        )

                        self._simple_insert_txn(
                            txn,
                            table="state_group_edges",
                            values={
                                "state_group": state_group,
                                "prev_state_group": prev_group,
                            }
                        )

                        self._simple_delete_txn(
                            txn,
                            table="state_groups_state",
                            keyvalues={
                                "state_group": state_group,
                            }
                        )

                        self._simple_insert_many_txn(
                            txn,
                            table="state_groups_state",
                            values=[
                                {
                                    "state_group": state_group,
                                    "room_id": room_id,
                                    "type": key[0],
                                    "state_key": key[1],
                                    "event_id": state_id,
                                }
                                for key, state_id in iteritems(delta_state)
                            ],
                        )

            progress = {
                "last_state_group": state_group,
                "rows_inserted": rows_inserted + batch_size,
                "max_group": max_group,
            }

            self._background_update_progress_txn(
                txn, self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME, progress
            )

            return False, batch_size

        finished, result = yield self.runInteraction(
            self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME, reindex_txn
        )

        if finished:
            yield self._end_background_update(self.STATE_GROUP_DEDUPLICATION_UPDATE_NAME)

        defer.returnValue(result * BATCH_SIZE_SCALE_FACTOR)

    @defer.inlineCallbacks
    def _background_index_state(self, progress, batch_size):
        def reindex_txn(conn):
            conn.rollback()
            if isinstance(self.database_engine, PostgresEngine):
                # postgres insists on autocommit for the index
                conn.set_session(autocommit=True)
                try:
                    txn = conn.cursor()
                    txn.execute(
                        "CREATE INDEX CONCURRENTLY state_groups_state_type_idx"
                        " ON state_groups_state(state_group, type, state_key)"
                    )
                    txn.execute(
                        "DROP INDEX IF EXISTS state_groups_state_id"
                    )
                finally:
                    conn.set_session(autocommit=False)
            else:
                txn = conn.cursor()
                txn.execute(
                    "CREATE INDEX state_groups_state_type_idx"
                    " ON state_groups_state(state_group, type, state_key)"
                )
                txn.execute(
                    "DROP INDEX IF EXISTS state_groups_state_id"
                )

        yield self.runWithConnection(reindex_txn)

        yield self._end_background_update(self.STATE_GROUP_INDEX_UPDATE_NAME)

        defer.returnValue(1)
