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

from ._base import SQLBaseStore
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.caches import intern_string

from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class StateStore(SQLBaseStore):
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

    @defer.inlineCallbacks
    def get_state_groups(self, room_id, event_ids):
        """ Get the state groups for the given list of event_ids

        The return value is a dict mapping group names to lists of events.
        """
        if not event_ids:
            defer.returnValue({})

        event_to_groups = yield self._get_state_group_for_events(
            event_ids,
        )

        groups = set(event_to_groups.values())
        group_to_state = yield self._get_state_for_groups(groups)

        defer.returnValue({
            group: state_map.values()
            for group, state_map in group_to_state.items()
        })

    def _store_mult_state_groups_txn(self, txn, events_and_contexts):
        state_groups = {}
        for event, context in events_and_contexts:
            if event.internal_metadata.is_outlier():
                continue

            if context.current_state is None:
                continue

            if context.state_group is not None:
                state_groups[event.event_id] = context.state_group
                continue

            state_events = dict(context.current_state)

            if event.is_state():
                state_events[(event.type, event.state_key)] = event

            state_group = context.new_state_group_id

            self._simple_insert_txn(
                txn,
                table="state_groups",
                values={
                    "id": state_group,
                    "room_id": event.room_id,
                    "event_id": event.event_id,
                },
            )

            self._simple_insert_many_txn(
                txn,
                table="state_groups_state",
                values=[
                    {
                        "state_group": state_group,
                        "room_id": state.room_id,
                        "type": state.type,
                        "state_key": state.state_key,
                        "event_id": state.event_id,
                    }
                    for state in state_events.values()
                ],
            )
            state_groups[event.event_id] = state_group

        self._simple_insert_many_txn(
            txn,
            table="event_to_state_groups",
            values=[
                {
                    "state_group": state_group_id,
                    "event_id": event_id,
                }
                for event_id, state_group_id in state_groups.items()
            ],
        )

    @defer.inlineCallbacks
    def get_current_state(self, room_id, event_type=None, state_key=""):
        if event_type and state_key is not None:
            result = yield self.get_current_state_for_key(
                room_id, event_type, state_key
            )
            defer.returnValue(result)

        def f(txn):
            sql = (
                "SELECT event_id FROM current_state_events"
                " WHERE room_id = ? "
            )

            if event_type and state_key is not None:
                sql += " AND type = ? AND state_key = ? "
                args = (room_id, event_type, state_key)
            elif event_type:
                sql += " AND type = ?"
                args = (room_id, event_type)
            else:
                args = (room_id, )

            txn.execute(sql, args)
            results = txn.fetchall()

            return [r[0] for r in results]

        event_ids = yield self.runInteraction("get_current_state", f)
        events = yield self._get_events(event_ids, get_prev_content=False)
        defer.returnValue(events)

    @defer.inlineCallbacks
    def get_current_state_for_key(self, room_id, event_type, state_key):
        event_ids = yield self._get_current_state_for_key(room_id, event_type, state_key)
        events = yield self._get_events(event_ids, get_prev_content=False)
        defer.returnValue(events)

    @cached(num_args=3)
    def _get_current_state_for_key(self, room_id, event_type, state_key):
        def f(txn):
            sql = (
                "SELECT event_id FROM current_state_events"
                " WHERE room_id = ? AND type = ? AND state_key = ?"
            )

            args = (room_id, event_type, state_key)
            txn.execute(sql, args)
            results = txn.fetchall()
            return [r[0] for r in results]
        return self.runInteraction("get_current_state_for_key", f)

    @cached(num_args=2, lru=True, max_entries=1000)
    def _get_state_group_from_group(self, group, types):
        raise NotImplementedError()

    @cachedList(cached_method_name="_get_state_group_from_group",
                list_name="groups", num_args=2, inlineCallbacks=True)
    def _get_state_groups_from_groups(self, groups, types):
        """Returns dictionary state_group -> (dict of (type, state_key) -> event id)
        """
        def f(txn, groups):
            if types is not None:
                where_clause = "AND (%s)" % (
                    " OR ".join(["(type = ? AND state_key = ?)"] * len(types)),
                )
            else:
                where_clause = ""

            sql = (
                "SELECT state_group, event_id, type, state_key"
                " FROM state_groups_state WHERE"
                " state_group IN (%s) %s" % (
                    ",".join("?" for _ in groups),
                    where_clause,
                )
            )

            args = list(groups)
            if types is not None:
                args.extend([i for typ in types for i in typ])

            txn.execute(sql, args)
            rows = self.cursor_to_dict(txn)

            results = {group: {} for group in groups}
            for row in rows:
                key = (row["type"], row["state_key"])
                results[row["state_group"]][key] = row["event_id"]
            return results

        results = {}

        chunks = [groups[i:i + 100] for i in xrange(0, len(groups), 100)]
        for chunk in chunks:
            res = yield self.runInteraction(
                "_get_state_groups_from_groups",
                f, chunk
            )
            results.update(res)

        defer.returnValue(results)

    @defer.inlineCallbacks
    def get_state_for_events(self, event_ids, types):
        """Given a list of event_ids and type tuples, return a list of state
        dicts for each event. The state dicts will only have the type/state_keys
        that are in the `types` list.

        Args:
            event_ids (list)
            types (list): List of (type, state_key) tuples which are used to
                filter the state fetched. `state_key` may be None, which matches
                any `state_key`

        Returns:
            deferred: A list of dicts corresponding to the event_ids given.
            The dicts are mappings from (type, state_key) -> state_events
        """
        event_to_groups = yield self._get_state_group_for_events(
            event_ids,
        )

        groups = set(event_to_groups.values())
        group_to_state = yield self._get_state_for_groups(groups, types)

        event_to_state = {
            event_id: group_to_state[group]
            for event_id, group in event_to_groups.items()
        }

        defer.returnValue({event: event_to_state[event] for event in event_ids})

    @defer.inlineCallbacks
    def get_state_for_event(self, event_id, types=None):
        """
        Get the state dict corresponding to a particular event

        Args:
            event_id(str): event whose state should be returned
            types(list[(str, str)]|None): List of (type, state_key) tuples
                which are used to filter the state fetched. May be None, which
                matches any key

        Returns:
            A deferred dict from (type, state_key) -> state_event
        """
        state_map = yield self.get_state_for_events([event_id], types)
        defer.returnValue(state_map[event_id])

    @cached(num_args=2, lru=True, max_entries=10000)
    def _get_state_group_for_event(self, room_id, event_id):
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

    def _get_some_state_from_cache(self, group, types):
        """Checks if group is in cache. See `_get_state_for_groups`

        Returns 3-tuple (`state_dict`, `missing_types`, `got_all`).
        `missing_types` is the list of types that aren't in the cache for that
        group. `got_all` is a bool indicating if we successfully retrieved all
        requests state from the cache, if False we need to query the DB for the
        missing state.

        Args:
            group: The state group to lookup
            types (list): List of 2-tuples of the form (`type`, `state_key`),
                where a `state_key` of `None` matches all state_keys for the
                `type`.
        """
        is_all, state_dict_ids = self._state_group_cache.get(group)

        type_to_key = {}
        missing_types = set()
        for typ, state_key in types:
            if state_key is None:
                type_to_key[typ] = None
                missing_types.add((typ, state_key))
            else:
                if type_to_key.get(typ, object()) is not None:
                    type_to_key.setdefault(typ, set()).add(state_key)

                if (typ, state_key) not in state_dict_ids:
                    missing_types.add((typ, state_key))

        sentinel = object()

        def include(typ, state_key):
            valid_state_keys = type_to_key.get(typ, sentinel)
            if valid_state_keys is sentinel:
                return False
            if valid_state_keys is None:
                return True
            if state_key in valid_state_keys:
                return True
            return False

        got_all = not (missing_types or types is None)

        return {
            k: v for k, v in state_dict_ids.items()
            if include(k[0], k[1])
        }, missing_types, got_all

    def _get_all_state_from_cache(self, group):
        """Checks if group is in cache. See `_get_state_for_groups`

        Returns 2-tuple (`state_dict`, `got_all`). `got_all` is a bool
        indicating if we successfully retrieved all requests state from the
        cache, if False we need to query the DB for the missing state.

        Args:
            group: The state group to lookup
        """
        is_all, state_dict_ids = self._state_group_cache.get(group)

        return state_dict_ids, is_all

    @defer.inlineCallbacks
    def _get_state_for_groups(self, groups, types=None):
        """Given list of groups returns dict of group -> list of state events
        with matching types. `types` is a list of `(type, state_key)`, where
        a `state_key` of None matches all state_keys. If `types` is None then
        all events are returned.
        """
        if types:
            types = frozenset(types)
        results = {}
        missing_groups = []
        if types is not None:
            for group in set(groups):
                state_dict_ids, missing_types, got_all = self._get_some_state_from_cache(
                    group, types
                )
                results[group] = state_dict_ids

                if not got_all:
                    missing_groups.append(group)
        else:
            for group in set(groups):
                state_dict_ids, got_all = self._get_all_state_from_cache(
                    group
                )

                results[group] = state_dict_ids

                if not got_all:
                    missing_groups.append(group)

        if missing_groups:
            # Okay, so we have some missing_types, lets fetch them.
            cache_seq_num = self._state_group_cache.sequence

            group_to_state_dict = yield self._get_state_groups_from_groups(
                missing_groups, types
            )

            # Now we want to update the cache with all the things we fetched
            # from the database.
            for group, group_state_dict in group_to_state_dict.items():
                if types:
                    # We delibrately put key -> None mappings into the cache to
                    # cache absence of the key, on the assumption that if we've
                    # explicitly asked for some types then we will probably ask
                    # for them again.
                    state_dict = {
                        (intern_string(etype), intern_string(state_key)): None
                        for (etype, state_key) in types
                    }
                    state_dict.update(results[group])
                    results[group] = state_dict
                else:
                    state_dict = results[group]

                state_dict.update(group_state_dict)

                self._state_group_cache.update(
                    cache_seq_num,
                    key=group,
                    value=state_dict,
                    full=(types is None),
                )

        state_events = yield self._get_events(
            [ev_id for sd in results.values() for ev_id in sd.values()],
            get_prev_content=False
        )

        state_events = {e.event_id: e for e in state_events}

        # Remove all the entries with None values. The None values were just
        # used for bookkeeping in the cache.
        for group, state_dict in results.items():
            results[group] = {
                key: state_events[event_id]
                for key, event_id in state_dict.items()
                if event_id and event_id in state_events
            }

        defer.returnValue(results)

    def get_all_new_state_groups(self, last_id, current_id, limit):
        def get_all_new_state_groups_txn(txn):
            sql = (
                "SELECT id, room_id, event_id FROM state_groups"
                " WHERE ? < id AND id <= ? ORDER BY id LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            groups = txn.fetchall()

            if not groups:
                return ([], [])

            lower_bound = groups[0][0]
            upper_bound = groups[-1][0]
            sql = (
                "SELECT state_group, type, state_key, event_id"
                " FROM state_groups_state"
                " WHERE ? <= state_group AND state_group <= ?"
            )

            txn.execute(sql, (lower_bound, upper_bound))
            state_group_state = txn.fetchall()
            return (groups, state_group_state)
        return self.runInteraction(
            "get_all_new_state_groups", get_all_new_state_groups_txn
        )

    def get_state_stream_token(self):
        return self._state_groups_id_gen.get_current_token()
