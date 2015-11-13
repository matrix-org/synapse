# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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
from synapse.util.caches.descriptors import (
    cached, cachedInlineCallbacks, cachedList
)

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

    def _store_state_groups_txn(self, txn, event, context):
        return self._store_mult_state_groups_txn(txn, [(event, context)])

    def _store_mult_state_groups_txn(self, txn, events_and_contexts):
        state_groups = {}
        for event, context in events_and_contexts:
            if context.current_state is None:
                continue

            if context.state_group is not None:
                state_groups[event.event_id] = context.state_group
                continue

            state_events = dict(context.current_state)

            if event.is_state():
                state_events[(event.type, event.state_key)] = event

            state_group = self._state_groups_id_gen.get_next_txn(txn)
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
                    "state_group": state_groups[event.event_id],
                    "event_id": event.event_id,
                }
                for event, context in events_and_contexts
                if context.current_state is not None
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

    @cachedInlineCallbacks(num_args=3)
    def get_current_state_for_key(self, room_id, event_type, state_key):
        def f(txn):
            sql = (
                "SELECT event_id FROM current_state_events"
                " WHERE room_id = ? AND type = ? AND state_key = ?"
            )

            args = (room_id, event_type, state_key)
            txn.execute(sql, args)
            results = txn.fetchall()
            return [r[0] for r in results]
        event_ids = yield self.runInteraction("get_current_state_for_key", f)
        events = yield self._get_events(event_ids, get_prev_content=False)
        defer.returnValue(events)

    def _get_state_groups_from_groups(self, groups_and_types):
        """Returns dictionary state_group -> state event ids

        Args:
            groups_and_types (list): list of 2-tuple (`group`, `types`)
        """
        def f(txn):
            results = {}
            for group, types in groups_and_types:
                if types is not None:
                    where_clause = "AND (%s)" % (
                        " OR ".join(["(type = ? AND state_key = ?)"] * len(types)),
                    )
                else:
                    where_clause = ""

                sql = (
                    "SELECT event_id FROM state_groups_state WHERE"
                    " state_group = ? %s"
                ) % (where_clause,)

                args = [group]
                if types is not None:
                    args.extend([i for typ in types for i in typ])

                txn.execute(sql, args)

                results[group] = [r[0] for r in txn.fetchall()]

            return results

        return self.runInteraction(
            "_get_state_groups_from_groups",
            f,
        )

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

        :param str event_id: event whose state should be returned
        :param list[(str, str)]|None types: List of (type, state_key) tuples
            which are used to filter the state fetched. May be None, which
            matches any key
        :return: a deferred dict from (type, state_key) -> state_event
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

    @cachedList(cache=_get_state_group_for_event.cache, list_name="event_ids",
                num_args=1)
    def _get_state_group_for_events(self, event_ids):
        """Returns mapping event_id -> state_group
        """
        def f(txn):
            results = {}
            for event_id in event_ids:
                results[event_id] = self._simple_select_one_onecol_txn(
                    txn,
                    table="event_to_state_groups",
                    keyvalues={
                        "event_id": event_id,
                    },
                    retcol="state_group",
                    allow_none=True,
                )

            return results

        return self.runInteraction("_get_state_group_for_events", f)

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
        is_all, state_dict = self._state_group_cache.get(group)

        type_to_key = {}
        missing_types = set()
        for typ, state_key in types:
            if state_key is None:
                type_to_key[typ] = None
                missing_types.add((typ, state_key))
            else:
                if type_to_key.get(typ, object()) is not None:
                    type_to_key.setdefault(typ, set()).add(state_key)

                if (typ, state_key) not in state_dict:
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
            k: v for k, v in state_dict.items()
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
        is_all, state_dict = self._state_group_cache.get(group)
        return state_dict, is_all

    @defer.inlineCallbacks
    def _get_state_for_groups(self, groups, types=None):
        """Given list of groups returns dict of group -> list of state events
        with matching types. `types` is a list of `(type, state_key)`, where
        a `state_key` of None matches all state_keys. If `types` is None then
        all events are returned.
        """
        results = {}
        missing_groups_and_types = []
        if types is not None:
            for group in set(groups):
                state_dict, missing_types, got_all = self._get_some_state_from_cache(
                    group, types
                )
                results[group] = state_dict

                if not got_all:
                    missing_groups_and_types.append((group, missing_types))
        else:
            for group in set(groups):
                state_dict, got_all = self._get_all_state_from_cache(
                    group
                )
                results[group] = state_dict

                if not got_all:
                    missing_groups_and_types.append((group, None))

        if not missing_groups_and_types:
            defer.returnValue({
                group: {
                    type_tuple: event
                    for type_tuple, event in state.items()
                    if event
                }
                for group, state in results.items()
            })

        # Okay, so we have some missing_types, lets fetch them.
        cache_seq_num = self._state_group_cache.sequence

        group_state_dict = yield self._get_state_groups_from_groups(
            missing_groups_and_types
        )

        state_events = yield self._get_events(
            [e_id for l in group_state_dict.values() for e_id in l],
            get_prev_content=False
        )

        state_events = {e.event_id: e for e in state_events}

        # Now we want to update the cache with all the things we fetched
        # from the database.
        for group, state_ids in group_state_dict.items():
            if types:
                # We delibrately put key -> None mappings into the cache to
                # cache absence of the key, on the assumption that if we've
                # explicitly asked for some types then we will probably ask
                # for them again.
                state_dict = {key: None for key in types}
                state_dict.update(results[group])
                results[group] = state_dict
            else:
                state_dict = results[group]

            for event_id in state_ids:
                try:
                    state_event = state_events[event_id]
                    state_dict[(state_event.type, state_event.state_key)] = state_event
                except KeyError:
                    # Hmm. So we do don't have that state event? Interesting.
                    logger.warn(
                        "Can't find state event %r for state group %r",
                        event_id, group,
                    )

            self._state_group_cache.update(
                cache_seq_num,
                key=group,
                value=state_dict,
                full=(types is None),
            )

        # Remove all the entries with None values. The None values were just
        # used for bookkeeping in the cache.
        for group, state_dict in results.items():
            results[group] = {
                key: event for key, event in state_dict.items() if event
            }

        defer.returnValue(results)
