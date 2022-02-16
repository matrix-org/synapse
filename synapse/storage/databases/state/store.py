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
    Collection,
    Dict,
    Iterable,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import attr

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.logging.context import make_deferred_yieldable, run_in_background
from synapse.storage._base import SQLBaseStore
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.state.bg_updates import StateBackgroundUpdateStore
from synapse.storage.state import StateFilter
from synapse.storage.types import Cursor
from synapse.storage.util.sequence import build_sequence_generator
from synapse.types import MutableStateMap, StateKey, StateMap
from synapse.util import unwrapFirstError
from synapse.util.async_helpers import (
    AbstractObservableDeferred,
    ObservableDeferred,
    yieldable_gather_results,
)
from synapse.util.caches.descriptors import cached
from synapse.util.caches.dictionary_cache import DictionaryCache

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)

MAX_STATE_DELTA_HOPS = 100


@attr.s(slots=True, frozen=True, auto_attribs=True)
class _GetStateGroupDelta:
    """Return type of get_state_group_delta that implements __len__, which lets
    us use the iterable flag when caching
    """

    prev_group: Optional[int]
    delta_ids: Optional[StateMap[str]]

    def __len__(self) -> int:
        return len(self.delta_ids) if self.delta_ids else 0


class StateGroupDataStore(StateBackgroundUpdateStore, SQLBaseStore):
    """A data store for fetching/storing state groups."""

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

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

        self._state_group_cache: DictionaryCache[int, StateKey, str] = DictionaryCache(
            "*stateGroupCache*",
            # TODO: this hasn't been tuned yet
            50000,
        )
        self._state_group_members_cache: DictionaryCache[
            int, StateKey, str
        ] = DictionaryCache(
            "*stateGroupMembersCache*",
            500000,
        )

        # Current ongoing get_state_for_groups in-flight requests
        # {group ID -> {StateFilter -> ObservableDeferred}}
        self._state_group_inflight_requests: Dict[
            int, Dict[StateFilter, AbstractObservableDeferred[StateMap[str]]]
        ] = {}

        def get_max_state_group_txn(txn: Cursor) -> int:
            txn.execute("SELECT COALESCE(max(id), 0) FROM state_groups")
            return txn.fetchone()[0]  # type: ignore

        self._state_group_seq_gen = build_sequence_generator(
            db_conn,
            self.database_engine,
            get_max_state_group_txn,
            "state_group_id_seq",
            table="state_groups",
            id_column="id",
        )

    @cached(max_entries=10000, iterable=True)
    async def get_state_group_delta(self, state_group: int) -> _GetStateGroupDelta:
        """Given a state group try to return a previous group and a delta between
        the old and the new.

        Returns:
            _GetStateGroupDelta containing prev_group and delta_ids, where both may be None.
        """

        def _get_state_group_delta_txn(txn: LoggingTransaction) -> _GetStateGroupDelta:
            prev_group = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="state_group_edges",
                keyvalues={"state_group": state_group},
                retcol="prev_state_group",
                allow_none=True,
            )

            if not prev_group:
                return _GetStateGroupDelta(None, None)

            delta_ids = self.db_pool.simple_select_list_txn(
                txn,
                table="state_groups_state",
                keyvalues={"state_group": state_group},
                retcols=("type", "state_key", "event_id"),
            )

            return _GetStateGroupDelta(
                prev_group,
                {(row["type"], row["state_key"]): row["event_id"] for row in delta_ids},
            )

        return await self.db_pool.runInteraction(
            "get_state_group_delta", _get_state_group_delta_txn
        )

    async def _get_state_groups_from_groups(
        self, groups: Sequence[int], state_filter: StateFilter
    ) -> Dict[int, StateMap[str]]:
        """Returns the state groups for a given set of groups from the
        database, filtering on types of state events.

        Args:
            groups: list of state group IDs to query
            state_filter: The state filter used to fetch state
                from the database.
        Returns:
            Dict of state group to state map.
        """
        results: Dict[int, StateMap[str]] = {}

        chunks = [groups[i : i + 100] for i in range(0, len(groups), 100)]
        for chunk in chunks:
            res = await self.db_pool.runInteraction(
                "_get_state_groups_from_groups",
                self._get_state_groups_from_groups_txn,
                chunk,
                state_filter,
            )
            results.update(res)

        return results

    def _get_state_for_group_using_cache(
        self,
        cache: DictionaryCache[int, StateKey, str],
        group: int,
        state_filter: StateFilter,
    ) -> Tuple[MutableStateMap[str], bool]:
        """Checks if group is in cache. See `_get_state_for_groups`

        Args:
            cache: the state group cache to use
            group: The state group to lookup
            state_filter: The state filter used to fetch state from the database.

        Returns:
             2-tuple (`state_dict`, `got_all`).
                `got_all` is a bool indicating if we successfully retrieved all
                requests state from the cache, if False we need to query the DB for the
                missing state.
        """
        cache_entry = cache.get(group)
        state_dict_ids = cache_entry.value

        if cache_entry.full or state_filter.is_full():
            # Either we have everything or want everything, either way
            # `is_all` tells us whether we've gotten everything.
            return state_filter.filter_state(state_dict_ids), cache_entry.full

        # tracks whether any of our requested types are missing from the cache
        missing_types = False

        if state_filter.has_wildcards():
            # We don't know if we fetched all the state keys for the types in
            # the filter that are wildcards, so we have to assume that we may
            # have missed some.
            missing_types = True
        else:
            # There aren't any wild cards, so `concrete_types()` returns the
            # complete list of event types we're wanting.
            for key in state_filter.concrete_types():
                if key not in state_dict_ids and key not in cache_entry.known_absent:
                    missing_types = True
                    break

        return state_filter.filter_state(state_dict_ids), not missing_types

    def _get_state_for_group_gather_inflight_requests(
        self, group: int, state_filter_left_over: StateFilter
    ) -> Tuple[Sequence[AbstractObservableDeferred[StateMap[str]]], StateFilter]:
        """
        Attempts to gather in-flight requests and re-use them to retrieve state
        for the given state group, filtered with the given state filter.

        Returns:
            Tuple of two values:
                A sequence of ObservableDeferreds to observe
                A StateFilter representing what else needs to be requested to fulfill the request
        """

        inflight_requests = self._state_group_inflight_requests.get(group)
        if inflight_requests is None:
            # no requests for this group, need to retrieve it all ourselves
            return (), state_filter_left_over

        # The list of ongoing requests which will help narrow the current request.
        reusable_requests = []
        for (request_state_filter, request_deferred) in inflight_requests.items():
            new_state_filter_left_over = state_filter_left_over.approx_difference(
                request_state_filter
            )
            if new_state_filter_left_over == state_filter_left_over:
                # Reusing this request would not gain us anything, so don't bother.
                continue

            reusable_requests.append(request_deferred)
            state_filter_left_over = new_state_filter_left_over
            if state_filter_left_over == StateFilter.none():
                # we have managed to collect enough of the in-flight requests
                # to cover our StateFilter and give us the state we need.
                break

        return reusable_requests, state_filter_left_over

    async def _get_state_for_group_fire_request(
        self, group: int, state_filter: StateFilter
    ) -> StateMap[str]:
        """
        Fires off a request to get the state at a state group,
        potentially filtering by type and/or state key.

        This request will be tracked in the in-flight request cache and automatically
        removed when it is finished.

        Args:
            group: ID of the state group for which we want to get state
            state_filter: the state filter used to fetch state from the database
        """
        cache_sequence_nm = self._state_group_cache.sequence
        cache_sequence_m = self._state_group_members_cache.sequence

        # Help the cache hit ratio by expanding the filter a bit
        db_state_filter = state_filter.return_expanded()

        async def _the_request() -> StateMap[str]:
            group_to_state_dict = await self._get_state_groups_from_groups(
                (group,), state_filter=db_state_filter
            )

            # Now let's update the caches
            self._insert_into_cache(
                group_to_state_dict,
                db_state_filter,
                cache_seq_num_members=cache_sequence_m,
                cache_seq_num_non_members=cache_sequence_nm,
            )

            # Remove ourselves from the in-flight cache
            group_request_dict = self._state_group_inflight_requests[group]
            del group_request_dict[db_state_filter]
            if not group_request_dict:
                # If there are no more requests in-flight for this group,
                # clean up the cache by removing the empty dictionary
                del self._state_group_inflight_requests[group]

            return group_to_state_dict[group]

        # We don't immediately await the result, so must use run_in_background
        # But we DO await the result before the current log context (request)
        # finishes, so don't need to run it as a background process.
        request_deferred = run_in_background(_the_request)
        observable_deferred = ObservableDeferred(request_deferred, consumeErrors=True)

        # Insert the ObservableDeferred into the cache
        group_request_dict = self._state_group_inflight_requests.setdefault(group, {})
        group_request_dict[db_state_filter] = observable_deferred

        return await make_deferred_yieldable(observable_deferred.observe())

    async def _get_state_for_group_using_inflight_cache(
        self, group: int, state_filter: StateFilter
    ) -> MutableStateMap[str]:
        """
        Gets the state at a state group, potentially filtering by type and/or
        state key.

        Args:
            group: ID of the state group for which we want to get state
            state_filter: the state filter used to fetch state from the database
        Returns:
            state map
        """

        # first, figure out whether we can re-use any in-flight requests
        # (and if so, what would be left over)
        (
            reusable_requests,
            state_filter_left_over,
        ) = self._get_state_for_group_gather_inflight_requests(group, state_filter)

        if state_filter_left_over != StateFilter.none():
            # Fetch remaining state
            remaining = await self._get_state_for_group_fire_request(
                group, state_filter_left_over
            )
            assembled_state: MutableStateMap[str] = dict(remaining)
        else:
            assembled_state = {}

        gathered = await make_deferred_yieldable(
            defer.gatherResults(
                (r.observe() for r in reusable_requests), consumeErrors=True
            )
        ).addErrback(unwrapFirstError)

        # assemble our result.
        for result_piece in gathered:
            assembled_state.update(result_piece)

        # Filter out any state that may be more than what we asked for.
        return state_filter.filter_state(assembled_state)

    async def _get_state_for_groups(
        self, groups: Iterable[int], state_filter: Optional[StateFilter] = None
    ) -> Dict[int, MutableStateMap[str]]:
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key

        Args:
            groups: list of state groups for which we want
                to get the state.
            state_filter: The state filter used to fetch state
                from the database.
        Returns:
            Dict of state group to state map.
        """
        state_filter = state_filter or StateFilter.all()

        member_filter, non_member_filter = state_filter.get_member_split()

        # Now we look them up in the member and non-member caches
        (
            non_member_state,
            incomplete_groups_nm,
        ) = self._get_state_for_groups_using_cache(
            groups, self._state_group_cache, state_filter=non_member_filter
        )

        (member_state, incomplete_groups_m,) = self._get_state_for_groups_using_cache(
            groups, self._state_group_members_cache, state_filter=member_filter
        )

        state = dict(non_member_state)
        for group in groups:
            state[group].update(member_state[group])

        # Now fetch any missing groups from the database

        incomplete_groups = incomplete_groups_m | incomplete_groups_nm

        if not incomplete_groups:
            return state

        incomplete_groups_list = list(incomplete_groups)

        results_from_requests = await yieldable_gather_results(
            self._get_state_for_group_using_inflight_cache,
            incomplete_groups_list,
            state_filter,
        )

        for group, group_result in zip(incomplete_groups_list, results_from_requests):
            state[group] = group_result

        return state

    def _get_state_for_groups_using_cache(
        self,
        groups: Iterable[int],
        cache: DictionaryCache[int, StateKey, str],
        state_filter: StateFilter,
    ) -> Tuple[Dict[int, MutableStateMap[str]], Set[int]]:
        """Gets the state at each of a list of state groups, optionally
        filtering by type/state_key, querying from a specific cache.

        Args:
            groups: list of state groups for which we want to get the state.
            cache: the cache of group ids to state dicts which
                we will pass through - either the normal state cache or the
                specific members state cache.
            state_filter: The state filter used to fetch state from the
                database.

        Returns:
            Tuple of dict of state_group_id to state map of entries in the
            cache, and the state group ids either missing from the cache or
            incomplete.
        """
        results = {}
        incomplete_groups = set()
        for group in set(groups):
            state_dict_ids, got_all = self._get_state_for_group_using_cache(
                cache, group, state_filter
            )
            results[group] = state_dict_ids

            if not got_all:
                incomplete_groups.add(group)

        return results, incomplete_groups

    def _insert_into_cache(
        self,
        group_to_state_dict: Dict[int, StateMap[str]],
        state_filter: StateFilter,
        cache_seq_num_members: int,
        cache_seq_num_non_members: int,
    ) -> None:
        """Inserts results from querying the database into the relevant cache.

        Args:
            group_to_state_dict: The new entries pulled from database.
                Map from state group to state dict
            state_filter: The state filter used to fetch state
                from the database.
            cache_seq_num_members: Sequence number of member cache since
                last lookup in cache
            cache_seq_num_non_members: Sequence number of member cache since
                last lookup in cache
        """

        # We need to work out which types we've fetched from the DB for the
        # member vs non-member caches. This should be as accurate as possible,
        # but can be an underestimate (e.g. when we have wild cards)

        member_filter, non_member_filter = state_filter.get_member_split()
        if member_filter.is_full():
            # We fetched all member events
            member_types = None
        else:
            # `concrete_types()` will only return a subset when there are wild
            # cards in the filter, but that's fine.
            member_types = member_filter.concrete_types()

        if non_member_filter.is_full():
            # We fetched all non member events
            non_member_types = None
        else:
            non_member_types = non_member_filter.concrete_types()

        for group, group_state_dict in group_to_state_dict.items():
            state_dict_members = {}
            state_dict_non_members = {}

            for k, v in group_state_dict.items():
                if k[0] == EventTypes.Member:
                    state_dict_members[k] = v
                else:
                    state_dict_non_members[k] = v

            self._state_group_members_cache.update(
                cache_seq_num_members,
                key=group,
                value=state_dict_members,
                fetched_keys=member_types,
            )

            self._state_group_cache.update(
                cache_seq_num_non_members,
                key=group,
                value=state_dict_non_members,
                fetched_keys=non_member_types,
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
            event_id: The event ID for which the state was calculated
            room_id
            prev_group: A previous state group for the room, optional.
            delta_ids: The delta between state at `prev_group` and
                `current_state_ids`, if `prev_group` was given. Same format as
                `current_state_ids`.
            current_state_ids: The state to store. Map of (type, state_key)
                to event_id.

        Returns:
            The state group ID
        """

        def _store_state_group_txn(txn: LoggingTransaction) -> int:
            if current_state_ids is None:
                # AFAIK, this can never happen
                raise Exception("current_state_ids cannot be None")

            state_group = self._state_group_seq_gen.get_next_id_txn(txn)

            self.db_pool.simple_insert_txn(
                txn,
                table="state_groups",
                values={"id": state_group, "room_id": room_id, "event_id": event_id},
            )

            # We persist as a delta if we can, while also ensuring the chain
            # of deltas isn't tooo long, as otherwise read performance degrades.
            if prev_group:
                is_in_db = self.db_pool.simple_select_one_onecol_txn(
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

                potential_hops = self._count_state_group_hops_txn(txn, prev_group)
            if prev_group and potential_hops < MAX_STATE_DELTA_HOPS:
                assert delta_ids is not None

                self.db_pool.simple_insert_txn(
                    txn,
                    table="state_group_edges",
                    values={"state_group": state_group, "prev_state_group": prev_group},
                )

                self.db_pool.simple_insert_many_txn(
                    txn,
                    table="state_groups_state",
                    keys=("state_group", "room_id", "type", "state_key", "event_id"),
                    values=[
                        (state_group, room_id, key[0], key[1], state_id)
                        for key, state_id in delta_ids.items()
                    ],
                )
            else:
                self.db_pool.simple_insert_many_txn(
                    txn,
                    table="state_groups_state",
                    keys=("state_group", "room_id", "type", "state_key", "event_id"),
                    values=[
                        (state_group, room_id, key[0], key[1], state_id)
                        for key, state_id in current_state_ids.items()
                    ],
                )

            # Prefill the state group caches with this group.
            # It's fine to use the sequence like this as the state group map
            # is immutable. (If the map wasn't immutable then this prefill could
            # race with another update)

            current_member_state_ids = {
                s: ev
                for (s, ev) in current_state_ids.items()
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
                for (s, ev) in current_state_ids.items()
                if s[0] != EventTypes.Member
            }
            txn.call_after(
                self._state_group_cache.update,
                self._state_group_cache.sequence,
                key=state_group,
                value=dict(current_non_member_state_ids),
            )

            return state_group

        return await self.db_pool.runInteraction(
            "store_state_group", _store_state_group_txn
        )

    async def purge_unreferenced_state_groups(
        self, room_id: str, state_groups_to_delete: Collection[int]
    ) -> None:
        """Deletes no longer referenced state groups and de-deltas any state
        groups that reference them.

        Args:
            room_id: The room the state groups belong to (must all be in the
                same room).
            state_groups_to_delete: Set of all state groups to delete.
        """

        await self.db_pool.runInteraction(
            "purge_unreferenced_state_groups",
            self._purge_unreferenced_state_groups,
            room_id,
            state_groups_to_delete,
        )

    def _purge_unreferenced_state_groups(
        self,
        txn: LoggingTransaction,
        room_id: str,
        state_groups_to_delete: Collection[int],
    ) -> None:
        logger.info(
            "[purge] found %i state groups to delete", len(state_groups_to_delete)
        )

        rows = self.db_pool.simple_select_many_txn(
            txn,
            table="state_group_edges",
            column="prev_state_group",
            iterable=state_groups_to_delete,
            keyvalues={},
            retcols=("state_group",),
        )

        remaining_state_groups = {
            row["state_group"]
            for row in rows
            if row["state_group"] not in state_groups_to_delete
        }

        logger.info(
            "[purge] de-delta-ing %i remaining state groups",
            len(remaining_state_groups),
        )

        # Now we turn the state groups that reference to-be-deleted state
        # groups to non delta versions.
        for sg in remaining_state_groups:
            logger.info("[purge] de-delta-ing remaining state group %s", sg)
            curr_state_by_group = self._get_state_groups_from_groups_txn(txn, [sg])
            curr_state = curr_state_by_group[sg]

            self.db_pool.simple_delete_txn(
                txn, table="state_groups_state", keyvalues={"state_group": sg}
            )

            self.db_pool.simple_delete_txn(
                txn, table="state_group_edges", keyvalues={"state_group": sg}
            )

            self.db_pool.simple_insert_many_txn(
                txn,
                table="state_groups_state",
                keys=("state_group", "room_id", "type", "state_key", "event_id"),
                values=[
                    (sg, room_id, key[0], key[1], state_id)
                    for key, state_id in curr_state.items()
                ],
            )

        logger.info("[purge] removing redundant state groups")
        txn.execute_batch(
            "DELETE FROM state_groups_state WHERE state_group = ?",
            ((sg,) for sg in state_groups_to_delete),
        )
        txn.execute_batch(
            "DELETE FROM state_groups WHERE id = ?",
            ((sg,) for sg in state_groups_to_delete),
        )

    async def get_previous_state_groups(
        self, state_groups: Iterable[int]
    ) -> Dict[int, int]:
        """Fetch the previous groups of the given state groups.

        Args:
            state_groups

        Returns:
            A mapping from state group to previous state group.
        """

        rows = await self.db_pool.simple_select_many_batch(
            table="state_group_edges",
            column="prev_state_group",
            iterable=state_groups,
            keyvalues={},
            retcols=("prev_state_group", "state_group"),
            desc="get_previous_state_groups",
        )

        return {row["state_group"]: row["prev_state_group"] for row in rows}

    async def purge_room_state(
        self, room_id: str, state_groups_to_delete: Collection[int]
    ) -> None:
        """Deletes all record of a room from state tables

        Args:
            room_id:
            state_groups_to_delete: State groups to delete
        """

        await self.db_pool.runInteraction(
            "purge_room_state",
            self._purge_room_state_txn,
            room_id,
            state_groups_to_delete,
        )

    def _purge_room_state_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        state_groups_to_delete: Collection[int],
    ) -> None:
        # first we have to delete the state groups states
        logger.info("[purge] removing %s from state_groups_state", room_id)

        self.db_pool.simple_delete_many_txn(
            txn,
            table="state_groups_state",
            column="state_group",
            values=state_groups_to_delete,
            keyvalues={},
        )

        # ... and the state group edges
        logger.info("[purge] removing %s from state_group_edges", room_id)

        self.db_pool.simple_delete_many_txn(
            txn,
            table="state_group_edges",
            column="state_group",
            values=state_groups_to_delete,
            keyvalues={},
        )

        # ... and the state groups
        logger.info("[purge] removing %s from state_groups", room_id)

        self.db_pool.simple_delete_many_txn(
            txn,
            table="state_groups",
            column="id",
            values=state_groups_to_delete,
            keyvalues={},
        )
