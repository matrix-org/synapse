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
import itertools
import logging
from queue import Empty, PriorityQueue
from typing import Dict, Iterable, List, Set, Tuple

from synapse.api.errors import StoreError
from synapse.events import EventBase
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, make_in_list_sql_clause
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.signatures import SignatureWorkerStore
from synapse.storage.engines import PostgresEngine
from synapse.storage.types import Cursor
from synapse.types import Collection
from synapse.util.caches.descriptors import cached
from synapse.util.caches.lrucache import LruCache
from synapse.util.iterutils import batch_iter

logger = logging.getLogger(__name__)


class _NoChainCoverIndex(Exception):
    def __init__(self, room_id: str):
        super().__init__("Unexpectedly no chain cover for events in %s" % (room_id,))


class EventFederationWorkerStore(EventsWorkerStore, SignatureWorkerStore, SQLBaseStore):
    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        if hs.config.run_background_tasks:
            hs.get_clock().looping_call(
                self._delete_old_forward_extrem_cache, 60 * 60 * 1000
            )

        # Cache of event ID to list of auth event IDs and their depths.
        self._event_auth_cache = LruCache(
            500000, "_event_auth_cache", size_callback=len
        )  # type: LruCache[str, List[Tuple[str, int]]]

    async def get_auth_chain(
        self, event_ids: Collection[str], include_given: bool = False
    ) -> List[EventBase]:
        """Get auth events for given event_ids. The events *must* be state events.

        Args:
            event_ids: state events
            include_given: include the given events in result

        Returns:
            list of events
        """
        event_ids = await self.get_auth_chain_ids(
            event_ids, include_given=include_given
        )
        return await self.get_events_as_list(event_ids)

    async def get_auth_chain_ids(
        self,
        event_ids: Collection[str],
        include_given: bool = False,
    ) -> List[str]:
        """Get auth events for given event_ids. The events *must* be state events.

        Args:
            event_ids: state events
            include_given: include the given events in result

        Returns:
            An awaitable which resolve to a list of event_ids
        """
        return await self.db_pool.runInteraction(
            "get_auth_chain_ids",
            self._get_auth_chain_ids_txn,
            event_ids,
            include_given,
        )

    def _get_auth_chain_ids_txn(
        self, txn: LoggingTransaction, event_ids: Collection[str], include_given: bool
    ) -> List[str]:
        if include_given:
            results = set(event_ids)
        else:
            results = set()

        # We pull out the depth simply so that we can populate the
        # `_event_auth_cache` cache.
        base_sql = """
            SELECT a.event_id, auth_id, depth
            FROM event_auth AS a
            INNER JOIN events AS e ON (e.event_id = a.auth_id)
            WHERE
        """

        front = set(event_ids)
        while front:
            new_front = set()
            for chunk in batch_iter(front, 100):
                # Pull the auth events either from the cache or DB.
                to_fetch = []  # Event IDs to fetch from DB  # type: List[str]
                for event_id in chunk:
                    res = self._event_auth_cache.get(event_id)
                    if res is None:
                        to_fetch.append(event_id)
                    else:
                        new_front.update(auth_id for auth_id, depth in res)

                if to_fetch:
                    clause, args = make_in_list_sql_clause(
                        txn.database_engine, "a.event_id", to_fetch
                    )
                    txn.execute(base_sql + clause, args)

                    # Note we need to batch up the results by event ID before
                    # adding to the cache.
                    to_cache = {}
                    for event_id, auth_event_id, auth_event_depth in txn:
                        to_cache.setdefault(event_id, []).append(
                            (auth_event_id, auth_event_depth)
                        )
                        new_front.add(auth_event_id)

                    for event_id, auth_events in to_cache.items():
                        self._event_auth_cache.set(event_id, auth_events)

            new_front -= results

            front = new_front
            results.update(front)

        return list(results)

    async def get_auth_chain_difference(
        self, room_id: str, state_sets: List[Set[str]]
    ) -> Set[str]:
        """Given sets of state events figure out the auth chain difference (as
        per state res v2 algorithm).

        This equivalent to fetching the full auth chain for each set of state
        and returning the events that don't appear in each and every auth
        chain.

        Returns:
            The set of the difference in auth chains.
        """

        # Check if we have indexed the room so we can use the chain cover
        # algorithm.
        room = await self.get_room(room_id)
        if room["has_auth_chain_index"]:
            try:
                return await self.db_pool.runInteraction(
                    "get_auth_chain_difference_chains",
                    self._get_auth_chain_difference_using_cover_index_txn,
                    room_id,
                    state_sets,
                )
            except _NoChainCoverIndex:
                # For whatever reason we don't actually have a chain cover index
                # for the events in question, so we fall back to the old method.
                pass

        return await self.db_pool.runInteraction(
            "get_auth_chain_difference",
            self._get_auth_chain_difference_txn,
            state_sets,
        )

    def _get_auth_chain_difference_using_cover_index_txn(
        self, txn: Cursor, room_id: str, state_sets: List[Set[str]]
    ) -> Set[str]:
        """Calculates the auth chain difference using the chain index.

        See docs/auth_chain_difference_algorithm.md for details
        """

        # First we look up the chain ID/sequence numbers for all the events, and
        # work out the chain/sequence numbers reachable from each state set.

        initial_events = set(state_sets[0]).union(*state_sets[1:])

        # Map from event_id -> (chain ID, seq no)
        chain_info = {}  # type: Dict[str, Tuple[int, int]]

        # Map from chain ID -> seq no -> event Id
        chain_to_event = {}  # type: Dict[int, Dict[int, str]]

        # All the chains that we've found that are reachable from the state
        # sets.
        seen_chains = set()  # type: Set[int]

        sql = """
            SELECT event_id, chain_id, sequence_number
            FROM event_auth_chains
            WHERE %s
        """
        for batch in batch_iter(initial_events, 1000):
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "event_id", batch
            )
            txn.execute(sql % (clause,), args)

            for event_id, chain_id, sequence_number in txn:
                chain_info[event_id] = (chain_id, sequence_number)
                seen_chains.add(chain_id)
                chain_to_event.setdefault(chain_id, {})[sequence_number] = event_id

        # Check that we actually have a chain ID for all the events.
        events_missing_chain_info = initial_events.difference(chain_info)
        if events_missing_chain_info:
            # This can happen due to e.g. downgrade/upgrade of the server. We
            # raise an exception and fall back to the previous algorithm.
            logger.info(
                "Unexpectedly found that events don't have chain IDs in room %s: %s",
                room_id,
                events_missing_chain_info,
            )
            raise _NoChainCoverIndex(room_id)

        # Corresponds to `state_sets`, except as a map from chain ID to max
        # sequence number reachable from the state set.
        set_to_chain = []  # type: List[Dict[int, int]]
        for state_set in state_sets:
            chains = {}  # type: Dict[int, int]
            set_to_chain.append(chains)

            for event_id in state_set:
                chain_id, seq_no = chain_info[event_id]

                chains[chain_id] = max(seq_no, chains.get(chain_id, 0))

        # Now we look up all links for the chains we have, adding chains to
        # set_to_chain that are reachable from each set.
        sql = """
            SELECT
                origin_chain_id, origin_sequence_number,
                target_chain_id, target_sequence_number
            FROM event_auth_chain_links
            WHERE %s
        """

        # (We need to take a copy of `seen_chains` as we want to mutate it in
        # the loop)
        for batch in batch_iter(set(seen_chains), 1000):
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "origin_chain_id", batch
            )
            txn.execute(sql % (clause,), args)

            for (
                origin_chain_id,
                origin_sequence_number,
                target_chain_id,
                target_sequence_number,
            ) in txn:
                for chains in set_to_chain:
                    # chains are only reachable if the origin sequence number of
                    # the link is less than the max sequence number in the
                    # origin chain.
                    if origin_sequence_number <= chains.get(origin_chain_id, 0):
                        chains[target_chain_id] = max(
                            target_sequence_number,
                            chains.get(target_chain_id, 0),
                        )

                seen_chains.add(target_chain_id)

        # Now for each chain we figure out the maximum sequence number reachable
        # from *any* state set and the minimum sequence number reachable from
        # *all* state sets. Events in that range are in the auth chain
        # difference.
        result = set()

        # Mapping from chain ID to the range of sequence numbers that should be
        # pulled from the database.
        chain_to_gap = {}  # type: Dict[int, Tuple[int, int]]

        for chain_id in seen_chains:
            min_seq_no = min(chains.get(chain_id, 0) for chains in set_to_chain)
            max_seq_no = max(chains.get(chain_id, 0) for chains in set_to_chain)

            if min_seq_no < max_seq_no:
                # We have a non empty gap, try and fill it from the events that
                # we have, otherwise add them to the list of gaps to pull out
                # from the DB.
                for seq_no in range(min_seq_no + 1, max_seq_no + 1):
                    event_id = chain_to_event.get(chain_id, {}).get(seq_no)
                    if event_id:
                        result.add(event_id)
                    else:
                        chain_to_gap[chain_id] = (min_seq_no, max_seq_no)
                        break

        if not chain_to_gap:
            # If there are no gaps to fetch, we're done!
            return result

        if isinstance(self.database_engine, PostgresEngine):
            # We can use `execute_values` to efficiently fetch the gaps when
            # using postgres.
            sql = """
                SELECT event_id
                FROM event_auth_chains AS c, (VALUES ?) AS l(chain_id, min_seq, max_seq)
                WHERE
                    c.chain_id = l.chain_id
                    AND min_seq < sequence_number AND sequence_number <= max_seq
            """

            args = [
                (chain_id, min_no, max_no)
                for chain_id, (min_no, max_no) in chain_to_gap.items()
            ]

            rows = txn.execute_values(sql, args)
            result.update(r for r, in rows)
        else:
            # For SQLite we just fall back to doing a noddy for loop.
            sql = """
                SELECT event_id FROM event_auth_chains
                WHERE chain_id = ? AND ? < sequence_number AND sequence_number <= ?
            """
            for chain_id, (min_no, max_no) in chain_to_gap.items():
                txn.execute(sql, (chain_id, min_no, max_no))
                result.update(r for r, in txn)

        return result

    def _get_auth_chain_difference_txn(
        self, txn, state_sets: List[Set[str]]
    ) -> Set[str]:
        """Calculates the auth chain difference using a breadth first search.

        This is used when we don't have a cover index for the room.
        """

        # Algorithm Description
        # ~~~~~~~~~~~~~~~~~~~~~
        #
        # The idea here is to basically walk the auth graph of each state set in
        # tandem, keeping track of which auth events are reachable by each state
        # set. If we reach an auth event we've already visited (via a different
        # state set) then we mark that auth event and all ancestors as reachable
        # by the state set. This requires that we keep track of the auth chains
        # in memory.
        #
        # Doing it in a such a way means that we can stop early if all auth
        # events we're currently walking are reachable by all state sets.
        #
        # *Note*: We can't stop walking an event's auth chain if it is reachable
        # by all state sets. This is because other auth chains we're walking
        # might be reachable only via the original auth chain. For example,
        # given the following auth chain:
        #
        #       A -> C -> D -> E
        #           /         /
        #       B -´---------´
        #
        # and state sets {A} and {B} then walking the auth chains of A and B
        # would immediately show that C is reachable by both. However, if we
        # stopped at C then we'd only reach E via the auth chain of B and so E
        # would erroneously get included in the returned difference.
        #
        # The other thing that we do is limit the number of auth chains we walk
        # at once, due to practical limits (i.e. we can only query the database
        # with a limited set of parameters). We pick the auth chains we walk
        # each iteration based on their depth, in the hope that events with a
        # lower depth are likely reachable by those with higher depths.
        #
        # We could use any ordering that we believe would give a rough
        # topological ordering, e.g. origin server timestamp. If the ordering
        # chosen is not topological then the algorithm still produces the right
        # result, but perhaps a bit more inefficiently. This is why it is safe
        # to use "depth" here.

        initial_events = set(state_sets[0]).union(*state_sets[1:])

        # Dict from events in auth chains to which sets *cannot* reach them.
        # I.e. if the set is empty then all sets can reach the event.
        event_to_missing_sets = {
            event_id: {i for i, a in enumerate(state_sets) if event_id not in a}
            for event_id in initial_events
        }

        # The sorted list of events whose auth chains we should walk.
        search = []  # type: List[Tuple[int, str]]

        # We need to get the depth of the initial events for sorting purposes.
        sql = """
            SELECT depth, event_id FROM events
            WHERE %s
        """
        # the list can be huge, so let's avoid looking them all up in one massive
        # query.
        for batch in batch_iter(initial_events, 1000):
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "event_id", batch
            )
            txn.execute(sql % (clause,), args)

            # I think building a temporary list with fetchall is more efficient than
            # just `search.extend(txn)`, but this is unconfirmed
            search.extend(txn.fetchall())

        # sort by depth
        search.sort()

        # Map from event to its auth events
        event_to_auth_events = {}  # type: Dict[str, Set[str]]

        base_sql = """
            SELECT a.event_id, auth_id, depth
            FROM event_auth AS a
            INNER JOIN events AS e ON (e.event_id = a.auth_id)
            WHERE
        """

        while search:
            # Check whether all our current walks are reachable by all state
            # sets. If so we can bail.
            if all(not event_to_missing_sets[eid] for _, eid in search):
                break

            # Fetch the auth events and their depths of the N last events we're
            # currently walking, either from cache or DB.
            search, chunk = search[:-100], search[-100:]

            found = []  # Results found  # type: List[Tuple[str, str, int]]
            to_fetch = []  # Event IDs to fetch from DB  # type: List[str]
            for _, event_id in chunk:
                res = self._event_auth_cache.get(event_id)
                if res is None:
                    to_fetch.append(event_id)
                else:
                    found.extend((event_id, auth_id, depth) for auth_id, depth in res)

            if to_fetch:
                clause, args = make_in_list_sql_clause(
                    txn.database_engine, "a.event_id", to_fetch
                )
                txn.execute(base_sql + clause, args)

                # We parse the results and add the to the `found` set and the
                # cache (note we need to batch up the results by event ID before
                # adding to the cache).
                to_cache = {}
                for event_id, auth_event_id, auth_event_depth in txn:
                    to_cache.setdefault(event_id, []).append(
                        (auth_event_id, auth_event_depth)
                    )
                    found.append((event_id, auth_event_id, auth_event_depth))

                for event_id, auth_events in to_cache.items():
                    self._event_auth_cache.set(event_id, auth_events)

            for event_id, auth_event_id, auth_event_depth in found:
                event_to_auth_events.setdefault(event_id, set()).add(auth_event_id)

                sets = event_to_missing_sets.get(auth_event_id)
                if sets is None:
                    # First time we're seeing this event, so we add it to the
                    # queue of things to fetch.
                    search.append((auth_event_depth, auth_event_id))

                    # Assume that this event is unreachable from any of the
                    # state sets until proven otherwise
                    sets = event_to_missing_sets[auth_event_id] = set(
                        range(len(state_sets))
                    )
                else:
                    # We've previously seen this event, so look up its auth
                    # events and recursively mark all ancestors as reachable
                    # by the current event's state set.
                    a_ids = event_to_auth_events.get(auth_event_id)
                    while a_ids:
                        new_aids = set()
                        for a_id in a_ids:
                            event_to_missing_sets[a_id].intersection_update(
                                event_to_missing_sets[event_id]
                            )

                            b = event_to_auth_events.get(a_id)
                            if b:
                                new_aids.update(b)

                        a_ids = new_aids

                # Mark that the auth event is reachable by the appropriate sets.
                sets.intersection_update(event_to_missing_sets[event_id])

            search.sort()

        # Return all events where not all sets can reach them.
        return {eid for eid, n in event_to_missing_sets.items() if n}

    async def get_oldest_events_with_depth_in_room(self, room_id):
        return await self.db_pool.runInteraction(
            "get_oldest_events_with_depth_in_room",
            self.get_oldest_events_with_depth_in_room_txn,
            room_id,
        )

    def get_oldest_events_with_depth_in_room_txn(self, txn, room_id):
        sql = (
            "SELECT b.event_id, MAX(e.depth) FROM events as e"
            " INNER JOIN event_edges as g"
            " ON g.event_id = e.event_id"
            " INNER JOIN event_backward_extremities as b"
            " ON g.prev_event_id = b.event_id"
            " WHERE b.room_id = ? AND g.is_state is ?"
            " GROUP BY b.event_id"
        )

        txn.execute(sql, (room_id, False))

        return dict(txn)

    async def get_max_depth_of(self, event_ids: List[str]) -> int:
        """Returns the max depth of a set of event IDs

        Args:
            event_ids: The event IDs to calculate the max depth of.
        """
        rows = await self.db_pool.simple_select_many_batch(
            table="events",
            column="event_id",
            iterable=event_ids,
            retcols=("depth",),
            desc="get_max_depth_of",
        )

        if not rows:
            return 0
        else:
            return max(row["depth"] for row in rows)

    async def get_prev_events_for_room(self, room_id: str) -> List[str]:
        """
        Gets a subset of the current forward extremities in the given room.

        Limits the result to 10 extremities, so that we can avoid creating
        events which refer to hundreds of prev_events.

        Args:
            room_id: room_id

        Returns:
            The event ids of the forward extremities.

        """

        return await self.db_pool.runInteraction(
            "get_prev_events_for_room", self._get_prev_events_for_room_txn, room_id
        )

    def _get_prev_events_for_room_txn(self, txn, room_id: str):
        # we just use the 10 newest events. Older events will become
        # prev_events of future events.

        sql = """
            SELECT e.event_id FROM event_forward_extremities AS f
            INNER JOIN events AS e USING (event_id)
            WHERE f.room_id = ?
            ORDER BY e.depth DESC
            LIMIT 10
        """

        txn.execute(sql, (room_id,))

        return [row[0] for row in txn]

    async def get_rooms_with_many_extremities(
        self, min_count: int, limit: int, room_id_filter: Iterable[str]
    ) -> List[str]:
        """Get the top rooms with at least N extremities.

        Args:
            min_count: The minimum number of extremities
            limit: The maximum number of rooms to return.
            room_id_filter: room_ids to exclude from the results

        Returns:
            At most `limit` room IDs that have at least `min_count` extremities,
            sorted by extremity count.
        """

        def _get_rooms_with_many_extremities_txn(txn):
            where_clause = "1=1"
            if room_id_filter:
                where_clause = "room_id NOT IN (%s)" % (
                    ",".join("?" for _ in room_id_filter),
                )

            sql = """
                SELECT room_id FROM event_forward_extremities
                WHERE %s
                GROUP BY room_id
                HAVING count(*) > ?
                ORDER BY count(*) DESC
                LIMIT ?
            """ % (
                where_clause,
            )

            query_args = list(itertools.chain(room_id_filter, [min_count, limit]))
            txn.execute(sql, query_args)
            return [room_id for room_id, in txn]

        return await self.db_pool.runInteraction(
            "get_rooms_with_many_extremities", _get_rooms_with_many_extremities_txn
        )

    @cached(max_entries=5000, iterable=True)
    async def get_latest_event_ids_in_room(self, room_id: str) -> List[str]:
        return await self.db_pool.simple_select_onecol(
            table="event_forward_extremities",
            keyvalues={"room_id": room_id},
            retcol="event_id",
            desc="get_latest_event_ids_in_room",
        )

    async def get_min_depth(self, room_id: str) -> int:
        """For the given room, get the minimum depth we have seen for it."""
        return await self.db_pool.runInteraction(
            "get_min_depth", self._get_min_depth_interaction, room_id
        )

    def _get_min_depth_interaction(self, txn, room_id):
        min_depth = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="room_depth",
            keyvalues={"room_id": room_id},
            retcol="min_depth",
            allow_none=True,
        )

        return int(min_depth) if min_depth is not None else None

    async def get_forward_extremeties_for_room(
        self, room_id: str, stream_ordering: int
    ) -> List[str]:
        """For a given room_id and stream_ordering, return the forward
        extremeties of the room at that point in "time".

        Throws a StoreError if we have since purged the index for
        stream_orderings from that point.

        Args:
            room_id:
            stream_ordering:

        Returns:
            A list of event_ids
        """
        # We want to make the cache more effective, so we clamp to the last
        # change before the given ordering.
        last_change = self._events_stream_cache.get_max_pos_of_last_change(room_id)

        # We don't always have a full stream_to_exterm_id table, e.g. after
        # the upgrade that introduced it, so we make sure we never ask for a
        # stream_ordering from before a restart
        last_change = max(self._stream_order_on_start, last_change)

        # provided the last_change is recent enough, we now clamp the requested
        # stream_ordering to it.
        if last_change > self.stream_ordering_month_ago:
            stream_ordering = min(last_change, stream_ordering)

        return await self._get_forward_extremeties_for_room(room_id, stream_ordering)

    @cached(max_entries=5000, num_args=2)
    async def _get_forward_extremeties_for_room(self, room_id, stream_ordering):
        """For a given room_id and stream_ordering, return the forward
        extremeties of the room at that point in "time".

        Throws a StoreError if we have since purged the index for
        stream_orderings from that point.
        """

        if stream_ordering <= self.stream_ordering_month_ago:
            raise StoreError(400, "stream_ordering too old %s" % (stream_ordering,))

        sql = """
                SELECT event_id FROM stream_ordering_to_exterm
                INNER JOIN (
                    SELECT room_id, MAX(stream_ordering) AS stream_ordering
                    FROM stream_ordering_to_exterm
                    WHERE stream_ordering <= ? GROUP BY room_id
                ) AS rms USING (room_id, stream_ordering)
                WHERE room_id = ?
        """

        def get_forward_extremeties_for_room_txn(txn):
            txn.execute(sql, (stream_ordering, room_id))
            return [event_id for event_id, in txn]

        return await self.db_pool.runInteraction(
            "get_forward_extremeties_for_room", get_forward_extremeties_for_room_txn
        )

    async def get_backfill_events(self, room_id: str, event_list: list, limit: int):
        """Get a list of Events for a given topic that occurred before (and
        including) the events in event_list. Return a list of max size `limit`

        Args:
            room_id
            event_list
            limit
        """
        event_ids = await self.db_pool.runInteraction(
            "get_backfill_events",
            self._get_backfill_events,
            room_id,
            event_list,
            limit,
        )
        events = await self.get_events_as_list(event_ids)
        return sorted(events, key=lambda e: -e.depth)

    def _get_backfill_events(self, txn, room_id, event_list, limit):
        logger.debug("_get_backfill_events: %s, %r, %s", room_id, event_list, limit)

        event_results = set()

        # We want to make sure that we do a breadth-first, "depth" ordered
        # search.

        query = (
            "SELECT depth, prev_event_id FROM event_edges"
            " INNER JOIN events"
            " ON prev_event_id = events.event_id"
            " WHERE event_edges.event_id = ?"
            " AND event_edges.is_state = ?"
            " LIMIT ?"
        )

        queue = PriorityQueue()

        for event_id in event_list:
            depth = self.db_pool.simple_select_one_onecol_txn(
                txn,
                table="events",
                keyvalues={"event_id": event_id, "room_id": room_id},
                retcol="depth",
                allow_none=True,
            )

            if depth:
                queue.put((-depth, event_id))

        while not queue.empty() and len(event_results) < limit:
            try:
                _, event_id = queue.get_nowait()
            except Empty:
                break

            if event_id in event_results:
                continue

            event_results.add(event_id)

            txn.execute(query, (event_id, False, limit - len(event_results)))

            for row in txn:
                if row[1] not in event_results:
                    queue.put((-row[0], row[1]))

        return event_results

    async def get_missing_events(self, room_id, earliest_events, latest_events, limit):
        ids = await self.db_pool.runInteraction(
            "get_missing_events",
            self._get_missing_events,
            room_id,
            earliest_events,
            latest_events,
            limit,
        )
        return await self.get_events_as_list(ids)

    def _get_missing_events(self, txn, room_id, earliest_events, latest_events, limit):

        seen_events = set(earliest_events)
        front = set(latest_events) - seen_events
        event_results = []

        query = (
            "SELECT prev_event_id FROM event_edges "
            "WHERE room_id = ? AND event_id = ? AND is_state = ? "
            "LIMIT ?"
        )

        while front and len(event_results) < limit:
            new_front = set()
            for event_id in front:
                txn.execute(
                    query, (room_id, event_id, False, limit - len(event_results))
                )

                new_results = {t[0] for t in txn} - seen_events

                new_front |= new_results
                seen_events |= new_results
                event_results.extend(new_results)

            front = new_front

        # we built the list working backwards from latest_events; we now need to
        # reverse it so that the events are approximately chronological.
        event_results.reverse()
        return event_results

    async def get_successor_events(self, event_ids: Iterable[str]) -> List[str]:
        """Fetch all events that have the given events as a prev event

        Args:
            event_ids: The events to use as the previous events.
        """
        rows = await self.db_pool.simple_select_many_batch(
            table="event_edges",
            column="prev_event_id",
            iterable=event_ids,
            retcols=("event_id",),
            desc="get_successor_events",
        )

        return [row["event_id"] for row in rows]

    @wrap_as_background_process("delete_old_forward_extrem_cache")
    async def _delete_old_forward_extrem_cache(self) -> None:
        def _delete_old_forward_extrem_cache_txn(txn):
            # Delete entries older than a month, while making sure we don't delete
            # the only entries for a room.
            sql = """
                DELETE FROM stream_ordering_to_exterm
                WHERE
                room_id IN (
                    SELECT room_id
                    FROM stream_ordering_to_exterm
                    WHERE stream_ordering > ?
                ) AND stream_ordering < ?
            """
            txn.execute(
                sql, (self.stream_ordering_month_ago, self.stream_ordering_month_ago)
            )

        await self.db_pool.runInteraction(
            "_delete_old_forward_extrem_cache",
            _delete_old_forward_extrem_cache_txn,
        )


class EventFederationStore(EventFederationWorkerStore):
    """Responsible for storing and serving up the various graphs associated
    with an event. Including the main event graph and the auth chains for an
    event.

    Also has methods for getting the front (latest) and back (oldest) edges
    of the event graphs. These are used to generate the parents for new events
    and backfilling from another server respectively.
    """

    EVENT_AUTH_STATE_ONLY = "event_auth_state_only"

    def __init__(self, database: DatabasePool, db_conn, hs):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            self.EVENT_AUTH_STATE_ONLY, self._background_delete_non_state_event_auth
        )

    async def clean_room_for_join(self, room_id):
        return await self.db_pool.runInteraction(
            "clean_room_for_join", self._clean_room_for_join_txn, room_id
        )

    def _clean_room_for_join_txn(self, txn, room_id):
        query = "DELETE FROM event_forward_extremities WHERE room_id = ?"

        txn.execute(query, (room_id,))
        txn.call_after(self.get_latest_event_ids_in_room.invalidate, (room_id,))

    async def _background_delete_non_state_event_auth(self, progress, batch_size):
        def delete_event_auth(txn):
            target_min_stream_id = progress.get("target_min_stream_id_inclusive")
            max_stream_id = progress.get("max_stream_id_exclusive")

            if not target_min_stream_id or not max_stream_id:
                txn.execute("SELECT COALESCE(MIN(stream_ordering), 0) FROM events")
                rows = txn.fetchall()
                target_min_stream_id = rows[0][0]

                txn.execute("SELECT COALESCE(MAX(stream_ordering), 0) FROM events")
                rows = txn.fetchall()
                max_stream_id = rows[0][0]

            min_stream_id = max_stream_id - batch_size

            sql = """
                DELETE FROM event_auth
                WHERE event_id IN (
                    SELECT event_id FROM events
                    LEFT JOIN state_events USING (room_id, event_id)
                    WHERE ? <= stream_ordering AND stream_ordering < ?
                        AND state_key IS null
                )
            """

            txn.execute(sql, (min_stream_id, max_stream_id))

            new_progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
            }

            self.db_pool.updates._background_update_progress_txn(
                txn, self.EVENT_AUTH_STATE_ONLY, new_progress
            )

            return min_stream_id >= target_min_stream_id

        result = await self.db_pool.runInteraction(
            self.EVENT_AUTH_STATE_ONLY, delete_event_auth
        )

        if not result:
            await self.db_pool.updates._end_background_update(
                self.EVENT_AUTH_STATE_ONLY
            )

        return batch_size
