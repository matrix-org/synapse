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
import datetime
import itertools
import logging
from queue import Empty, PriorityQueue
from typing import (
    TYPE_CHECKING,
    Collection,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    cast,
)

import attr
from prometheus_client import Counter, Gauge

from synapse.api.constants import MAX_DEPTH, EventTypes
from synapse.api.errors import StoreError
from synapse.api.room_versions import EventFormatVersions, RoomVersion
from synapse.events import EventBase, make_event_from_dict
from synapse.logging.opentracing import tag_args, trace
from synapse.metrics.background_process_metrics import wrap_as_background_process
from synapse.storage._base import SQLBaseStore, db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.signatures import SignatureWorkerStore
from synapse.storage.engines import PostgresEngine, Sqlite3Engine
from synapse.types import JsonDict
from synapse.util import json_encoder
from synapse.util.caches.descriptors import cached
from synapse.util.caches.lrucache import LruCache
from synapse.util.cancellation import cancellable
from synapse.util.iterutils import batch_iter

if TYPE_CHECKING:
    from synapse.server import HomeServer

oldest_pdu_in_federation_staging = Gauge(
    "synapse_federation_server_oldest_inbound_pdu_in_staging",
    "The age in seconds since we received the oldest pdu in the federation staging area",
)

number_pdus_in_federation_queue = Gauge(
    "synapse_federation_server_number_inbound_pdu_in_staging",
    "The total number of events in the inbound federation staging",
)

pdus_pruned_from_federation_queue = Counter(
    "synapse_federation_server_number_inbound_pdu_pruned",
    "The number of events in the inbound federation staging that have been "
    "pruned due to the queue getting too long",
)

logger = logging.getLogger(__name__)

# Parameters controlling exponential backoff between backfill failures.
# After the first failure to backfill, we wait 2 hours before trying again. If the
# second attempt fails, we wait 4 hours before trying again. If the third attempt fails,
# we wait 8 hours before trying again, ... and so on.
#
# Each successive backoff period is twice as long as the last. However we cap this
# period at a maximum of 2^8 = 256 hours: a little over 10 days. (This is the smallest
# power of 2 which yields a maximum backoff period of at least 7 days---which was the
# original maximum backoff period.) Even when we hit this cap, we will continue to
# make backfill attempts once every 10 days.
BACKFILL_EVENT_EXPONENTIAL_BACKOFF_MAXIMUM_DOUBLING_STEPS = 8
BACKFILL_EVENT_EXPONENTIAL_BACKOFF_STEP_MILLISECONDS = int(
    datetime.timedelta(hours=1).total_seconds() * 1000
)

# We need a cap on the power of 2 or else the backoff period
#   2^N * (milliseconds per hour)
# will overflow when calcuated within the database. We ensure overflow does not occur
# by checking that the largest backoff period fits in a 32-bit signed integer.
_LONGEST_BACKOFF_PERIOD_MILLISECONDS = (
    2**BACKFILL_EVENT_EXPONENTIAL_BACKOFF_MAXIMUM_DOUBLING_STEPS
) * BACKFILL_EVENT_EXPONENTIAL_BACKOFF_STEP_MILLISECONDS
assert 0 < _LONGEST_BACKOFF_PERIOD_MILLISECONDS <= ((2**31) - 1)


# All the info we need while iterating the DAG while backfilling
@attr.s(frozen=True, slots=True, auto_attribs=True)
class BackfillQueueNavigationItem:
    depth: int
    stream_ordering: int
    event_id: str
    type: str


class _NoChainCoverIndex(Exception):
    def __init__(self, room_id: str):
        super().__init__("Unexpectedly no chain cover for events in %s" % (room_id,))


class EventFederationWorkerStore(SignatureWorkerStore, EventsWorkerStore, SQLBaseStore):
    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.hs = hs

        if hs.config.worker.run_background_tasks:
            hs.get_clock().looping_call(
                self._delete_old_forward_extrem_cache, 60 * 60 * 1000
            )

        # Cache of event ID to list of auth event IDs and their depths.
        self._event_auth_cache: LruCache[str, List[Tuple[str, int]]] = LruCache(
            500000, "_event_auth_cache", size_callback=len
        )

        self._clock.looping_call(self._get_stats_for_federation_staging, 30 * 1000)

    async def get_auth_chain(
        self, room_id: str, event_ids: Collection[str], include_given: bool = False
    ) -> List[EventBase]:
        """Get auth events for given event_ids. The events *must* be state events.

        Args:
            room_id: The room the event is in.
            event_ids: state events
            include_given: include the given events in result

        Returns:
            list of events
        """
        event_ids = await self.get_auth_chain_ids(
            room_id, event_ids, include_given=include_given
        )
        return await self.get_events_as_list(event_ids)

    @trace
    @tag_args
    async def get_auth_chain_ids(
        self,
        room_id: str,
        event_ids: Collection[str],
        include_given: bool = False,
    ) -> Set[str]:
        """Get auth events for given event_ids. The events *must* be state events.

        Args:
            room_id: The room the event is in.
            event_ids: state events
            include_given: include the given events in result

        Returns:
            set of event_ids
        """

        # Check if we have indexed the room so we can use the chain cover
        # algorithm.
        room = await self.get_room(room_id)  # type: ignore[attr-defined]
        if room["has_auth_chain_index"]:
            try:
                return await self.db_pool.runInteraction(
                    "get_auth_chain_ids_chains",
                    self._get_auth_chain_ids_using_cover_index_txn,
                    room_id,
                    event_ids,
                    include_given,
                )
            except _NoChainCoverIndex:
                # For whatever reason we don't actually have a chain cover index
                # for the events in question, so we fall back to the old method.
                pass

        return await self.db_pool.runInteraction(
            "get_auth_chain_ids",
            self._get_auth_chain_ids_txn,
            event_ids,
            include_given,
        )

    def _get_auth_chain_ids_using_cover_index_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        event_ids: Collection[str],
        include_given: bool,
    ) -> Set[str]:
        """Calculates the auth chain IDs using the chain index."""

        # First we look up the chain ID/sequence numbers for the given events.

        initial_events = set(event_ids)

        # All the events that we've found that are reachable from the events.
        seen_events: Set[str] = set()

        # A map from chain ID to max sequence number of the given events.
        event_chains: Dict[int, int] = {}

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
                seen_events.add(event_id)
                event_chains[chain_id] = max(
                    sequence_number, event_chains.get(chain_id, 0)
                )

        # Check that we actually have a chain ID for all the events.
        events_missing_chain_info = initial_events.difference(seen_events)
        if events_missing_chain_info:
            # This can happen due to e.g. downgrade/upgrade of the server. We
            # raise an exception and fall back to the previous algorithm.
            logger.info(
                "Unexpectedly found that events don't have chain IDs in room %s: %s",
                room_id,
                events_missing_chain_info,
            )
            raise _NoChainCoverIndex(room_id)

        # Now we look up all links for the chains we have, adding chains that
        # are reachable from any event.
        sql = """
            SELECT
                origin_chain_id, origin_sequence_number,
                target_chain_id, target_sequence_number
            FROM event_auth_chain_links
            WHERE %s
        """

        # A map from chain ID to max sequence number *reachable* from any event ID.
        chains: Dict[int, int] = {}

        # Add all linked chains reachable from initial set of chains.
        for batch2 in batch_iter(event_chains, 1000):
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "origin_chain_id", batch2
            )
            txn.execute(sql % (clause,), args)

            for (
                origin_chain_id,
                origin_sequence_number,
                target_chain_id,
                target_sequence_number,
            ) in txn:
                # chains are only reachable if the origin sequence number of
                # the link is less than the max sequence number in the
                # origin chain.
                if origin_sequence_number <= event_chains.get(origin_chain_id, 0):
                    chains[target_chain_id] = max(
                        target_sequence_number,
                        chains.get(target_chain_id, 0),
                    )

        # Add the initial set of chains, excluding the sequence corresponding to
        # initial event.
        for chain_id, seq_no in event_chains.items():
            chains[chain_id] = max(seq_no - 1, chains.get(chain_id, 0))

        # Now for each chain we figure out the maximum sequence number reachable
        # from *any* event ID. Events with a sequence less than that are in the
        # auth chain.
        if include_given:
            results = initial_events
        else:
            results = set()

        if isinstance(self.database_engine, PostgresEngine):
            # We can use `execute_values` to efficiently fetch the gaps when
            # using postgres.
            sql = """
                SELECT event_id
                FROM event_auth_chains AS c, (VALUES ?) AS l(chain_id, max_seq)
                WHERE
                    c.chain_id = l.chain_id
                    AND sequence_number <= max_seq
            """

            rows = txn.execute_values(sql, chains.items())
            results.update(r for r, in rows)
        else:
            # For SQLite we just fall back to doing a noddy for loop.
            sql = """
                SELECT event_id FROM event_auth_chains
                WHERE chain_id = ? AND sequence_number <= ?
            """
            for chain_id, max_no in chains.items():
                txn.execute(sql, (chain_id, max_no))
                results.update(r for r, in txn)

        return results

    def _get_auth_chain_ids_txn(
        self, txn: LoggingTransaction, event_ids: Collection[str], include_given: bool
    ) -> Set[str]:
        """Calculates the auth chain IDs.

        This is used when we don't have a cover index for the room.
        """
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
            new_front: Set[str] = set()
            for chunk in batch_iter(front, 100):
                # Pull the auth events either from the cache or DB.
                to_fetch: List[str] = []  # Event IDs to fetch from DB
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
                    to_cache: Dict[str, List[Tuple[str, int]]] = {}
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

        return results

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
        room = await self.get_room(room_id)  # type: ignore[attr-defined]
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
        self, txn: LoggingTransaction, room_id: str, state_sets: List[Set[str]]
    ) -> Set[str]:
        """Calculates the auth chain difference using the chain index.

        See docs/auth_chain_difference_algorithm.md for details
        """

        # First we look up the chain ID/sequence numbers for all the events, and
        # work out the chain/sequence numbers reachable from each state set.

        initial_events = set(state_sets[0]).union(*state_sets[1:])

        # Map from event_id -> (chain ID, seq no)
        chain_info: Dict[str, Tuple[int, int]] = {}

        # Map from chain ID -> seq no -> event Id
        chain_to_event: Dict[int, Dict[int, str]] = {}

        # All the chains that we've found that are reachable from the state
        # sets.
        seen_chains: Set[int] = set()

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
        set_to_chain: List[Dict[int, int]] = []
        for state_set in state_sets:
            chains: Dict[int, int] = {}
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
        for batch2 in batch_iter(set(seen_chains), 1000):
            clause, args = make_in_list_sql_clause(
                txn.database_engine, "origin_chain_id", batch2
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
        chain_to_gap: Dict[int, Tuple[int, int]] = {}

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
        self, txn: LoggingTransaction, state_sets: List[Set[str]]
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
        search: List[Tuple[int, str]] = []

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
            search.extend(cast(List[Tuple[int, str]], txn.fetchall()))

        # sort by depth
        search.sort()

        # Map from event to its auth events
        event_to_auth_events: Dict[str, Set[str]] = {}

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

            found: List[Tuple[str, str, int]] = []  # Results found
            to_fetch: List[str] = []  # Event IDs to fetch from DB
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
                to_cache: Dict[str, List[Tuple[str, int]]] = {}
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

    @trace
    @tag_args
    async def get_backfill_points_in_room(
        self,
        room_id: str,
        current_depth: int,
        limit: int,
    ) -> List[Tuple[str, int]]:
        """
        Get the backward extremities to backfill from in the room along with the
        approximate depth.

        Only returns events that are at a depth lower than or
        equal to the `current_depth`. Sorted by depth, highest to lowest (descending)
        so the closest events to the `current_depth` are first in the list.

        We ignore extremities that are newer than the user's current scroll position
        (ie, those with depth greater than `current_depth`) as:
            1. we don't really care about getting events that have happened
               after our current position; and
            2. by the nature of paginating and scrolling back, we have likely
               previously tried and failed to backfill from that extremity, so
               to avoid getting "stuck" requesting the same backfill repeatedly
               we drop those extremities.

        Args:
            room_id: Room where we want to find the oldest events
            current_depth: The depth at the user's current scrollback position
            limit: The max number of backfill points to return

        Returns:
            List of (event_id, depth) tuples. Sorted by depth, highest to lowest
            (descending) so the closest events to the `current_depth` are first
            in the list.
        """

        def get_backfill_points_in_room_txn(
            txn: LoggingTransaction, room_id: str
        ) -> List[Tuple[str, int]]:
            # Assemble a tuple lookup of event_id -> depth for the oldest events
            # we know of in the room. Backwards extremeties are the oldest
            # events we know of in the room but we only know of them because
            # some other event referenced them by prev_event and aren't
            # persisted in our database yet (meaning we don't know their depth
            # specifically). So we need to look for the approximate depth from
            # the events connected to the current backwards extremeties.

            if isinstance(self.database_engine, PostgresEngine):
                least_function = "LEAST"
            elif isinstance(self.database_engine, Sqlite3Engine):
                least_function = "MIN"
            else:
                raise RuntimeError("Unknown database engine")

            sql = f"""
                SELECT backward_extrem.event_id, event.depth FROM events AS event
                /**
                 * Get the edge connections from the event_edges table
                 * so we can see whether this event's prev_events points
                 * to a backward extremity in the next join.
                 */
                INNER JOIN event_edges AS edge
                ON edge.event_id = event.event_id
                /**
                 * We find the "oldest" events in the room by looking for
                 * events connected to backwards extremeties (oldest events
                 * in the room that we know of so far).
                 */
                INNER JOIN event_backward_extremities AS backward_extrem
                ON edge.prev_event_id = backward_extrem.event_id
                /**
                 * We use this info to make sure we don't retry to use a backfill point
                 * if we've already attempted to backfill from it recently.
                 */
                LEFT JOIN event_failed_pull_attempts AS failed_backfill_attempt_info
                ON
                    failed_backfill_attempt_info.room_id = backward_extrem.room_id
                    AND failed_backfill_attempt_info.event_id = backward_extrem.event_id
                WHERE
                    backward_extrem.room_id = ?
                    /* We only care about non-state edges because we used to use
                     * `event_edges` for two different sorts of "edges" (the current
                     * event DAG, but also a link to the previous state, for state
                     * events). These legacy state event edges can be distinguished by
                     * `is_state` and are removed from the codebase and schema but
                     * because the schema change is in a background update, it's not
                     * necessarily safe to assume that it will have been completed.
                     */
                    AND edge.is_state is ? /* False */
                    /**
                     * We only want backwards extremities that are older than or at
                     * the same position of the given `current_depth` (where older
                     * means less than the given depth) because we're looking backwards
                     * from the `current_depth` when backfilling.
                     *
                     *                         current_depth (ignore events that come after this, ignore 2-4)
                     *                         |
                     *                         ▼
                     * <oldest-in-time> [0]<--[1]<--[2]<--[3]<--[4] <newest-in-time>
                     */
                    AND event.depth <= ? /* current_depth */
                    /**
                     * Exponential back-off (up to the upper bound) so we don't retry the
                     * same backfill point over and over. ex. 2hr, 4hr, 8hr, 16hr, etc.
                     *
                     * We use `1 << n` as a power of 2 equivalent for compatibility
                     * with older SQLites. The left shift equivalent only works with
                     * powers of 2 because left shift is a binary operation (base-2).
                     * Otherwise, we would use `power(2, n)` or the power operator, `2^n`.
                     */
                    AND (
                        failed_backfill_attempt_info.event_id IS NULL
                        OR ? /* current_time */ >= failed_backfill_attempt_info.last_attempt_ts + (
                            (1 << {least_function}(failed_backfill_attempt_info.num_attempts, ? /* max doubling steps */))
                            * ? /* step */
                        )
                    )
                /**
                 * Sort from highest (closest to the `current_depth`) to the lowest depth
                 * because the closest are most relevant to backfill from first.
                 * Then tie-break on alphabetical order of the event_ids so we get a
                 * consistent ordering which is nice when asserting things in tests.
                 */
                ORDER BY event.depth DESC, backward_extrem.event_id DESC
                LIMIT ?
            """

            txn.execute(
                sql,
                (
                    room_id,
                    False,
                    current_depth,
                    self._clock.time_msec(),
                    BACKFILL_EVENT_EXPONENTIAL_BACKOFF_MAXIMUM_DOUBLING_STEPS,
                    BACKFILL_EVENT_EXPONENTIAL_BACKOFF_STEP_MILLISECONDS,
                    limit,
                ),
            )

            return cast(List[Tuple[str, int]], txn.fetchall())

        return await self.db_pool.runInteraction(
            "get_backfill_points_in_room",
            get_backfill_points_in_room_txn,
            room_id,
        )

    @trace
    async def get_insertion_event_backward_extremities_in_room(
        self,
        room_id: str,
        current_depth: int,
        limit: int,
    ) -> List[Tuple[str, int]]:
        """
        Get the insertion events we know about that we haven't backfilled yet
        along with the approximate depth. Only returns insertion events that are
        at a depth lower than or equal to the `current_depth`. Sorted by depth,
        highest to lowest (descending) so the closest events to the
        `current_depth` are first in the list.

        We ignore insertion events that are newer than the user's current scroll
        position (ie, those with depth greater than `current_depth`) as:
            1. we don't really care about getting events that have happened
               after our current position; and
            2. by the nature of paginating and scrolling back, we have likely
               previously tried and failed to backfill from that insertion event, so
               to avoid getting "stuck" requesting the same backfill repeatedly
               we drop those insertion event.

        Args:
            room_id: Room where we want to find the oldest events
            current_depth: The depth at the user's current scrollback position
            limit: The max number of insertion event extremities to return

        Returns:
            List of (event_id, depth) tuples. Sorted by depth, highest to lowest
            (descending) so the closest events to the `current_depth` are first
            in the list.
        """

        def get_insertion_event_backward_extremities_in_room_txn(
            txn: LoggingTransaction, room_id: str
        ) -> List[Tuple[str, int]]:
            if isinstance(self.database_engine, PostgresEngine):
                least_function = "LEAST"
            elif isinstance(self.database_engine, Sqlite3Engine):
                least_function = "MIN"
            else:
                raise RuntimeError("Unknown database engine")

            sql = f"""
                SELECT
                    insertion_event_extremity.event_id, event.depth
                /* We only want insertion events that are also marked as backwards extremities */
                FROM insertion_event_extremities AS insertion_event_extremity
                /* Get the depth of the insertion event from the events table */
                INNER JOIN events AS event USING (event_id)
                /**
                 * We use this info to make sure we don't retry to use a backfill point
                 * if we've already attempted to backfill from it recently.
                 */
                LEFT JOIN event_failed_pull_attempts AS failed_backfill_attempt_info
                ON
                    failed_backfill_attempt_info.room_id = insertion_event_extremity.room_id
                    AND failed_backfill_attempt_info.event_id = insertion_event_extremity.event_id
                WHERE
                    insertion_event_extremity.room_id = ?
                    /**
                     * We only want extremities that are older than or at
                     * the same position of the given `current_depth` (where older
                     * means less than the given depth) because we're looking backwards
                     * from the `current_depth` when backfilling.
                     *
                     *                         current_depth (ignore events that come after this, ignore 2-4)
                     *                         |
                     *                         ▼
                     * <oldest-in-time> [0]<--[1]<--[2]<--[3]<--[4] <newest-in-time>
                     */
                    AND event.depth <= ? /* current_depth */
                    /**
                     * Exponential back-off (up to the upper bound) so we don't retry the
                     * same backfill point over and over. ex. 2hr, 4hr, 8hr, 16hr, etc
                     *
                     * We use `1 << n` as a power of 2 equivalent for compatibility
                     * with older SQLites. The left shift equivalent only works with
                     * powers of 2 because left shift is a binary operation (base-2).
                     * Otherwise, we would use `power(2, n)` or the power operator, `2^n`.
                     */
                    AND (
                        failed_backfill_attempt_info.event_id IS NULL
                        OR ? /* current_time */ >= failed_backfill_attempt_info.last_attempt_ts + (
                            (1 << {least_function}(failed_backfill_attempt_info.num_attempts, ? /* max doubling steps */))
                            * ? /* step */
                        )
                    )
                /**
                 * Sort from highest (closest to the `current_depth`) to the lowest depth
                 * because the closest are most relevant to backfill from first.
                 * Then tie-break on alphabetical order of the event_ids so we get a
                 * consistent ordering which is nice when asserting things in tests.
                 */
                ORDER BY event.depth DESC, insertion_event_extremity.event_id DESC
                LIMIT ?
            """

            txn.execute(
                sql,
                (
                    room_id,
                    current_depth,
                    self._clock.time_msec(),
                    BACKFILL_EVENT_EXPONENTIAL_BACKOFF_MAXIMUM_DOUBLING_STEPS,
                    BACKFILL_EVENT_EXPONENTIAL_BACKOFF_STEP_MILLISECONDS,
                    limit,
                ),
            )
            return cast(List[Tuple[str, int]], txn.fetchall())

        return await self.db_pool.runInteraction(
            "get_insertion_event_backward_extremities_in_room",
            get_insertion_event_backward_extremities_in_room_txn,
            room_id,
        )

    async def get_max_depth_of(self, event_ids: List[str]) -> Tuple[Optional[str], int]:
        """Returns the event ID and depth for the event that has the max depth from a set of event IDs

        Args:
            event_ids: The event IDs to calculate the max depth of.
        """
        rows = await self.db_pool.simple_select_many_batch(
            table="events",
            column="event_id",
            iterable=event_ids,
            retcols=(
                "event_id",
                "depth",
            ),
            desc="get_max_depth_of",
        )

        if not rows:
            return None, 0
        else:
            max_depth_event_id = ""
            current_max_depth = 0
            for row in rows:
                if row["depth"] > current_max_depth:
                    max_depth_event_id = row["event_id"]
                    current_max_depth = row["depth"]

            return max_depth_event_id, current_max_depth

    async def get_min_depth_of(self, event_ids: List[str]) -> Tuple[Optional[str], int]:
        """Returns the event ID and depth for the event that has the min depth from a set of event IDs

        Args:
            event_ids: The event IDs to calculate the max depth of.
        """
        rows = await self.db_pool.simple_select_many_batch(
            table="events",
            column="event_id",
            iterable=event_ids,
            retcols=(
                "event_id",
                "depth",
            ),
            desc="get_min_depth_of",
        )

        if not rows:
            return None, 0
        else:
            min_depth_event_id = ""
            current_min_depth = MAX_DEPTH
            for row in rows:
                if row["depth"] < current_min_depth:
                    min_depth_event_id = row["event_id"]
                    current_min_depth = row["depth"]

            return min_depth_event_id, current_min_depth

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

    def _get_prev_events_for_room_txn(
        self, txn: LoggingTransaction, room_id: str
    ) -> List[str]:
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

        def _get_rooms_with_many_extremities_txn(txn: LoggingTransaction) -> List[str]:
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

    async def get_min_depth(self, room_id: str) -> Optional[int]:
        """For the given room, get the minimum depth we have seen for it."""
        return await self.db_pool.runInteraction(
            "get_min_depth", self._get_min_depth_interaction, room_id
        )

    def _get_min_depth_interaction(
        self, txn: LoggingTransaction, room_id: str
    ) -> Optional[int]:
        min_depth = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="room_depth",
            keyvalues={"room_id": room_id},
            retcol="min_depth",
            allow_none=True,
        )

        return int(min_depth) if min_depth is not None else None

    @cancellable
    async def get_forward_extremities_for_room_at_stream_ordering(
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
        last_change = self._events_stream_cache.get_max_pos_of_last_change(room_id)  # type: ignore[attr-defined]

        # We don't always have a full stream_to_exterm_id table, e.g. after
        # the upgrade that introduced it, so we make sure we never ask for a
        # stream_ordering from before a restart
        last_change = max(self._stream_order_on_start, last_change)  # type: ignore[attr-defined]

        # provided the last_change is recent enough, we now clamp the requested
        # stream_ordering to it.
        if last_change > self.stream_ordering_month_ago:  # type: ignore[attr-defined]
            stream_ordering = min(last_change, stream_ordering)

        return await self._get_forward_extremeties_for_room(room_id, stream_ordering)

    @cached(max_entries=5000, num_args=2)
    async def _get_forward_extremeties_for_room(
        self, room_id: str, stream_ordering: int
    ) -> List[str]:
        """For a given room_id and stream_ordering, return the forward
        extremeties of the room at that point in "time".

        Throws a StoreError if we have since purged the index for
        stream_orderings from that point.
        """

        if stream_ordering <= self.stream_ordering_month_ago:  # type: ignore[attr-defined]
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

        def get_forward_extremeties_for_room_txn(txn: LoggingTransaction) -> List[str]:
            txn.execute(sql, (stream_ordering, room_id))
            return [event_id for event_id, in txn]

        return await self.db_pool.runInteraction(
            "get_forward_extremeties_for_room", get_forward_extremeties_for_room_txn
        )

    def _get_connected_batch_event_backfill_results_txn(
        self, txn: LoggingTransaction, insertion_event_id: str, limit: int
    ) -> List[BackfillQueueNavigationItem]:
        """
        Find any batch connections of a given insertion event.
        A batch event points at a insertion event via:
        batch_event.content[MSC2716_BATCH_ID] -> insertion_event.content[MSC2716_NEXT_BATCH_ID]

        Args:
            txn: The database transaction to use
            insertion_event_id: The event ID to navigate from. We will find
                batch events that point back at this insertion event.
            limit: Max number of event ID's to query for and return

        Returns:
            List of batch events that the backfill queue can process
        """
        batch_connection_query = """
            SELECT e.depth, e.stream_ordering, c.event_id, e.type FROM insertion_events AS i
            /* Find the batch that connects to the given insertion event */
            INNER JOIN batch_events AS c
            ON i.next_batch_id = c.batch_id
            /* Get the depth of the batch start event from the events table */
            INNER JOIN events AS e ON c.event_id = e.event_id
            /* Find an insertion event which matches the given event_id */
            WHERE i.event_id = ?
            LIMIT ?
        """

        # Find any batch connections for the given insertion event
        txn.execute(
            batch_connection_query,
            (insertion_event_id, limit),
        )
        return [
            BackfillQueueNavigationItem(
                depth=row[0],
                stream_ordering=row[1],
                event_id=row[2],
                type=row[3],
            )
            for row in txn
        ]

    def _get_connected_prev_event_backfill_results_txn(
        self, txn: LoggingTransaction, event_id: str, limit: int
    ) -> List[BackfillQueueNavigationItem]:
        """
        Find any events connected by prev_event the specified event_id.

        Args:
            txn: The database transaction to use
            event_id: The event ID to navigate from
            limit: Max number of event ID's to query for and return

        Returns:
            List of prev events that the backfill queue can process
        """
        # Look for the prev_event_id connected to the given event_id
        connected_prev_event_query = """
            SELECT depth, stream_ordering, prev_event_id, events.type FROM event_edges
            /* Get the depth and stream_ordering of the prev_event_id from the events table */
            INNER JOIN events
            ON prev_event_id = events.event_id

            /* exclude outliers from the results (we don't have the state, so cannot
             * verify if the requesting server can see them).
             */
            WHERE NOT events.outlier

            /* Look for an edge which matches the given event_id */
            AND event_edges.event_id = ? AND NOT event_edges.is_state

            /* Because we can have many events at the same depth,
            * we want to also tie-break and sort on stream_ordering */
            ORDER BY depth DESC, stream_ordering DESC
            LIMIT ?
        """

        txn.execute(
            connected_prev_event_query,
            (event_id, limit),
        )
        return [
            BackfillQueueNavigationItem(
                depth=row[0],
                stream_ordering=row[1],
                event_id=row[2],
                type=row[3],
            )
            for row in txn
        ]

    async def get_backfill_events(
        self, room_id: str, seed_event_id_list: List[str], limit: int
    ) -> List[EventBase]:
        """Get a list of Events for a given topic that occurred before (and
        including) the events in seed_event_id_list. Return a list of max size `limit`

        Args:
            room_id
            seed_event_id_list
            limit
        """
        event_ids = await self.db_pool.runInteraction(
            "get_backfill_events",
            self._get_backfill_events,
            room_id,
            seed_event_id_list,
            limit,
        )
        events = await self.get_events_as_list(event_ids)
        return sorted(
            # type-ignore: mypy doesn't like negating the Optional[int] stream_ordering.
            # But it's never None, because these events were previously persisted to the DB.
            events,
            key=lambda e: (-e.depth, -e.internal_metadata.stream_ordering),  # type: ignore[operator]
        )

    def _get_backfill_events(
        self,
        txn: LoggingTransaction,
        room_id: str,
        seed_event_id_list: List[str],
        limit: int,
    ) -> Set[str]:
        """
        We want to make sure that we do a breadth-first, "depth" ordered search.
        We also handle navigating historical branches of history connected by
        insertion and batch events.
        """
        logger.debug(
            "_get_backfill_events(room_id=%s): seeding backfill with seed_event_id_list=%s limit=%s",
            room_id,
            seed_event_id_list,
            limit,
        )

        event_id_results: Set[str] = set()

        # In a PriorityQueue, the lowest valued entries are retrieved first.
        # We're using depth as the priority in the queue and tie-break based on
        # stream_ordering. Depth is lowest at the oldest-in-time message and
        # highest and newest-in-time message. We add events to the queue with a
        # negative depth so that we process the newest-in-time messages first
        # going backwards in time. stream_ordering follows the same pattern.
        queue: "PriorityQueue[Tuple[int, int, str, str]]" = PriorityQueue()

        for seed_event_id in seed_event_id_list:
            event_lookup_result = self.db_pool.simple_select_one_txn(
                txn,
                table="events",
                keyvalues={"event_id": seed_event_id, "room_id": room_id},
                retcols=(
                    "type",
                    "depth",
                    "stream_ordering",
                ),
                allow_none=True,
            )

            if event_lookup_result is not None:
                logger.debug(
                    "_get_backfill_events(room_id=%s): seed_event_id=%s depth=%s stream_ordering=%s type=%s",
                    room_id,
                    seed_event_id,
                    event_lookup_result["depth"],
                    event_lookup_result["stream_ordering"],
                    event_lookup_result["type"],
                )

                if event_lookup_result["depth"]:
                    queue.put(
                        (
                            -event_lookup_result["depth"],
                            -event_lookup_result["stream_ordering"],
                            seed_event_id,
                            event_lookup_result["type"],
                        )
                    )

        while not queue.empty() and len(event_id_results) < limit:
            try:
                _, _, event_id, event_type = queue.get_nowait()
            except Empty:
                break

            if event_id in event_id_results:
                continue

            event_id_results.add(event_id)

            # Try and find any potential historical batches of message history.
            if self.hs.config.experimental.msc2716_enabled:
                # We need to go and try to find any batch events connected
                # to a given insertion event (by batch_id). If we find any, we'll
                # add them to the queue and navigate up the DAG like normal in the
                # next iteration of the loop.
                if event_type == EventTypes.MSC2716_INSERTION:
                    # Find any batch connections for the given insertion event
                    connected_batch_event_backfill_results = (
                        self._get_connected_batch_event_backfill_results_txn(
                            txn, event_id, limit - len(event_id_results)
                        )
                    )
                    logger.debug(
                        "_get_backfill_events(room_id=%s): connected_batch_event_backfill_results=%s",
                        room_id,
                        connected_batch_event_backfill_results,
                    )
                    for (
                        connected_batch_event_backfill_item
                    ) in connected_batch_event_backfill_results:
                        if (
                            connected_batch_event_backfill_item.event_id
                            not in event_id_results
                        ):
                            queue.put(
                                (
                                    -connected_batch_event_backfill_item.depth,
                                    -connected_batch_event_backfill_item.stream_ordering,
                                    connected_batch_event_backfill_item.event_id,
                                    connected_batch_event_backfill_item.type,
                                )
                            )

            # Now we just look up the DAG by prev_events as normal
            connected_prev_event_backfill_results = (
                self._get_connected_prev_event_backfill_results_txn(
                    txn, event_id, limit - len(event_id_results)
                )
            )
            logger.debug(
                "_get_backfill_events(room_id=%s): connected_prev_event_backfill_results=%s",
                room_id,
                connected_prev_event_backfill_results,
            )
            for (
                connected_prev_event_backfill_item
            ) in connected_prev_event_backfill_results:
                if connected_prev_event_backfill_item.event_id not in event_id_results:
                    queue.put(
                        (
                            -connected_prev_event_backfill_item.depth,
                            -connected_prev_event_backfill_item.stream_ordering,
                            connected_prev_event_backfill_item.event_id,
                            connected_prev_event_backfill_item.type,
                        )
                    )

        return event_id_results

    @trace
    async def record_event_failed_pull_attempt(
        self, room_id: str, event_id: str, cause: str
    ) -> None:
        """
        Record when we fail to pull an event over federation.

        This information allows us to be more intelligent when we decide to
        retry (we don't need to fail over and over) and we can process that
        event in the background so we don't block on it each time.

        Args:
            room_id: The room where the event failed to pull from
            event_id: The event that failed to be fetched or processed
            cause: The error message or reason that we failed to pull the event
        """
        logger.debug(
            "record_event_failed_pull_attempt room_id=%s, event_id=%s, cause=%s",
            room_id,
            event_id,
            cause,
        )
        await self.db_pool.runInteraction(
            "record_event_failed_pull_attempt",
            self._record_event_failed_pull_attempt_upsert_txn,
            room_id,
            event_id,
            cause,
            db_autocommit=True,  # Safe as it's a single upsert
        )

    def _record_event_failed_pull_attempt_upsert_txn(
        self,
        txn: LoggingTransaction,
        room_id: str,
        event_id: str,
        cause: str,
    ) -> None:
        sql = """
            INSERT INTO event_failed_pull_attempts (
                room_id, event_id, num_attempts, last_attempt_ts, last_cause
            )
                VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (room_id, event_id) DO UPDATE SET
                num_attempts=event_failed_pull_attempts.num_attempts + 1,
                last_attempt_ts=EXCLUDED.last_attempt_ts,
                last_cause=EXCLUDED.last_cause;
        """

        txn.execute(sql, (room_id, event_id, 1, self._clock.time_msec(), cause))

    @trace
    async def get_event_ids_to_not_pull_from_backoff(
        self,
        room_id: str,
        event_ids: Collection[str],
    ) -> List[str]:
        """
        Filter down the events to ones that we've failed to pull before recently. Uses
        exponential backoff.

        Args:
            room_id: The room that the events belong to
            event_ids: A list of events to filter down

        Returns:
            List of event_ids that should not be attempted to be pulled
        """
        event_failed_pull_attempts = await self.db_pool.simple_select_many_batch(
            table="event_failed_pull_attempts",
            column="event_id",
            iterable=event_ids,
            keyvalues={},
            retcols=(
                "event_id",
                "last_attempt_ts",
                "num_attempts",
            ),
            desc="get_event_ids_to_not_pull_from_backoff",
        )

        current_time = self._clock.time_msec()
        return [
            event_failed_pull_attempt["event_id"]
            for event_failed_pull_attempt in event_failed_pull_attempts
            # Exponential back-off (up to the upper bound) so we don't try to
            # pull the same event over and over. ex. 2hr, 4hr, 8hr, 16hr, etc.
            if current_time
            < event_failed_pull_attempt["last_attempt_ts"]
            + (
                2
                ** min(
                    event_failed_pull_attempt["num_attempts"],
                    BACKFILL_EVENT_EXPONENTIAL_BACKOFF_MAXIMUM_DOUBLING_STEPS,
                )
            )
            * BACKFILL_EVENT_EXPONENTIAL_BACKOFF_STEP_MILLISECONDS
        ]

    async def get_missing_events(
        self,
        room_id: str,
        earliest_events: List[str],
        latest_events: List[str],
        limit: int,
    ) -> List[EventBase]:
        ids = await self.db_pool.runInteraction(
            "get_missing_events",
            self._get_missing_events,
            room_id,
            earliest_events,
            latest_events,
            limit,
        )
        return await self.get_events_as_list(ids)

    def _get_missing_events(
        self,
        txn: LoggingTransaction,
        room_id: str,
        earliest_events: List[str],
        latest_events: List[str],
        limit: int,
    ) -> List[str]:

        seen_events = set(earliest_events)
        front = set(latest_events) - seen_events
        event_results: List[str] = []

        query = (
            "SELECT prev_event_id FROM event_edges "
            "WHERE event_id = ? AND NOT is_state "
            "LIMIT ?"
        )

        while front and len(event_results) < limit:
            new_front = set()
            for event_id in front:
                txn.execute(query, (event_id, limit - len(event_results)))
                new_results = {t[0] for t in txn} - seen_events

                new_front |= new_results
                seen_events |= new_results
                event_results.extend(new_results)

            front = new_front

        # we built the list working backwards from latest_events; we now need to
        # reverse it so that the events are approximately chronological.
        event_results.reverse()
        return event_results

    @trace
    @tag_args
    async def get_successor_events(self, event_id: str) -> List[str]:
        """Fetch all events that have the given event as a prev event

        Args:
            event_id: The event to search for as a prev_event.
        """
        return await self.db_pool.simple_select_onecol(
            table="event_edges",
            keyvalues={"prev_event_id": event_id},
            retcol="event_id",
            desc="get_successor_events",
        )

    @wrap_as_background_process("delete_old_forward_extrem_cache")
    async def _delete_old_forward_extrem_cache(self) -> None:
        def _delete_old_forward_extrem_cache_txn(txn: LoggingTransaction) -> None:
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
                sql, (self.stream_ordering_month_ago, self.stream_ordering_month_ago)  # type: ignore[attr-defined]
            )

        await self.db_pool.runInteraction(
            "_delete_old_forward_extrem_cache",
            _delete_old_forward_extrem_cache_txn,
        )

    @trace
    async def insert_insertion_extremity(self, event_id: str, room_id: str) -> None:
        await self.db_pool.simple_upsert(
            table="insertion_event_extremities",
            keyvalues={"event_id": event_id},
            values={
                "event_id": event_id,
                "room_id": room_id,
            },
            insertion_values={},
            desc="insert_insertion_extremity",
            lock=False,
        )

    async def insert_received_event_to_staging(
        self, origin: str, event: EventBase
    ) -> None:
        """Insert a newly received event from federation into the staging area."""

        # We use an upsert here to handle the case where we see the same event
        # from the same server multiple times.
        await self.db_pool.simple_upsert(
            table="federation_inbound_events_staging",
            keyvalues={
                "origin": origin,
                "event_id": event.event_id,
            },
            values={},
            insertion_values={
                "room_id": event.room_id,
                "received_ts": self._clock.time_msec(),
                "event_json": json_encoder.encode(event.get_dict()),
                "internal_metadata": json_encoder.encode(
                    event.internal_metadata.get_dict()
                ),
            },
            desc="insert_received_event_to_staging",
        )

    async def remove_received_event_from_staging(
        self,
        origin: str,
        event_id: str,
    ) -> Optional[int]:
        """Remove the given event from the staging area.

        Returns:
            The received_ts of the row that was deleted, if any.
        """
        if self.db_pool.engine.supports_returning:

            def _remove_received_event_from_staging_txn(
                txn: LoggingTransaction,
            ) -> Optional[int]:
                sql = """
                    DELETE FROM federation_inbound_events_staging
                    WHERE origin = ? AND event_id = ?
                    RETURNING received_ts
                """

                txn.execute(sql, (origin, event_id))
                row = cast(Optional[Tuple[int]], txn.fetchone())

                if row is None:
                    return None

                return row[0]

            return await self.db_pool.runInteraction(
                "remove_received_event_from_staging",
                _remove_received_event_from_staging_txn,
                db_autocommit=True,
            )

        else:

            def _remove_received_event_from_staging_txn(
                txn: LoggingTransaction,
            ) -> Optional[int]:
                received_ts = self.db_pool.simple_select_one_onecol_txn(
                    txn,
                    table="federation_inbound_events_staging",
                    keyvalues={
                        "origin": origin,
                        "event_id": event_id,
                    },
                    retcol="received_ts",
                    allow_none=True,
                )
                self.db_pool.simple_delete_txn(
                    txn,
                    table="federation_inbound_events_staging",
                    keyvalues={
                        "origin": origin,
                        "event_id": event_id,
                    },
                )

                return received_ts

            return await self.db_pool.runInteraction(
                "remove_received_event_from_staging",
                _remove_received_event_from_staging_txn,
            )

    async def get_next_staged_event_id_for_room(
        self,
        room_id: str,
    ) -> Optional[Tuple[str, str]]:
        """
        Get the next event ID in the staging area for the given room.

        Returns:
            Tuple of the `origin` and `event_id`
        """

        def _get_next_staged_event_id_for_room_txn(
            txn: LoggingTransaction,
        ) -> Optional[Tuple[str, str]]:
            sql = """
                SELECT origin, event_id
                FROM federation_inbound_events_staging
                WHERE room_id = ?
                ORDER BY received_ts ASC
                LIMIT 1
            """

            txn.execute(sql, (room_id,))

            return cast(Optional[Tuple[str, str]], txn.fetchone())

        return await self.db_pool.runInteraction(
            "get_next_staged_event_id_for_room", _get_next_staged_event_id_for_room_txn
        )

    async def get_next_staged_event_for_room(
        self,
        room_id: str,
        room_version: RoomVersion,
    ) -> Optional[Tuple[str, EventBase]]:
        """Get the next event in the staging area for the given room."""

        def _get_next_staged_event_for_room_txn(
            txn: LoggingTransaction,
        ) -> Optional[Tuple[str, str, str]]:
            sql = """
                SELECT event_json, internal_metadata, origin
                FROM federation_inbound_events_staging
                WHERE room_id = ?
                ORDER BY received_ts ASC
                LIMIT 1
            """
            txn.execute(sql, (room_id,))

            return cast(Optional[Tuple[str, str, str]], txn.fetchone())

        row = await self.db_pool.runInteraction(
            "get_next_staged_event_for_room", _get_next_staged_event_for_room_txn
        )

        if not row:
            return None

        event_d = db_to_json(row[0])
        internal_metadata_d = db_to_json(row[1])
        origin = row[2]

        event = make_event_from_dict(
            event_dict=event_d,
            room_version=room_version,
            internal_metadata_dict=internal_metadata_d,
        )

        return origin, event

    async def prune_staged_events_in_room(
        self,
        room_id: str,
        room_version: RoomVersion,
    ) -> bool:
        """Checks if there are lots of staged events for the room, and if so
        prune them down.

        Returns:
            Whether any events were pruned
        """

        # First check the size of the queue.
        count = await self.db_pool.simple_select_one_onecol(
            table="federation_inbound_events_staging",
            keyvalues={"room_id": room_id},
            retcol="COUNT(*)",
            desc="prune_staged_events_in_room_count",
        )

        if count < 100:
            return False

        # If the queue is too large, then we want clear the entire queue,
        # keeping only the forward extremities (i.e. the events not referenced
        # by other events in the queue). We do this so that we can always
        # backpaginate in all the events we have dropped.
        rows = await self.db_pool.simple_select_list(
            table="federation_inbound_events_staging",
            keyvalues={"room_id": room_id},
            retcols=("event_id", "event_json"),
            desc="prune_staged_events_in_room_fetch",
        )

        # Find the set of events referenced by those in the queue, as well as
        # collecting all the event IDs in the queue.
        referenced_events: Set[str] = set()
        seen_events: Set[str] = set()
        for row in rows:
            event_id = row["event_id"]
            seen_events.add(event_id)
            event_d = db_to_json(row["event_json"])

            # We don't bother parsing the dicts into full blown event objects,
            # as that is needlessly expensive.

            # We haven't checked that the `prev_events` have the right format
            # yet, so we check as we go.
            prev_events = event_d.get("prev_events", [])
            if not isinstance(prev_events, list):
                logger.info("Invalid prev_events for %s", event_id)
                continue

            if room_version.event_format == EventFormatVersions.ROOM_V1_V2:
                for prev_event_tuple in prev_events:
                    if (
                        not isinstance(prev_event_tuple, list)
                        or len(prev_event_tuple) != 2
                    ):
                        logger.info("Invalid prev_events for %s", event_id)
                        break

                    prev_event_id = prev_event_tuple[0]
                    if not isinstance(prev_event_id, str):
                        logger.info("Invalid prev_events for %s", event_id)
                        break

                    referenced_events.add(prev_event_id)
            else:
                for prev_event_id in prev_events:
                    if not isinstance(prev_event_id, str):
                        logger.info("Invalid prev_events for %s", event_id)
                        break

                    referenced_events.add(prev_event_id)

        to_delete = referenced_events & seen_events
        if not to_delete:
            return False

        pdus_pruned_from_federation_queue.inc(len(to_delete))
        logger.info(
            "Pruning %d events in room %s from federation queue",
            len(to_delete),
            room_id,
        )

        await self.db_pool.simple_delete_many(
            table="federation_inbound_events_staging",
            keyvalues={"room_id": room_id},
            iterable=to_delete,
            column="event_id",
            desc="prune_staged_events_in_room_delete",
        )

        return True

    async def get_all_rooms_with_staged_incoming_events(self) -> List[str]:
        """Get the room IDs of all events currently staged."""
        return await self.db_pool.simple_select_onecol(
            table="federation_inbound_events_staging",
            keyvalues={},
            retcol="DISTINCT room_id",
            desc="get_all_rooms_with_staged_incoming_events",
        )

    @wrap_as_background_process("_get_stats_for_federation_staging")
    async def _get_stats_for_federation_staging(self) -> None:
        """Update the prometheus metrics for the inbound federation staging area."""

        def _get_stats_for_federation_staging_txn(
            txn: LoggingTransaction,
        ) -> Tuple[int, int]:
            txn.execute("SELECT count(*) FROM federation_inbound_events_staging")
            (count,) = cast(Tuple[int], txn.fetchone())

            txn.execute(
                "SELECT min(received_ts) FROM federation_inbound_events_staging"
            )

            (received_ts,) = cast(Tuple[Optional[int]], txn.fetchone())

            # If there is nothing in the staging area default it to 0.
            age = 0
            if received_ts is not None:
                age = self._clock.time_msec() - received_ts

            return count, age

        count, age = await self.db_pool.runInteraction(
            "_get_stats_for_federation_staging", _get_stats_for_federation_staging_txn
        )

        number_pdus_in_federation_queue.set(count)
        oldest_pdu_in_federation_staging.set(age)


class EventFederationStore(EventFederationWorkerStore):
    """Responsible for storing and serving up the various graphs associated
    with an event. Including the main event graph and the auth chains for an
    event.

    Also has methods for getting the front (latest) and back (oldest) edges
    of the event graphs. These are used to generate the parents for new events
    and backfilling from another server respectively.
    """

    EVENT_AUTH_STATE_ONLY = "event_auth_state_only"

    def __init__(
        self,
        database: DatabasePool,
        db_conn: LoggingDatabaseConnection,
        hs: "HomeServer",
    ):
        super().__init__(database, db_conn, hs)

        self.db_pool.updates.register_background_update_handler(
            self.EVENT_AUTH_STATE_ONLY, self._background_delete_non_state_event_auth
        )

    async def clean_room_for_join(self, room_id: str) -> None:
        await self.db_pool.runInteraction(
            "clean_room_for_join", self._clean_room_for_join_txn, room_id
        )

    def _clean_room_for_join_txn(self, txn: LoggingTransaction, room_id: str) -> None:
        query = "DELETE FROM event_forward_extremities WHERE room_id = ?"

        txn.execute(query, (room_id,))
        txn.call_after(self.get_latest_event_ids_in_room.invalidate, (room_id,))

    async def _background_delete_non_state_event_auth(
        self, progress: JsonDict, batch_size: int
    ) -> int:
        def delete_event_auth(txn: LoggingTransaction) -> bool:
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
                    LEFT JOIN state_events AS se USING (room_id, event_id)
                    WHERE ? <= stream_ordering AND stream_ordering < ?
                        AND se.state_key IS null
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
