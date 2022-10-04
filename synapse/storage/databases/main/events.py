# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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
from collections import OrderedDict
from http import HTTPStatus
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Generator,
    Iterable,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import attr
from prometheus_client import Counter

import synapse.metrics
from synapse.api.constants import EventContentFields, EventTypes
from synapse.api.errors import Codes, SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase, relation_from_event
from synapse.events.snapshot import EventContext
from synapse.logging.opentracing import trace
from synapse.storage._base import db_to_json, make_in_list_sql_clause
from synapse.storage.database import (
    DatabasePool,
    LoggingDatabaseConnection,
    LoggingTransaction,
)
from synapse.storage.databases.main.events_worker import EventCacheEntry
from synapse.storage.databases.main.search import SearchEntry
from synapse.storage.engines import PostgresEngine
from synapse.storage.util.id_generators import AbstractStreamIdGenerator
from synapse.storage.util.sequence import SequenceGenerator
from synapse.types import JsonDict, StateMap, get_domain_from_id
from synapse.util import json_encoder
from synapse.util.iterutils import batch_iter, sorted_topologically
from synapse.util.stringutils import non_null_str_or_none

if TYPE_CHECKING:
    from synapse.server import HomeServer
    from synapse.storage.databases.main import DataStore


logger = logging.getLogger(__name__)

persist_event_counter = Counter("synapse_storage_events_persisted_events", "")
event_counter = Counter(
    "synapse_storage_events_persisted_events_sep",
    "",
    ["type", "origin_type", "origin_entity"],
)


class PartialStateConflictError(SynapseError):
    """An internal error raised when attempting to persist an event with partial state
    after the room containing the event has been un-partial stated.

    This error should be handled by recomputing the event context and trying again.

    This error has an HTTP status code so that it can be transported over replication.
    It should not be exposed to clients.
    """

    def __init__(self) -> None:
        super().__init__(
            HTTPStatus.CONFLICT,
            msg="Cannot persist partial state event in un-partial stated room",
            errcode=Codes.UNKNOWN,
        )


@attr.s(slots=True, auto_attribs=True)
class DeltaState:
    """Deltas to use to update the `current_state_events` table.

    Attributes:
        to_delete: List of type/state_keys to delete from current state
        to_insert: Map of state to upsert into current state
        no_longer_in_room: The server is not longer in the room, so the room
            should e.g. be removed from `current_state_events` table.
    """

    to_delete: List[Tuple[str, str]]
    to_insert: StateMap[str]
    no_longer_in_room: bool = False


class PersistEventsStore:
    """Contains all the functions for writing events to the database.

    Should only be instantiated on one process (when using a worker mode setup).

    Note: This is not part of the `DataStore` mixin.
    """

    def __init__(
        self,
        hs: "HomeServer",
        db: DatabasePool,
        main_data_store: "DataStore",
        db_conn: LoggingDatabaseConnection,
    ):
        self.hs = hs
        self.db_pool = db
        self.store = main_data_store
        self.database_engine = db.engine
        self._clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()

        self._ephemeral_messages_enabled = hs.config.server.enable_ephemeral_messages
        self.is_mine_id = hs.is_mine_id

        # This should only exist on instances that are configured to write
        assert (
            hs.get_instance_name() in hs.config.worker.writers.events
        ), "Can only instantiate EventsStore on master"

        # Since we have been configured to write, we ought to have id generators,
        # rather than id trackers.
        assert isinstance(self.store._backfill_id_gen, AbstractStreamIdGenerator)
        assert isinstance(self.store._stream_id_gen, AbstractStreamIdGenerator)

        # Ideally we'd move these ID gens here, unfortunately some other ID
        # generators are chained off them so doing so is a bit of a PITA.
        self._backfill_id_gen: AbstractStreamIdGenerator = self.store._backfill_id_gen
        self._stream_id_gen: AbstractStreamIdGenerator = self.store._stream_id_gen

    @trace
    async def _persist_events_and_state_updates(
        self,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        *,
        state_delta_for_room: Dict[str, DeltaState],
        new_forward_extremities: Dict[str, Set[str]],
        use_negative_stream_ordering: bool = False,
        inhibit_local_membership_updates: bool = False,
    ) -> None:
        """Persist a set of events alongside updates to the current state and
        forward extremities tables.

        Args:
            events_and_contexts:
            state_delta_for_room: Map from room_id to the delta to apply to
                room state
            new_forward_extremities: Map from room_id to set of event IDs
                that are the new forward extremities of the room.
            use_negative_stream_ordering: Whether to start stream_ordering on
                the negative side and decrement. This should be set as True
                for backfilled events because backfilled events get a negative
                stream ordering so they don't come down incremental `/sync`.
            inhibit_local_membership_updates: Stop the local_current_membership
                from being updated by these events. This should be set to True
                for backfilled events because backfilled events in the past do
                not affect the current local state.

        Returns:
            Resolves when the events have been persisted

        Raises:
            PartialStateConflictError: if attempting to persist a partial state event in
                a room that has been un-partial stated.
        """

        # We want to calculate the stream orderings as late as possible, as
        # we only notify after all events with a lesser stream ordering have
        # been persisted. I.e. if we spend 10s inside the with block then
        # that will delay all subsequent events from being notified about.
        # Hence why we do it down here rather than wrapping the entire
        # function.
        #
        # Its safe to do this after calculating the state deltas etc as we
        # only need to protect the *persistence* of the events. This is to
        # ensure that queries of the form "fetch events since X" don't
        # return events and stream positions after events that are still in
        # flight, as otherwise subsequent requests "fetch event since Y"
        # will not return those events.
        #
        # Note: Multiple instances of this function cannot be in flight at
        # the same time for the same room.
        if use_negative_stream_ordering:
            stream_ordering_manager = self._backfill_id_gen.get_next_mult(
                len(events_and_contexts)
            )
        else:
            stream_ordering_manager = self._stream_id_gen.get_next_mult(
                len(events_and_contexts)
            )

        async with stream_ordering_manager as stream_orderings:
            for (event, _), stream in zip(events_and_contexts, stream_orderings):
                event.internal_metadata.stream_ordering = stream

            await self.db_pool.runInteraction(
                "persist_events",
                self._persist_events_txn,
                events_and_contexts=events_and_contexts,
                inhibit_local_membership_updates=inhibit_local_membership_updates,
                state_delta_for_room=state_delta_for_room,
                new_forward_extremities=new_forward_extremities,
            )
            persist_event_counter.inc(len(events_and_contexts))

            if not use_negative_stream_ordering:
                # we don't want to set the event_persisted_position to a negative
                # stream_ordering.
                synapse.metrics.event_persisted_position.set(stream)

            for event, context in events_and_contexts:
                if context.app_service:
                    origin_type = "local"
                    origin_entity = context.app_service.id
                elif self.hs.is_mine_id(event.sender):
                    origin_type = "local"
                    origin_entity = "*client*"
                else:
                    origin_type = "remote"
                    origin_entity = get_domain_from_id(event.sender)

                event_counter.labels(event.type, origin_type, origin_entity).inc()

            for room_id, latest_event_ids in new_forward_extremities.items():
                self.store.get_latest_event_ids_in_room.prefill(
                    (room_id,), list(latest_event_ids)
                )

    async def _get_events_which_are_prevs(self, event_ids: Iterable[str]) -> List[str]:
        """Filter the supplied list of event_ids to get those which are prev_events of
        existing (non-outlier/rejected) events.

        Args:
            event_ids: event ids to filter

        Returns:
            Filtered event ids
        """
        results: List[str] = []

        def _get_events_which_are_prevs_txn(
            txn: LoggingTransaction, batch: Collection[str]
        ) -> None:
            sql = """
            SELECT prev_event_id, internal_metadata
            FROM event_edges
                INNER JOIN events USING (event_id)
                LEFT JOIN rejections USING (event_id)
                LEFT JOIN event_json USING (event_id)
            WHERE
                NOT events.outlier
                AND rejections.event_id IS NULL
                AND
            """

            clause, args = make_in_list_sql_clause(
                self.database_engine, "prev_event_id", batch
            )

            txn.execute(sql + clause, args)
            results.extend(r[0] for r in txn if not db_to_json(r[1]).get("soft_failed"))

        for chunk in batch_iter(event_ids, 100):
            await self.db_pool.runInteraction(
                "_get_events_which_are_prevs", _get_events_which_are_prevs_txn, chunk
            )

        return results

    async def _get_prevs_before_rejected(self, event_ids: Iterable[str]) -> Set[str]:
        """Get soft-failed ancestors to remove from the extremities.

        Given a set of events, find all those that have been soft-failed or
        rejected. Returns those soft failed/rejected events and their prev
        events (whether soft-failed/rejected or not), and recurses up the
        prev-event graph until it finds no more soft-failed/rejected events.

        This is used to find extremities that are ancestors of new events, but
        are separated by soft failed events.

        Args:
            event_ids: Events to find prev events for. Note that these must have
                already been persisted.

        Returns:
            The previous events.
        """

        # The set of event_ids to return. This includes all soft-failed events
        # and their prev events.
        existing_prevs = set()

        def _get_prevs_before_rejected_txn(
            txn: LoggingTransaction, batch: Collection[str]
        ) -> None:
            to_recursively_check = batch

            while to_recursively_check:
                sql = """
                SELECT
                    event_id, prev_event_id, internal_metadata,
                    rejections.event_id IS NOT NULL
                FROM event_edges
                    INNER JOIN events USING (event_id)
                    LEFT JOIN rejections USING (event_id)
                    LEFT JOIN event_json USING (event_id)
                WHERE
                    NOT events.outlier
                    AND
                """

                clause, args = make_in_list_sql_clause(
                    self.database_engine, "event_id", to_recursively_check
                )

                txn.execute(sql + clause, args)
                to_recursively_check = []

                for _, prev_event_id, metadata, rejected in txn:
                    if prev_event_id in existing_prevs:
                        continue

                    soft_failed = db_to_json(metadata).get("soft_failed")
                    if soft_failed or rejected:
                        to_recursively_check.append(prev_event_id)
                        existing_prevs.add(prev_event_id)

        for chunk in batch_iter(event_ids, 100):
            await self.db_pool.runInteraction(
                "_get_prevs_before_rejected", _get_prevs_before_rejected_txn, chunk
            )

        return existing_prevs

    def _persist_events_txn(
        self,
        txn: LoggingTransaction,
        *,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        inhibit_local_membership_updates: bool = False,
        state_delta_for_room: Optional[Dict[str, DeltaState]] = None,
        new_forward_extremities: Optional[Dict[str, Set[str]]] = None,
    ) -> None:
        """Insert some number of room events into the necessary database tables.

        Rejected events are only inserted into the events table, the events_json table,
        and the rejections table. Things reading from those table will need to check
        whether the event was rejected.

        Args:
            txn
            events_and_contexts: events to persist
            inhibit_local_membership_updates: Stop the local_current_membership
                from being updated by these events. This should be set to True
                for backfilled events because backfilled events in the past do
                not affect the current local state.
            delete_existing True to purge existing table rows for the events
                from the database. This is useful when retrying due to
                IntegrityError.
            state_delta_for_room: The current-state delta for each room.
            new_forward_extremities: The new forward extremities for each room.
                For each room, a list of the event ids which are the forward
                extremities.

        Raises:
            PartialStateConflictError: if attempting to persist a partial state event in
                a room that has been un-partial stated.
        """
        state_delta_for_room = state_delta_for_room or {}
        new_forward_extremities = new_forward_extremities or {}

        all_events_and_contexts = events_and_contexts

        min_stream_order = events_and_contexts[0][0].internal_metadata.stream_ordering
        max_stream_order = events_and_contexts[-1][0].internal_metadata.stream_ordering

        # We check that the room still exists for events we're trying to
        # persist. This is to protect against races with deleting a room.
        #
        # Annoyingly SQLite doesn't support row level locking.
        if isinstance(self.database_engine, PostgresEngine):
            for room_id in {e.room_id for e, _ in events_and_contexts}:
                txn.execute(
                    "SELECT room_version FROM rooms WHERE room_id = ? FOR SHARE",
                    (room_id,),
                )
                row = txn.fetchone()
                if row is None:
                    raise Exception(f"Room does not exist {room_id}")

        # stream orderings should have been assigned by now
        assert min_stream_order
        assert max_stream_order

        # Once the txn completes, invalidate all of the relevant caches. Note that we do this
        # up here because it captures all the events_and_contexts before any are removed.
        for event, _ in events_and_contexts:
            self.store.invalidate_get_event_cache_after_txn(txn, event.event_id)
            if event.redacts:
                self.store.invalidate_get_event_cache_after_txn(txn, event.redacts)

            relates_to = None
            relation = relation_from_event(event)
            if relation:
                relates_to = relation.parent_id

            assert event.internal_metadata.stream_ordering is not None
            txn.call_after(
                self.store._invalidate_caches_for_event,
                event.internal_metadata.stream_ordering,
                event.event_id,
                event.room_id,
                event.type,
                getattr(event, "state_key", None),
                event.redacts,
                relates_to,
                backfilled=False,
            )

        self._update_forward_extremities_txn(
            txn,
            new_forward_extremities=new_forward_extremities,
            max_stream_order=max_stream_order,
        )

        # Ensure that we don't have the same event twice.
        events_and_contexts = self._filter_events_and_contexts_for_duplicates(
            events_and_contexts
        )

        self._update_room_depths_txn(txn, events_and_contexts=events_and_contexts)

        # _update_outliers_txn filters out any events which have already been
        # persisted, and returns the filtered list.
        events_and_contexts = self._update_outliers_txn(
            txn, events_and_contexts=events_and_contexts
        )

        # From this point onwards the events are only events that we haven't
        # seen before.

        self._store_event_txn(txn, events_and_contexts=events_and_contexts)

        self._persist_transaction_ids_txn(txn, events_and_contexts)

        # Insert into event_to_state_groups.
        self._store_event_state_mappings_txn(txn, events_and_contexts)

        self._persist_event_auth_chain_txn(txn, [e for e, _ in events_and_contexts])

        # _store_rejected_events_txn filters out any events which were
        # rejected, and returns the filtered list.
        events_and_contexts = self._store_rejected_events_txn(
            txn, events_and_contexts=events_and_contexts
        )

        # From this point onwards the events are only ones that weren't
        # rejected.

        self._update_metadata_tables_txn(
            txn,
            events_and_contexts=events_and_contexts,
            all_events_and_contexts=all_events_and_contexts,
            inhibit_local_membership_updates=inhibit_local_membership_updates,
        )

        # We call this last as it assumes we've inserted the events into
        # room_memberships, where applicable.
        # NB: This function invalidates all state related caches
        self._update_current_state_txn(txn, state_delta_for_room, min_stream_order)

    def _persist_event_auth_chain_txn(
        self,
        txn: LoggingTransaction,
        events: List[EventBase],
    ) -> None:

        # We only care about state events, so this if there are no state events.
        if not any(e.is_state() for e in events):
            return

        # We want to store event_auth mappings for rejected events, as they're
        # used in state res v2.
        # This is only necessary if the rejected event appears in an accepted
        # event's auth chain, but its easier for now just to store them (and
        # it doesn't take much storage compared to storing the entire event
        # anyway).
        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_auth",
            keys=("event_id", "room_id", "auth_id"),
            values=[
                (event.event_id, event.room_id, auth_id)
                for event in events
                for auth_id in event.auth_event_ids()
                if event.is_state()
            ],
        )

        # We now calculate chain ID/sequence numbers for any state events we're
        # persisting. We ignore out of band memberships as we're not in the room
        # and won't have their auth chain (we'll fix it up later if we join the
        # room).
        #
        # See: docs/auth_chain_difference_algorithm.md

        # We ignore legacy rooms that we aren't filling the chain cover index
        # for.
        rows = self.db_pool.simple_select_many_txn(
            txn,
            table="rooms",
            column="room_id",
            iterable={event.room_id for event in events if event.is_state()},
            keyvalues={},
            retcols=("room_id", "has_auth_chain_index"),
        )
        rooms_using_chain_index = {
            row["room_id"] for row in rows if row["has_auth_chain_index"]
        }

        state_events = {
            event.event_id: event
            for event in events
            if event.is_state() and event.room_id in rooms_using_chain_index
        }

        if not state_events:
            return

        # We need to know the type/state_key and auth events of the events we're
        # calculating chain IDs for. We don't rely on having the full Event
        # instances as we'll potentially be pulling more events from the DB and
        # we don't need the overhead of fetching/parsing the full event JSON.
        event_to_types = {
            e.event_id: (e.type, e.state_key) for e in state_events.values()
        }
        event_to_auth_chain = {
            e.event_id: e.auth_event_ids() for e in state_events.values()
        }
        event_to_room_id = {e.event_id: e.room_id for e in state_events.values()}

        self._add_chain_cover_index(
            txn,
            self.db_pool,
            self.store.event_chain_id_gen,
            event_to_room_id,
            event_to_types,
            event_to_auth_chain,
        )

    @classmethod
    def _add_chain_cover_index(
        cls,
        txn: LoggingTransaction,
        db_pool: DatabasePool,
        event_chain_id_gen: SequenceGenerator,
        event_to_room_id: Dict[str, str],
        event_to_types: Dict[str, Tuple[str, str]],
        event_to_auth_chain: Dict[str, Sequence[str]],
    ) -> None:
        """Calculate the chain cover index for the given events.

        Args:
            event_to_room_id: Event ID to the room ID of the event
            event_to_types: Event ID to type and state_key of the event
            event_to_auth_chain: Event ID to list of auth event IDs of the
                event (events with no auth events can be excluded).
        """

        # Map from event ID to chain ID/sequence number.
        chain_map: Dict[str, Tuple[int, int]] = {}

        # Set of event IDs to calculate chain ID/seq numbers for.
        events_to_calc_chain_id_for = set(event_to_room_id)

        # We check if there are any events that need to be handled in the rooms
        # we're looking at. These should just be out of band memberships, where
        # we didn't have the auth chain when we first persisted.
        rows = db_pool.simple_select_many_txn(
            txn,
            table="event_auth_chain_to_calculate",
            keyvalues={},
            column="room_id",
            iterable=set(event_to_room_id.values()),
            retcols=("event_id", "type", "state_key"),
        )
        for row in rows:
            event_id = row["event_id"]
            event_type = row["type"]
            state_key = row["state_key"]

            # (We could pull out the auth events for all rows at once using
            # simple_select_many, but this case happens rarely and almost always
            # with a single row.)
            auth_events = db_pool.simple_select_onecol_txn(
                txn,
                "event_auth",
                keyvalues={"event_id": event_id},
                retcol="auth_id",
            )

            events_to_calc_chain_id_for.add(event_id)
            event_to_types[event_id] = (event_type, state_key)
            event_to_auth_chain[event_id] = auth_events

        # First we get the chain ID and sequence numbers for the events'
        # auth events (that aren't also currently being persisted).
        #
        # Note that there there is an edge case here where we might not have
        # calculated chains and sequence numbers for events that were "out
        # of band". We handle this case by fetching the necessary info and
        # adding it to the set of events to calculate chain IDs for.

        missing_auth_chains = {
            a_id
            for auth_events in event_to_auth_chain.values()
            for a_id in auth_events
            if a_id not in events_to_calc_chain_id_for
        }

        # We loop here in case we find an out of band membership and need to
        # fetch their auth event info.
        while missing_auth_chains:
            sql = """
                SELECT event_id, events.type, se.state_key, chain_id, sequence_number
                FROM events
                INNER JOIN state_events AS se USING (event_id)
                LEFT JOIN event_auth_chains USING (event_id)
                WHERE
            """
            clause, args = make_in_list_sql_clause(
                txn.database_engine,
                "event_id",
                missing_auth_chains,
            )
            txn.execute(sql + clause, args)

            missing_auth_chains.clear()

            for (
                auth_id,
                event_type,
                state_key,
                chain_id,
                sequence_number,
            ) in txn.fetchall():
                event_to_types[auth_id] = (event_type, state_key)

                if chain_id is None:
                    # No chain ID, so the event was persisted out of band.
                    # We add to list of events to calculate auth chains for.

                    events_to_calc_chain_id_for.add(auth_id)

                    event_to_auth_chain[auth_id] = db_pool.simple_select_onecol_txn(
                        txn,
                        "event_auth",
                        keyvalues={"event_id": auth_id},
                        retcol="auth_id",
                    )

                    missing_auth_chains.update(
                        e
                        for e in event_to_auth_chain[auth_id]
                        if e not in event_to_types
                    )
                else:
                    chain_map[auth_id] = (chain_id, sequence_number)

        # Now we check if we have any events where we don't have auth chain,
        # this should only be out of band memberships.
        for event_id in sorted_topologically(event_to_auth_chain, event_to_auth_chain):
            for auth_id in event_to_auth_chain[event_id]:
                if (
                    auth_id not in chain_map
                    and auth_id not in events_to_calc_chain_id_for
                ):
                    events_to_calc_chain_id_for.discard(event_id)

                    # If this is an event we're trying to persist we add it to
                    # the list of events to calculate chain IDs for next time
                    # around. (Otherwise we will have already added it to the
                    # table).
                    room_id = event_to_room_id.get(event_id)
                    if room_id:
                        e_type, state_key = event_to_types[event_id]
                        db_pool.simple_insert_txn(
                            txn,
                            table="event_auth_chain_to_calculate",
                            values={
                                "event_id": event_id,
                                "room_id": room_id,
                                "type": e_type,
                                "state_key": state_key,
                            },
                        )

                    # We stop checking the event's auth events since we've
                    # discarded it.
                    break

        if not events_to_calc_chain_id_for:
            return

        # Allocate chain ID/sequence numbers to each new event.
        new_chain_tuples = cls._allocate_chain_ids(
            txn,
            db_pool,
            event_chain_id_gen,
            event_to_room_id,
            event_to_types,
            event_to_auth_chain,
            events_to_calc_chain_id_for,
            chain_map,
        )
        chain_map.update(new_chain_tuples)

        db_pool.simple_insert_many_txn(
            txn,
            table="event_auth_chains",
            keys=("event_id", "chain_id", "sequence_number"),
            values=[
                (event_id, c_id, seq)
                for event_id, (c_id, seq) in new_chain_tuples.items()
            ],
        )

        db_pool.simple_delete_many_txn(
            txn,
            table="event_auth_chain_to_calculate",
            keyvalues={},
            column="event_id",
            values=new_chain_tuples,
        )

        # Now we need to calculate any new links between chains caused by
        # the new events.
        #
        # Links are pairs of chain ID/sequence numbers such that for any
        # event A (CA, SA) and any event B (CB, SB), B is in A's auth chain
        # if and only if there is at least one link (CA, S1) -> (CB, S2)
        # where SA >= S1 and S2 >= SB.
        #
        # We try and avoid adding redundant links to the table, e.g. if we
        # have two links between two chains which both start/end at the
        # sequence number event (or cross) then one can be safely dropped.
        #
        # To calculate new links we look at every new event and:
        #   1. Fetch the chain ID/sequence numbers of its auth events,
        #      discarding any that are reachable by other auth events, or
        #      that have the same chain ID as the event.
        #   2. For each retained auth event we:
        #       a. Add a link from the event's to the auth event's chain
        #          ID/sequence number; and
        #       b. Add a link from the event to every chain reachable by the
        #          auth event.

        # Step 1, fetch all existing links from all the chains we've seen
        # referenced.
        chain_links = _LinkMap()
        rows = db_pool.simple_select_many_txn(
            txn,
            table="event_auth_chain_links",
            column="origin_chain_id",
            iterable={chain_id for chain_id, _ in chain_map.values()},
            keyvalues={},
            retcols=(
                "origin_chain_id",
                "origin_sequence_number",
                "target_chain_id",
                "target_sequence_number",
            ),
        )
        for row in rows:
            chain_links.add_link(
                (row["origin_chain_id"], row["origin_sequence_number"]),
                (row["target_chain_id"], row["target_sequence_number"]),
                new=False,
            )

        # We do this in toplogical order to avoid adding redundant links.
        for event_id in sorted_topologically(
            events_to_calc_chain_id_for, event_to_auth_chain
        ):
            chain_id, sequence_number = chain_map[event_id]

            # Filter out auth events that are reachable by other auth
            # events. We do this by looking at every permutation of pairs of
            # auth events (A, B) to check if B is reachable from A.
            reduction = {
                a_id
                for a_id in event_to_auth_chain.get(event_id, [])
                if chain_map[a_id][0] != chain_id
            }
            for start_auth_id, end_auth_id in itertools.permutations(
                event_to_auth_chain.get(event_id, []),
                r=2,
            ):
                if chain_links.exists_path_from(
                    chain_map[start_auth_id], chain_map[end_auth_id]
                ):
                    reduction.discard(end_auth_id)

            # Step 2, figure out what the new links are from the reduced
            # list of auth events.
            for auth_id in reduction:
                auth_chain_id, auth_sequence_number = chain_map[auth_id]

                # Step 2a, add link between the event and auth event
                chain_links.add_link(
                    (chain_id, sequence_number), (auth_chain_id, auth_sequence_number)
                )

                # Step 2b, add a link to chains reachable from the auth
                # event.
                for target_id, target_seq in chain_links.get_links_from(
                    (auth_chain_id, auth_sequence_number)
                ):
                    if target_id == chain_id:
                        continue

                    chain_links.add_link(
                        (chain_id, sequence_number), (target_id, target_seq)
                    )

        db_pool.simple_insert_many_txn(
            txn,
            table="event_auth_chain_links",
            keys=(
                "origin_chain_id",
                "origin_sequence_number",
                "target_chain_id",
                "target_sequence_number",
            ),
            values=[
                (source_id, source_seq, target_id, target_seq)
                for (
                    source_id,
                    source_seq,
                    target_id,
                    target_seq,
                ) in chain_links.get_additions()
            ],
        )

    @staticmethod
    def _allocate_chain_ids(
        txn: LoggingTransaction,
        db_pool: DatabasePool,
        event_chain_id_gen: SequenceGenerator,
        event_to_room_id: Dict[str, str],
        event_to_types: Dict[str, Tuple[str, str]],
        event_to_auth_chain: Dict[str, Sequence[str]],
        events_to_calc_chain_id_for: Set[str],
        chain_map: Dict[str, Tuple[int, int]],
    ) -> Dict[str, Tuple[int, int]]:
        """Allocates, but does not persist, chain ID/sequence numbers for the
        events in `events_to_calc_chain_id_for`. (c.f. _add_chain_cover_index
        for info on args)
        """

        # We now calculate the chain IDs/sequence numbers for the events. We do
        # this by looking at the chain ID and sequence number of any auth event
        # with the same type/state_key and incrementing the sequence number by
        # one. If there was no match or the chain ID/sequence number is already
        # taken we generate a new chain.
        #
        # We try to reduce the number of times that we hit the database by
        # batching up calls, to make this more efficient when persisting large
        # numbers of state events (e.g. during joins).
        #
        # We do this by:
        #   1. Calculating for each event which auth event will be used to
        #      inherit the chain ID, i.e. converting the auth chain graph to a
        #      tree that we can allocate chains on. We also keep track of which
        #      existing chain IDs have been referenced.
        #   2. Fetching the max allocated sequence number for each referenced
        #      existing chain ID, generating a map from chain ID to the max
        #      allocated sequence number.
        #   3. Iterating over the tree and allocating a chain ID/seq no. to the
        #      new event, by incrementing the sequence number from the
        #      referenced event's chain ID/seq no. and checking that the
        #      incremented sequence number hasn't already been allocated (by
        #      looking in the map generated in the previous step). We generate a
        #      new chain if the sequence number has already been allocated.
        #

        existing_chains: Set[int] = set()
        tree: List[Tuple[str, Optional[str]]] = []

        # We need to do this in a topologically sorted order as we want to
        # generate chain IDs/sequence numbers of an event's auth events before
        # the event itself.
        for event_id in sorted_topologically(
            events_to_calc_chain_id_for, event_to_auth_chain
        ):
            for auth_id in event_to_auth_chain.get(event_id, []):
                if event_to_types.get(event_id) == event_to_types.get(auth_id):
                    existing_chain_id = chain_map.get(auth_id)
                    if existing_chain_id:
                        existing_chains.add(existing_chain_id[0])

                    tree.append((event_id, auth_id))
                    break
            else:
                tree.append((event_id, None))

        # Fetch the current max sequence number for each existing referenced chain.
        sql = """
            SELECT chain_id, MAX(sequence_number) FROM event_auth_chains
            WHERE %s
            GROUP BY chain_id
        """
        clause, args = make_in_list_sql_clause(
            db_pool.engine, "chain_id", existing_chains
        )
        txn.execute(sql % (clause,), args)

        chain_to_max_seq_no: Dict[Any, int] = {row[0]: row[1] for row in txn}

        # Allocate the new events chain ID/sequence numbers.
        #
        # To reduce the number of calls to the database we don't allocate a
        # chain ID number in the loop, instead we use a temporary `object()` for
        # each new chain ID. Once we've done the loop we generate the necessary
        # number of new chain IDs in one call, replacing all temporary
        # objects with real allocated chain IDs.

        unallocated_chain_ids: Set[object] = set()
        new_chain_tuples: Dict[str, Tuple[Any, int]] = {}
        for event_id, auth_event_id in tree:
            # If we reference an auth_event_id we fetch the allocated chain ID,
            # either from the existing `chain_map` or the newly generated
            # `new_chain_tuples` map.
            existing_chain_id = None
            if auth_event_id:
                existing_chain_id = new_chain_tuples.get(auth_event_id)
                if not existing_chain_id:
                    existing_chain_id = chain_map[auth_event_id]

            new_chain_tuple: Optional[Tuple[Any, int]] = None
            if existing_chain_id:
                # We found a chain ID/sequence number candidate, check its
                # not already taken.
                proposed_new_id = existing_chain_id[0]
                proposed_new_seq = existing_chain_id[1] + 1

                if chain_to_max_seq_no[proposed_new_id] < proposed_new_seq:
                    new_chain_tuple = (
                        proposed_new_id,
                        proposed_new_seq,
                    )

            # If we need to start a new chain we allocate a temporary chain ID.
            if not new_chain_tuple:
                new_chain_tuple = (object(), 1)
                unallocated_chain_ids.add(new_chain_tuple[0])

            new_chain_tuples[event_id] = new_chain_tuple
            chain_to_max_seq_no[new_chain_tuple[0]] = new_chain_tuple[1]

        # Generate new chain IDs for all unallocated chain IDs.
        newly_allocated_chain_ids = event_chain_id_gen.get_next_mult_txn(
            txn, len(unallocated_chain_ids)
        )

        # Map from potentially temporary chain ID to real chain ID
        chain_id_to_allocated_map: Dict[Any, int] = dict(
            zip(unallocated_chain_ids, newly_allocated_chain_ids)
        )
        chain_id_to_allocated_map.update((c, c) for c in existing_chains)

        return {
            event_id: (chain_id_to_allocated_map[chain_id], seq)
            for event_id, (chain_id, seq) in new_chain_tuples.items()
        }

    def _persist_transaction_ids_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> None:
        """Persist the mapping from transaction IDs to event IDs (if defined)."""

        to_insert = []
        for event, _ in events_and_contexts:
            token_id = getattr(event.internal_metadata, "token_id", None)
            txn_id = getattr(event.internal_metadata, "txn_id", None)
            if token_id and txn_id:
                to_insert.append(
                    (
                        event.event_id,
                        event.room_id,
                        event.sender,
                        token_id,
                        txn_id,
                        self._clock.time_msec(),
                    )
                )

        if to_insert:
            self.db_pool.simple_insert_many_txn(
                txn,
                table="event_txn_id",
                keys=(
                    "event_id",
                    "room_id",
                    "user_id",
                    "token_id",
                    "txn_id",
                    "inserted_ts",
                ),
                values=to_insert,
            )

    async def update_current_state(
        self,
        room_id: str,
        state_delta: DeltaState,
    ) -> None:
        """Update the current state stored in the datatabase for the given room"""

        async with self._stream_id_gen.get_next() as stream_ordering:
            await self.db_pool.runInteraction(
                "update_current_state",
                self._update_current_state_txn,
                state_delta_by_room={room_id: state_delta},
                stream_id=stream_ordering,
            )

    def _update_current_state_txn(
        self,
        txn: LoggingTransaction,
        state_delta_by_room: Dict[str, DeltaState],
        stream_id: int,
    ) -> None:
        for room_id, delta_state in state_delta_by_room.items():
            to_delete = delta_state.to_delete
            to_insert = delta_state.to_insert

            # Figure out the changes of membership to invalidate the
            # `get_rooms_for_user` cache.
            # We find out which membership events we may have deleted
            # and which we have added, then we invalidate the caches for all
            # those users.
            members_changed = {
                state_key
                for ev_type, state_key in itertools.chain(to_delete, to_insert)
                if ev_type == EventTypes.Member
            }

            if delta_state.no_longer_in_room:
                # Server is no longer in the room so we delete the room from
                # current_state_events, being careful we've already updated the
                # rooms.room_version column (which gets populated in a
                # background task).
                self._upsert_room_version_txn(txn, room_id)

                # Before deleting we populate the current_state_delta_stream
                # so that async background tasks get told what happened.
                sql = """
                    INSERT INTO current_state_delta_stream
                        (stream_id, instance_name, room_id, type, state_key, event_id, prev_event_id)
                    SELECT ?, ?, room_id, type, state_key, null, event_id
                        FROM current_state_events
                        WHERE room_id = ?
                """
                txn.execute(sql, (stream_id, self._instance_name, room_id))

                # We also want to invalidate the membership caches for users
                # that were in the room.
                users_in_room = self.store.get_users_in_room_txn(txn, room_id)
                members_changed.update(users_in_room)

                self.db_pool.simple_delete_txn(
                    txn,
                    table="current_state_events",
                    keyvalues={"room_id": room_id},
                )
            else:
                # We're still in the room, so we update the current state as normal.

                # First we add entries to the current_state_delta_stream. We
                # do this before updating the current_state_events table so
                # that we can use it to calculate the `prev_event_id`. (This
                # allows us to not have to pull out the existing state
                # unnecessarily).
                #
                # The stream_id for the update is chosen to be the minimum of the stream_ids
                # for the batch of the events that we are persisting; that means we do not
                # end up in a situation where workers see events before the
                # current_state_delta updates.
                #
                sql = """
                    INSERT INTO current_state_delta_stream
                    (stream_id, instance_name, room_id, type, state_key, event_id, prev_event_id)
                    SELECT ?, ?, ?, ?, ?, ?, (
                        SELECT event_id FROM current_state_events
                        WHERE room_id = ? AND type = ? AND state_key = ?
                    )
                """
                txn.execute_batch(
                    sql,
                    (
                        (
                            stream_id,
                            self._instance_name,
                            room_id,
                            etype,
                            state_key,
                            to_insert.get((etype, state_key)),
                            room_id,
                            etype,
                            state_key,
                        )
                        for etype, state_key in itertools.chain(to_delete, to_insert)
                    ),
                )
                # Now we actually update the current_state_events table

                txn.execute_batch(
                    "DELETE FROM current_state_events"
                    " WHERE room_id = ? AND type = ? AND state_key = ?",
                    (
                        (room_id, etype, state_key)
                        for etype, state_key in itertools.chain(to_delete, to_insert)
                    ),
                )

                # We include the membership in the current state table, hence we do
                # a lookup when we insert. This assumes that all events have already
                # been inserted into room_memberships.
                txn.execute_batch(
                    """INSERT INTO current_state_events
                        (room_id, type, state_key, event_id, membership)
                    VALUES (?, ?, ?, ?, (SELECT membership FROM room_memberships WHERE event_id = ?))
                    """,
                    [
                        (room_id, key[0], key[1], ev_id, ev_id)
                        for key, ev_id in to_insert.items()
                    ],
                )

            # We now update `local_current_membership`. We do this regardless
            # of whether we're still in the room or not to handle the case where
            # e.g. we just got banned (where we need to record that fact here).

            # Note: Do we really want to delete rows here (that we do not
            # subsequently reinsert below)? While technically correct it means
            # we have no record of the fact the user *was* a member of the
            # room but got, say, state reset out of it.
            if to_delete or to_insert:
                txn.execute_batch(
                    "DELETE FROM local_current_membership"
                    " WHERE room_id = ? AND user_id = ?",
                    (
                        (room_id, state_key)
                        for etype, state_key in itertools.chain(to_delete, to_insert)
                        if etype == EventTypes.Member and self.is_mine_id(state_key)
                    ),
                )

            if to_insert:
                txn.execute_batch(
                    """INSERT INTO local_current_membership
                        (room_id, user_id, event_id, membership)
                    VALUES (?, ?, ?, (SELECT membership FROM room_memberships WHERE event_id = ?))
                    """,
                    [
                        (room_id, key[1], ev_id, ev_id)
                        for key, ev_id in to_insert.items()
                        if key[0] == EventTypes.Member and self.is_mine_id(key[1])
                    ],
                )

            txn.call_after(
                self.store._curr_state_delta_stream_cache.entity_has_changed,
                room_id,
                stream_id,
            )

            # Invalidate the various caches
            self.store._invalidate_state_caches_and_stream(
                txn, room_id, members_changed
            )

            # Check if any of the remote membership changes requires us to
            # unsubscribe from their device lists.
            self.store.handle_potentially_left_users_txn(
                txn, {m for m in members_changed if not self.hs.is_mine_id(m)}
            )

    def _upsert_room_version_txn(self, txn: LoggingTransaction, room_id: str) -> None:
        """Update the room version in the database based off current state
        events.

        This is used when we're about to delete current state and we want to
        ensure that the `rooms.room_version` column is up to date.
        """

        sql = """
            SELECT json FROM event_json
            INNER JOIN current_state_events USING (room_id, event_id)
            WHERE room_id = ? AND type = ? AND state_key = ?
        """
        txn.execute(sql, (room_id, EventTypes.Create, ""))
        row = txn.fetchone()
        if row:
            event_json = db_to_json(row[0])
            content = event_json.get("content", {})
            creator = content.get("creator")
            room_version_id = content.get("room_version", RoomVersions.V1.identifier)

            self.db_pool.simple_upsert_txn(
                txn,
                table="rooms",
                keyvalues={"room_id": room_id},
                values={"room_version": room_version_id},
                insertion_values={"is_public": False, "creator": creator},
            )

    def _update_forward_extremities_txn(
        self,
        txn: LoggingTransaction,
        new_forward_extremities: Dict[str, Set[str]],
        max_stream_order: int,
    ) -> None:
        for room_id in new_forward_extremities.keys():
            self.db_pool.simple_delete_txn(
                txn, table="event_forward_extremities", keyvalues={"room_id": room_id}
            )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_forward_extremities",
            keys=("event_id", "room_id"),
            values=[
                (ev_id, room_id)
                for room_id, new_extrem in new_forward_extremities.items()
                for ev_id in new_extrem
            ],
        )
        # We now insert into stream_ordering_to_exterm a mapping from room_id,
        # new stream_ordering to new forward extremeties in the room.
        # This allows us to later efficiently look up the forward extremeties
        # for a room before a given stream_ordering
        self.db_pool.simple_insert_many_txn(
            txn,
            table="stream_ordering_to_exterm",
            keys=("room_id", "event_id", "stream_ordering"),
            values=[
                (room_id, event_id, max_stream_order)
                for room_id, new_extrem in new_forward_extremities.items()
                for event_id in new_extrem
            ],
        )

    @classmethod
    def _filter_events_and_contexts_for_duplicates(
        cls, events_and_contexts: List[Tuple[EventBase, EventContext]]
    ) -> List[Tuple[EventBase, EventContext]]:
        """Ensure that we don't have the same event twice.

        Pick the earliest non-outlier if there is one, else the earliest one.

        Args:
            events_and_contexts (list[(EventBase, EventContext)]):
        Returns:
            list[(EventBase, EventContext)]: filtered list
        """
        new_events_and_contexts: OrderedDict[
            str, Tuple[EventBase, EventContext]
        ] = OrderedDict()
        for event, context in events_and_contexts:
            prev_event_context = new_events_and_contexts.get(event.event_id)
            if prev_event_context:
                if not event.internal_metadata.is_outlier():
                    if prev_event_context[0].internal_metadata.is_outlier():
                        # To ensure correct ordering we pop, as OrderedDict is
                        # ordered by first insertion.
                        new_events_and_contexts.pop(event.event_id, None)
                        new_events_and_contexts[event.event_id] = (event, context)
            else:
                new_events_and_contexts[event.event_id] = (event, context)
        return list(new_events_and_contexts.values())

    def _update_room_depths_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> None:
        """Update min_depth for each room

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
        """
        depth_updates: Dict[str, int] = {}
        for event, context in events_and_contexts:
            # Then update the `stream_ordering` position to mark the latest
            # event as the front of the room. This should not be done for
            # backfilled events because backfilled events have negative
            # stream_ordering and happened in the past so we know that we don't
            # need to update the stream_ordering tip/front for the room.
            assert event.internal_metadata.stream_ordering is not None
            if event.internal_metadata.stream_ordering >= 0:
                txn.call_after(
                    self.store._events_stream_cache.entity_has_changed,
                    event.room_id,
                    event.internal_metadata.stream_ordering,
                )

            if not event.internal_metadata.is_outlier() and not context.rejected:
                depth_updates[event.room_id] = max(
                    event.depth, depth_updates.get(event.room_id, event.depth)
                )

        for room_id, depth in depth_updates.items():
            self._update_min_depth_for_room_txn(txn, room_id, depth)

    def _update_outliers_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> List[Tuple[EventBase, EventContext]]:
        """Update any outliers with new event info.

        This turns outliers into ex-outliers (unless the new event was rejected), and
        also removes any other events we have already seen from the list.

        Args:
            txn: db connection
            events_and_contexts: events we are persisting

        Returns:
            new list, without events which are already in the events table.

        Raises:
            PartialStateConflictError: if attempting to persist a partial state event in
                a room that has been un-partial stated.
        """
        txn.execute(
            "SELECT event_id, outlier FROM events WHERE event_id in (%s)"
            % (",".join(["?"] * len(events_and_contexts)),),
            [event.event_id for event, _ in events_and_contexts],
        )

        have_persisted: Dict[str, bool] = {
            event_id: outlier for event_id, outlier in txn
        }

        logger.debug(
            "_update_outliers_txn: events=%s have_persisted=%s",
            [ev.event_id for ev, _ in events_and_contexts],
            have_persisted,
        )

        to_remove = set()
        for event, context in events_and_contexts:
            outlier_persisted = have_persisted.get(event.event_id)
            logger.debug(
                "_update_outliers_txn: event=%s outlier=%s outlier_persisted=%s",
                event.event_id,
                event.internal_metadata.is_outlier(),
                outlier_persisted,
            )

            # Ignore events which we haven't persisted at all
            if outlier_persisted is None:
                continue

            to_remove.add(event)

            if context.rejected:
                # If the incoming event is rejected then we don't care if the event
                # was an outlier or not - what we have is at least as good.
                continue

            if not event.internal_metadata.is_outlier() and outlier_persisted:
                # We received a copy of an event that we had already stored as
                # an outlier in the database. We now have some state at that event
                # so we need to update the state_groups table with that state.
                #
                # Note that we do not update the stream_ordering of the event in this
                # scenario. XXX: does this cause bugs? It will mean we won't send such
                # events down /sync. In general they will be historical events, so that
                # doesn't matter too much, but that is not always the case.

                logger.info(
                    "_update_outliers_txn: Updating state for ex-outlier event %s",
                    event.event_id,
                )

                # insert into event_to_state_groups.
                try:
                    self._store_event_state_mappings_txn(txn, ((event, context),))
                except Exception:
                    logger.exception("")
                    raise

                # Add an entry to the ex_outlier_stream table to replicate the
                # change in outlier status to our workers.
                stream_order = event.internal_metadata.stream_ordering
                state_group_id = context.state_group
                self.db_pool.simple_insert_txn(
                    txn,
                    table="ex_outlier_stream",
                    values={
                        "event_stream_ordering": stream_order,
                        "event_id": event.event_id,
                        "state_group": state_group_id,
                        "instance_name": self._instance_name,
                    },
                )

                sql = "UPDATE events SET outlier = ? WHERE event_id = ?"
                txn.execute(sql, (False, event.event_id))

                # Update the event_backward_extremities table now that this
                # event isn't an outlier any more.
                self._update_backward_extremeties(txn, [event])

        return [ec for ec in events_and_contexts if ec[0] not in to_remove]

    def _store_event_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: Collection[Tuple[EventBase, EventContext]],
    ) -> None:
        """Insert new events into the event, event_json, redaction and
        state_events tables.
        """

        if not events_and_contexts:
            # nothing to do here
            return

        def event_dict(event: EventBase) -> JsonDict:
            d = event.get_dict()
            d.pop("redacted", None)
            d.pop("redacted_because", None)
            return d

        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_json",
            keys=("event_id", "room_id", "internal_metadata", "json", "format_version"),
            values=(
                (
                    event.event_id,
                    event.room_id,
                    json_encoder.encode(event.internal_metadata.get_dict()),
                    json_encoder.encode(event_dict(event)),
                    event.format_version,
                )
                for event, _ in events_and_contexts
            ),
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="events",
            keys=(
                "instance_name",
                "stream_ordering",
                "topological_ordering",
                "depth",
                "event_id",
                "room_id",
                "type",
                "processed",
                "outlier",
                "origin_server_ts",
                "received_ts",
                "sender",
                "contains_url",
                "state_key",
                "rejection_reason",
            ),
            values=(
                (
                    self._instance_name,
                    event.internal_metadata.stream_ordering,
                    event.depth,  # topological_ordering
                    event.depth,  # depth
                    event.event_id,
                    event.room_id,
                    event.type,
                    True,  # processed
                    event.internal_metadata.is_outlier(),
                    int(event.origin_server_ts),
                    self._clock.time_msec(),
                    event.sender,
                    "url" in event.content and isinstance(event.content["url"], str),
                    event.get_state_key(),
                    context.rejected,
                )
                for event, context in events_and_contexts
            ),
        )

        # If we're persisting an unredacted event we go and ensure
        # that we mark any redactions that reference this event as
        # requiring censoring.
        unredacted_events = [
            event.event_id
            for event, _ in events_and_contexts
            if not event.internal_metadata.is_redacted()
        ]
        sql = "UPDATE redactions SET have_censored = ? WHERE "
        clause, args = make_in_list_sql_clause(
            self.database_engine,
            "redacts",
            unredacted_events,
        )
        txn.execute(sql + clause, [False] + args)

        self.db_pool.simple_insert_many_txn(
            txn,
            table="state_events",
            keys=("event_id", "room_id", "type", "state_key"),
            values=(
                (event.event_id, event.room_id, event.type, event.state_key)
                for event, _ in events_and_contexts
                if event.is_state()
            ),
        )

    def _store_rejected_events_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> List[Tuple[EventBase, EventContext]]:
        """Add rows to the 'rejections' table for received events which were
        rejected

        Args:
            txn: db connection
            events_and_contexts: events we are persisting

        Returns:
            new list, without the rejected events.
        """
        # Remove the rejected events from the list now that we've added them
        # to the events table and the events_json table.
        to_remove = set()
        for event, context in events_and_contexts:
            if context.rejected:
                # Insert the event_id into the rejections table
                # (events.rejection_reason has already been done)
                self._store_rejections_txn(txn, event.event_id, context.rejected)
                to_remove.add(event)

        return [ec for ec in events_and_contexts if ec[0] not in to_remove]

    def _update_metadata_tables_txn(
        self,
        txn: LoggingTransaction,
        *,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        all_events_and_contexts: List[Tuple[EventBase, EventContext]],
        inhibit_local_membership_updates: bool = False,
    ) -> None:
        """Update all the miscellaneous tables for new events

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
            all_events_and_contexts (list[(EventBase, EventContext)]): all
                events that we were going to persist. This includes events
                we've already persisted, etc, that wouldn't appear in
                events_and_context.
            inhibit_local_membership_updates: Stop the local_current_membership
                from being updated by these events. This should be set to True
                for backfilled events because backfilled events in the past do
                not affect the current local state.
        """

        # Insert all the push actions into the event_push_actions table.
        self._set_push_actions_for_event_and_users_txn(
            txn,
            events_and_contexts=events_and_contexts,
            all_events_and_contexts=all_events_and_contexts,
        )

        if not events_and_contexts:
            # nothing to do here
            return

        for event, _ in events_and_contexts:
            if event.type == EventTypes.Redaction and event.redacts is not None:
                # Remove the entries in the event_push_actions table for the
                # redacted event.
                self._remove_push_actions_for_event_id_txn(
                    txn, event.room_id, event.redacts
                )

                # Remove from relations table.
                self._handle_redact_relations(txn, event.redacts)

        # Update the event_forward_extremities, event_backward_extremities and
        # event_edges tables.
        self._handle_mult_prev_events(
            txn, events=[event for event, _ in events_and_contexts]
        )

        for event, _ in events_and_contexts:
            if event.type == EventTypes.Name:
                # Insert into the event_search table.
                self._store_room_name_txn(txn, event)
            elif event.type == EventTypes.Topic:
                # Insert into the event_search table.
                self._store_room_topic_txn(txn, event)
            elif event.type == EventTypes.Message:
                # Insert into the event_search table.
                self._store_room_message_txn(txn, event)
            elif event.type == EventTypes.Redaction and event.redacts is not None:
                # Insert into the redactions table.
                self._store_redaction(txn, event)
            elif event.type == EventTypes.Retention:
                # Update the room_retention table.
                self._store_retention_policy_for_room_txn(txn, event)

            self._handle_event_relations(txn, event)

            self._handle_insertion_event(txn, event)
            self._handle_batch_event(txn, event)

            # Store the labels for this event.
            labels = event.content.get(EventContentFields.LABELS)
            if labels:
                self.insert_labels_for_event_txn(
                    txn, event.event_id, labels, event.room_id, event.depth
                )

            if self._ephemeral_messages_enabled:
                # If there's an expiry timestamp on the event, store it.
                expiry_ts = event.content.get(EventContentFields.SELF_DESTRUCT_AFTER)
                if isinstance(expiry_ts, int) and not event.is_state():
                    self._insert_event_expiry_txn(txn, event.event_id, expiry_ts)

        # Insert into the room_memberships table.
        self._store_room_members_txn(
            txn,
            [
                event
                for event, _ in events_and_contexts
                if event.type == EventTypes.Member
            ],
            inhibit_local_membership_updates=inhibit_local_membership_updates,
        )

        # Prefill the event cache
        self._add_to_cache(txn, events_and_contexts)

    def _add_to_cache(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> None:
        to_prefill = []

        rows = []

        ev_map = {e.event_id: e for e, _ in events_and_contexts}
        if not ev_map:
            return

        sql = (
            "SELECT "
            " e.event_id as event_id, "
            " r.redacts as redacts,"
            " rej.event_id as rejects "
            " FROM events as e"
            " LEFT JOIN rejections as rej USING (event_id)"
            " LEFT JOIN redactions as r ON e.event_id = r.redacts"
            " WHERE "
        )

        clause, args = make_in_list_sql_clause(
            self.database_engine, "e.event_id", list(ev_map)
        )

        txn.execute(sql + clause, args)
        rows = self.db_pool.cursor_to_dict(txn)
        for row in rows:
            event = ev_map[row["event_id"]]
            if not row["rejects"] and not row["redacts"]:
                to_prefill.append(EventCacheEntry(event=event, redacted_event=None))

        async def prefill() -> None:
            for cache_entry in to_prefill:
                await self.store._get_event_cache.set(
                    (cache_entry.event.event_id,), cache_entry
                )

        txn.async_call_after(prefill)

    def _store_redaction(self, txn: LoggingTransaction, event: EventBase) -> None:
        assert event.redacts is not None
        self.db_pool.simple_upsert_txn(
            txn,
            table="redactions",
            keyvalues={"event_id": event.event_id},
            values={
                "redacts": event.redacts,
                "received_ts": self._clock.time_msec(),
            },
        )

    def insert_labels_for_event_txn(
        self,
        txn: LoggingTransaction,
        event_id: str,
        labels: List[str],
        room_id: str,
        topological_ordering: int,
    ) -> None:
        """Store the mapping between an event's ID and its labels, with one row per
        (event_id, label) tuple.

        Args:
            txn: The transaction to execute.
            event_id: The event's ID.
            labels: A list of text labels.
            room_id: The ID of the room the event was sent to.
            topological_ordering: The position of the event in the room's topology.
        """
        self.db_pool.simple_insert_many_txn(
            txn=txn,
            table="event_labels",
            keys=("event_id", "label", "room_id", "topological_ordering"),
            values=[
                (event_id, label, room_id, topological_ordering) for label in labels
            ],
        )

    def _insert_event_expiry_txn(
        self, txn: LoggingTransaction, event_id: str, expiry_ts: int
    ) -> None:
        """Save the expiry timestamp associated with a given event ID.

        Args:
            txn: The database transaction to use.
            event_id: The event ID the expiry timestamp is associated with.
            expiry_ts: The timestamp at which to expire (delete) the event.
        """
        self.db_pool.simple_insert_txn(
            txn=txn,
            table="event_expiry",
            values={"event_id": event_id, "expiry_ts": expiry_ts},
        )

    def _store_room_members_txn(
        self,
        txn: LoggingTransaction,
        events: List[EventBase],
        *,
        inhibit_local_membership_updates: bool = False,
    ) -> None:
        """
        Store a room member in the database.

        Args:
            txn: The transaction to use.
            events: List of events to store.
            inhibit_local_membership_updates: Stop the local_current_membership
                from being updated by these events. This should be set to True
                for backfilled events because backfilled events in the past do
                not affect the current local state.
        """

        self.db_pool.simple_insert_many_txn(
            txn,
            table="room_memberships",
            keys=(
                "event_id",
                "user_id",
                "sender",
                "room_id",
                "membership",
                "display_name",
                "avatar_url",
            ),
            values=[
                (
                    event.event_id,
                    event.state_key,
                    event.user_id,
                    event.room_id,
                    event.membership,
                    non_null_str_or_none(event.content.get("displayname")),
                    non_null_str_or_none(event.content.get("avatar_url")),
                )
                for event in events
            ],
        )

        for event in events:
            assert event.internal_metadata.stream_ordering is not None

            # We update the local_current_membership table only if the event is
            # "current", i.e., its something that has just happened.
            #
            # This will usually get updated by the `current_state_events` handling,
            # unless its an outlier, and an outlier is only "current" if it's an "out of
            # band membership", like a remote invite or a rejection of a remote invite.
            if (
                self.is_mine_id(event.state_key)
                and not inhibit_local_membership_updates
                and event.internal_metadata.is_outlier()
                and event.internal_metadata.is_out_of_band_membership()
            ):
                self.db_pool.simple_upsert_txn(
                    txn,
                    table="local_current_membership",
                    keyvalues={"room_id": event.room_id, "user_id": event.state_key},
                    values={
                        "event_id": event.event_id,
                        "membership": event.membership,
                    },
                )

    def _handle_event_relations(
        self, txn: LoggingTransaction, event: EventBase
    ) -> None:
        """Handles inserting relation data during persistence of events

        Args:
            txn: The current database transaction.
            event: The event which might have relations.
        """
        relation = relation_from_event(event)
        if not relation:
            # No relation, nothing to do.
            return

        self.db_pool.simple_insert_txn(
            txn,
            table="event_relations",
            values={
                "event_id": event.event_id,
                "relates_to_id": relation.parent_id,
                "relation_type": relation.rel_type,
                "aggregation_key": relation.aggregation_key,
            },
        )

    def _handle_insertion_event(
        self, txn: LoggingTransaction, event: EventBase
    ) -> None:
        """Handles keeping track of insertion events and edges/connections.
        Part of MSC2716.

        Args:
            txn: The database transaction object
            event: The event to process
        """

        if event.type != EventTypes.MSC2716_INSERTION:
            # Not a insertion event
            return

        # Skip processing an insertion event if the room version doesn't
        # support it or the event is not from the room creator.
        room_version = self.store.get_room_version_txn(txn, event.room_id)
        room_creator = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="rooms",
            keyvalues={"room_id": event.room_id},
            retcol="creator",
            allow_none=True,
        )
        if not room_version.msc2716_historical and (
            not self.hs.config.experimental.msc2716_enabled
            or event.sender != room_creator
        ):
            return

        next_batch_id = event.content.get(EventContentFields.MSC2716_NEXT_BATCH_ID)
        if next_batch_id is None:
            # Invalid insertion event without next batch ID
            return

        logger.debug(
            "_handle_insertion_event (next_batch_id=%s) %s", next_batch_id, event
        )

        # Keep track of the insertion event and the batch ID
        self.db_pool.simple_insert_txn(
            txn,
            table="insertion_events",
            values={
                "event_id": event.event_id,
                "room_id": event.room_id,
                "next_batch_id": next_batch_id,
            },
        )

        # Insert an edge for every prev_event connection
        for prev_event_id in event.prev_event_ids():
            self.db_pool.simple_insert_txn(
                txn,
                table="insertion_event_edges",
                values={
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "insertion_prev_event_id": prev_event_id,
                },
            )

    def _handle_batch_event(self, txn: LoggingTransaction, event: EventBase) -> None:
        """Handles inserting the batch edges/connections between the batch event
        and an insertion event. Part of MSC2716.

        Args:
            txn: The database transaction object
            event: The event to process
        """

        if event.type != EventTypes.MSC2716_BATCH:
            # Not a batch event
            return

        # Skip processing a batch event if the room version doesn't
        # support it or the event is not from the room creator.
        room_version = self.store.get_room_version_txn(txn, event.room_id)
        room_creator = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="rooms",
            keyvalues={"room_id": event.room_id},
            retcol="creator",
            allow_none=True,
        )
        if not room_version.msc2716_historical and (
            not self.hs.config.experimental.msc2716_enabled
            or event.sender != room_creator
        ):
            return

        batch_id = event.content.get(EventContentFields.MSC2716_BATCH_ID)
        if batch_id is None:
            # Invalid batch event without a batch ID
            return

        logger.debug("_handle_batch_event batch_id=%s %s", batch_id, event)

        # Keep track of the insertion event and the batch ID
        self.db_pool.simple_insert_txn(
            txn,
            table="batch_events",
            values={
                "event_id": event.event_id,
                "room_id": event.room_id,
                "batch_id": batch_id,
            },
        )

        # When we receive an event with a `batch_id` referencing the
        # `next_batch_id` of the insertion event, we can remove it from the
        # `insertion_event_extremities` table.
        sql = """
            DELETE FROM insertion_event_extremities WHERE event_id IN (
                SELECT event_id FROM insertion_events
                WHERE next_batch_id = ?
            )
        """

        txn.execute(sql, (batch_id,))

    def _handle_redact_relations(
        self, txn: LoggingTransaction, redacted_event_id: str
    ) -> None:
        """Handles receiving a redaction and checking whether the redacted event
        has any relations which must be removed from the database.

        Args:
            txn
            redacted_event_id: The event that was redacted.
        """

        # Fetch the current relation of the event being redacted.
        redacted_relates_to = self.db_pool.simple_select_one_onecol_txn(
            txn,
            table="event_relations",
            keyvalues={"event_id": redacted_event_id},
            retcol="relates_to_id",
            allow_none=True,
        )
        # Any relation information for the related event must be cleared.
        if redacted_relates_to is not None:
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_relations_for_event, (redacted_relates_to,)
            )
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_aggregation_groups_for_event, (redacted_relates_to,)
            )
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_applicable_edit, (redacted_relates_to,)
            )
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_thread_summary, (redacted_relates_to,)
            )
            self.store._invalidate_cache_and_stream(
                txn, self.store.get_thread_participated, (redacted_relates_to,)
            )
            self.store._invalidate_cache_and_stream(
                txn,
                self.store.get_mutual_event_relations_for_rel_type,
                (redacted_relates_to,),
            )

        self.db_pool.simple_delete_txn(
            txn, table="event_relations", keyvalues={"event_id": redacted_event_id}
        )

    def _store_room_topic_txn(self, txn: LoggingTransaction, event: EventBase) -> None:
        if isinstance(event.content.get("topic"), str):
            self.store_event_search_txn(
                txn, event, "content.topic", event.content["topic"]
            )

    def _store_room_name_txn(self, txn: LoggingTransaction, event: EventBase) -> None:
        if isinstance(event.content.get("name"), str):
            self.store_event_search_txn(
                txn, event, "content.name", event.content["name"]
            )

    def _store_room_message_txn(
        self, txn: LoggingTransaction, event: EventBase
    ) -> None:
        if isinstance(event.content.get("body"), str):
            self.store_event_search_txn(
                txn, event, "content.body", event.content["body"]
            )

    def _store_retention_policy_for_room_txn(
        self, txn: LoggingTransaction, event: EventBase
    ) -> None:
        if not event.is_state():
            logger.debug("Ignoring non-state m.room.retention event")
            return

        if hasattr(event, "content") and (
            "min_lifetime" in event.content or "max_lifetime" in event.content
        ):
            if (
                "min_lifetime" in event.content
                and not isinstance(event.content.get("min_lifetime"), int)
            ) or (
                "max_lifetime" in event.content
                and not isinstance(event.content.get("max_lifetime"), int)
            ):
                # Ignore the event if one of the value isn't an integer.
                return

            self.db_pool.simple_insert_txn(
                txn=txn,
                table="room_retention",
                values={
                    "room_id": event.room_id,
                    "event_id": event.event_id,
                    "min_lifetime": event.content.get("min_lifetime"),
                    "max_lifetime": event.content.get("max_lifetime"),
                },
            )

            self.store._invalidate_cache_and_stream(
                txn, self.store.get_retention_policy_for_room, (event.room_id,)
            )

    def store_event_search_txn(
        self, txn: LoggingTransaction, event: EventBase, key: str, value: str
    ) -> None:
        """Add event to the search table

        Args:
            txn: The database transaction.
            event: The event being added to the search table.
            key: A key describing the search value (one of "content.name",
                "content.topic", or "content.body")
            value: The value from the event's content.
        """
        self.store.store_search_entries_txn(
            txn,
            (
                SearchEntry(
                    key=key,
                    value=value,
                    event_id=event.event_id,
                    room_id=event.room_id,
                    stream_ordering=event.internal_metadata.stream_ordering,
                    origin_server_ts=event.origin_server_ts,
                ),
            ),
        )

    def _set_push_actions_for_event_and_users_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        all_events_and_contexts: List[Tuple[EventBase, EventContext]],
    ) -> None:
        """Handles moving push actions from staging table to main
        event_push_actions table for all events in `events_and_contexts`.

        Also ensures that all events in `all_events_and_contexts` are removed
        from the push action staging area.

        Args:
            events_and_contexts: events we are persisting
            all_events_and_contexts: all events that we were going to persist.
                This includes events we've already persisted, etc, that wouldn't
                appear in events_and_context.
        """

        # Only notifiable events will have push actions associated with them,
        # so let's filter them out. (This makes joining large rooms faster, as
        # these queries took seconds to process all the state events).
        notifiable_events = [
            event
            for event, _ in events_and_contexts
            if event.internal_metadata.is_notifiable()
        ]

        sql = """
            INSERT INTO event_push_actions (
                room_id, event_id, user_id, actions, stream_ordering,
                topological_ordering, notif, highlight, unread, thread_id
            )
            SELECT ?, event_id, user_id, actions, ?, ?, notif, highlight, unread, thread_id
            FROM event_push_actions_staging
            WHERE event_id = ?
        """

        if notifiable_events:
            txn.execute_batch(
                sql,
                (
                    (
                        event.room_id,
                        event.internal_metadata.stream_ordering,
                        event.depth,
                        event.event_id,
                    )
                    for event in notifiable_events
                ),
            )

        # Now we delete the staging area for *all* events that were being
        # persisted.
        txn.execute_batch(
            "DELETE FROM event_push_actions_staging WHERE event_id = ?",
            (
                (event.event_id,)
                for event, _ in all_events_and_contexts
                if event.internal_metadata.is_notifiable()
            ),
        )

    def _remove_push_actions_for_event_id_txn(
        self, txn: LoggingTransaction, room_id: str, event_id: str
    ) -> None:
        txn.execute(
            "DELETE FROM event_push_actions WHERE room_id = ? AND event_id = ?",
            (room_id, event_id),
        )

    def _store_rejections_txn(
        self, txn: LoggingTransaction, event_id: str, reason: str
    ) -> None:
        self.db_pool.simple_insert_txn(
            txn,
            table="rejections",
            values={
                "event_id": event_id,
                "reason": reason,
                "last_check": self._clock.time_msec(),
            },
        )

    def _store_event_state_mappings_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: Collection[Tuple[EventBase, EventContext]],
    ) -> None:
        """
        Raises:
            PartialStateConflictError: if attempting to persist a partial state event in
                a room that has been un-partial stated.
        """
        state_groups = {}
        for event, context in events_and_contexts:
            if event.internal_metadata.is_outlier():
                # double-check that we don't have any events that claim to be outliers
                # *and* have partial state (which is meaningless: we should have no
                # state at all for an outlier)
                if context.partial_state:
                    raise ValueError(
                        "Outlier event %s claims to have partial state", event.event_id
                    )

                continue

            # if the event was rejected, just give it the same state as its
            # predecessor.
            if context.rejected:
                state_groups[event.event_id] = context.state_group_before_event
                continue

            state_groups[event.event_id] = context.state_group

        # if we have partial state for these events, record the fact. (This happens
        # here rather than in _store_event_txn because it also needs to happen when
        # we de-outlier an event.)
        try:
            self.db_pool.simple_insert_many_txn(
                txn,
                table="partial_state_events",
                keys=("room_id", "event_id"),
                values=[
                    (
                        event.room_id,
                        event.event_id,
                    )
                    for event, ctx in events_and_contexts
                    if ctx.partial_state
                ],
            )
        except self.db_pool.engine.module.IntegrityError:
            logger.info(
                "Cannot persist events %s in rooms %s: room has been un-partial stated",
                [
                    event.event_id
                    for event, ctx in events_and_contexts
                    if ctx.partial_state
                ],
                list(
                    {
                        event.room_id
                        for event, ctx in events_and_contexts
                        if ctx.partial_state
                    }
                ),
            )
            raise PartialStateConflictError()

        self.db_pool.simple_upsert_many_txn(
            txn,
            table="event_to_state_groups",
            key_names=["event_id"],
            key_values=[[event_id] for event_id, _ in state_groups.items()],
            value_names=["state_group"],
            value_values=[
                [state_group_id] for _, state_group_id in state_groups.items()
            ],
        )

        for event_id, state_group_id in state_groups.items():
            txn.call_after(
                self.store._get_state_group_for_event.prefill,
                (event_id,),
                state_group_id,
            )

    def _update_min_depth_for_room_txn(
        self, txn: LoggingTransaction, room_id: str, depth: int
    ) -> None:
        min_depth = self.store._get_min_depth_interaction(txn, room_id)

        if min_depth is not None and depth >= min_depth:
            return

        self.db_pool.simple_upsert_txn(
            txn,
            table="room_depth",
            keyvalues={"room_id": room_id},
            values={"min_depth": depth},
        )

    def _handle_mult_prev_events(
        self, txn: LoggingTransaction, events: List[EventBase]
    ) -> None:
        """
        For the given event, update the event edges table and forward and
        backward extremities tables.
        """
        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_edges",
            keys=("event_id", "prev_event_id"),
            values=[
                (ev.event_id, e_id) for ev in events for e_id in ev.prev_event_ids()
            ],
        )

        self._update_backward_extremeties(txn, events)

    def _update_backward_extremeties(
        self, txn: LoggingTransaction, events: List[EventBase]
    ) -> None:
        """Updates the event_backward_extremities tables based on the new/updated
        events being persisted.

        This is called for new events *and* for events that were outliers, but
        are now being persisted as non-outliers.

        Forward extremities are handled when we first start persisting the events.
        """
        # From the events passed in, add all of the prev events as backwards extremities.
        # Ignore any events that are already backwards extrems or outliers.
        query = (
            "INSERT INTO event_backward_extremities (event_id, room_id)"
            " SELECT ?, ? WHERE NOT EXISTS ("
            "   SELECT 1 FROM event_backward_extremities"
            "   WHERE event_id = ? AND room_id = ?"
            " )"
            # 1. Don't add an event as a extremity again if we already persisted it
            # as a non-outlier.
            # 2. Don't add an outlier as an extremity if it has no prev_events
            " AND NOT EXISTS ("
            "   SELECT 1 FROM events"
            "   LEFT JOIN event_edges edge"
            "   ON edge.event_id = events.event_id"
            "   WHERE events.event_id = ? AND events.room_id = ? AND (events.outlier = ? OR edge.event_id IS NULL)"
            " )"
        )

        txn.execute_batch(
            query,
            [
                (e_id, ev.room_id, e_id, ev.room_id, e_id, ev.room_id, False)
                for ev in events
                for e_id in ev.prev_event_ids()
                if not ev.internal_metadata.is_outlier()
            ],
        )

        # Delete all these events that we've already fetched and now know that their
        # prev events are the new backwards extremeties.
        query = (
            "DELETE FROM event_backward_extremities"
            " WHERE event_id = ? AND room_id = ?"
        )
        backward_extremity_tuples_to_remove = [
            (ev.event_id, ev.room_id)
            for ev in events
            if not ev.internal_metadata.is_outlier()
            # If we encountered an event with no prev_events, then we might
            # as well remove it now because it won't ever have anything else
            # to backfill from.
            or len(ev.prev_event_ids()) == 0
        ]
        txn.execute_batch(
            query,
            backward_extremity_tuples_to_remove,
        )

        # Clear out the failed backfill attempts after we successfully pulled
        # the event. Since we no longer need these events as backward
        # extremities, it also means that they won't be backfilled from again so
        # we no longer need to store the backfill attempts around it.
        query = """
            DELETE FROM event_failed_pull_attempts
            WHERE event_id = ? and room_id = ?
        """
        txn.execute_batch(
            query,
            backward_extremity_tuples_to_remove,
        )


@attr.s(slots=True, auto_attribs=True)
class _LinkMap:
    """A helper type for tracking links between chains."""

    # Stores the set of links as nested maps: source chain ID -> target chain ID
    # -> source sequence number -> target sequence number.
    maps: Dict[int, Dict[int, Dict[int, int]]] = attr.Factory(dict)

    # Stores the links that have been added (with new set to true), as tuples of
    # `(source chain ID, source sequence no, target chain ID, target sequence no.)`
    additions: Set[Tuple[int, int, int, int]] = attr.Factory(set)

    def add_link(
        self,
        src_tuple: Tuple[int, int],
        target_tuple: Tuple[int, int],
        new: bool = True,
    ) -> bool:
        """Add a new link between two chains, ensuring no redundant links are added.

        New links should be added in topological order.

        Args:
            src_tuple: The chain ID/sequence number of the source of the link.
            target_tuple: The chain ID/sequence number of the target of the link.
            new: Whether this is a "new" link, i.e. should it be returned
                by `get_additions`.

        Returns:
            True if a link was added, false if the given link was dropped as redundant
        """
        src_chain, src_seq = src_tuple
        target_chain, target_seq = target_tuple

        current_links = self.maps.setdefault(src_chain, {}).setdefault(target_chain, {})

        assert src_chain != target_chain

        if new:
            # Check if the new link is redundant
            for current_seq_src, current_seq_target in current_links.items():
                # If a link "crosses" another link then its redundant. For example
                # in the following link 1 (L1) is redundant, as any event reachable
                # via L1 is *also* reachable via L2.
                #
                #   Chain A     Chain B
                #      |          |
                #   L1 |------    |
                #      |     |    |
                #   L2 |---- | -->|
                #      |     |    |
                #      |     |--->|
                #      |          |
                #      |          |
                #
                # So we only need to keep links which *do not* cross, i.e. links
                # that both start and end above or below an existing link.
                #
                # Note, since we add links in topological ordering we should never
                # see `src_seq` less than `current_seq_src`.

                if current_seq_src <= src_seq and target_seq <= current_seq_target:
                    # This new link is redundant, nothing to do.
                    return False

            self.additions.add((src_chain, src_seq, target_chain, target_seq))

        current_links[src_seq] = target_seq
        return True

    def get_links_from(
        self, src_tuple: Tuple[int, int]
    ) -> Generator[Tuple[int, int], None, None]:
        """Gets the chains reachable from the given chain/sequence number.

        Yields:
            The chain ID and sequence number the link points to.
        """
        src_chain, src_seq = src_tuple
        for target_id, sequence_numbers in self.maps.get(src_chain, {}).items():
            for link_src_seq, target_seq in sequence_numbers.items():
                if link_src_seq <= src_seq:
                    yield target_id, target_seq

    def get_links_between(
        self, source_chain: int, target_chain: int
    ) -> Generator[Tuple[int, int], None, None]:
        """Gets the links between two chains.

        Yields:
            The source and target sequence numbers.
        """

        yield from self.maps.get(source_chain, {}).get(target_chain, {}).items()

    def get_additions(self) -> Generator[Tuple[int, int, int, int], None, None]:
        """Gets any newly added links.

        Yields:
            The source chain ID/sequence number and target chain ID/sequence number
        """

        for src_chain, src_seq, target_chain, _ in self.additions:
            target_seq = self.maps.get(src_chain, {}).get(target_chain, {}).get(src_seq)
            if target_seq is not None:
                yield (src_chain, src_seq, target_chain, target_seq)

    def exists_path_from(
        self,
        src_tuple: Tuple[int, int],
        target_tuple: Tuple[int, int],
    ) -> bool:
        """Checks if there is a path between the source chain ID/sequence and
        target chain ID/sequence.
        """
        src_chain, src_seq = src_tuple
        target_chain, target_seq = target_tuple

        if src_chain == target_chain:
            return target_seq <= src_seq

        links = self.get_links_between(src_chain, target_chain)
        for link_start_seq, link_end_seq in links:
            if link_start_seq <= src_seq and target_seq <= link_end_seq:
                return True

        return False
