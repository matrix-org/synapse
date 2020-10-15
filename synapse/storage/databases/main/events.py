# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from collections import OrderedDict, namedtuple
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, Optional, Set, Tuple

import attr
from prometheus_client import Counter

import synapse.metrics
from synapse.api.constants import EventContentFields, EventTypes, RelationTypes
from synapse.api.room_versions import RoomVersions
from synapse.crypto.event_signing import compute_event_reference_hash
from synapse.events import EventBase  # noqa: F401
from synapse.events.snapshot import EventContext  # noqa: F401
from synapse.logging.utils import log_function
from synapse.storage._base import db_to_json, make_in_list_sql_clause
from synapse.storage.database import DatabasePool, LoggingTransaction
from synapse.storage.databases.main.search import SearchEntry
from synapse.storage.util.id_generators import MultiWriterIdGenerator
from synapse.types import StateMap, get_domain_from_id
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.iterutils import batch_iter

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


def encode_json(json_object):
    """
    Encode a Python object as JSON and return it in a Unicode string.
    """
    out = frozendict_json_encoder.encode(json_object)
    if isinstance(out, bytes):
        out = out.decode("utf8")
    return out


_EventCacheEntry = namedtuple("_EventCacheEntry", ("event", "redacted_event"))


@attr.s(slots=True)
class DeltaState:
    """Deltas to use to update the `current_state_events` table.

    Attributes:
        to_delete: List of type/state_keys to delete from current state
        to_insert: Map of state to upsert into current state
        no_longer_in_room: The server is not longer in the room, so the room
            should e.g. be removed from `current_state_events` table.
    """

    to_delete = attr.ib(type=List[Tuple[str, str]])
    to_insert = attr.ib(type=StateMap[str])
    no_longer_in_room = attr.ib(type=bool, default=False)


class PersistEventsStore:
    """Contains all the functions for writing events to the database.

    Should only be instantiated on one process (when using a worker mode setup).

    Note: This is not part of the `DataStore` mixin.
    """

    def __init__(
        self, hs: "HomeServer", db: DatabasePool, main_data_store: "DataStore"
    ):
        self.hs = hs
        self.db_pool = db
        self.store = main_data_store
        self.database_engine = db.engine
        self._clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()

        self._ephemeral_messages_enabled = hs.config.enable_ephemeral_messages
        self.is_mine_id = hs.is_mine_id

        # Ideally we'd move these ID gens here, unfortunately some other ID
        # generators are chained off them so doing so is a bit of a PITA.
        self._backfill_id_gen = (
            self.store._backfill_id_gen
        )  # type: MultiWriterIdGenerator
        self._stream_id_gen = self.store._stream_id_gen  # type: MultiWriterIdGenerator

        # This should only exist on instances that are configured to write
        assert (
            hs.get_instance_name() in hs.config.worker.writers.events
        ), "Can only instantiate EventsStore on master"

    async def _persist_events_and_state_updates(
        self,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        current_state_for_room: Dict[str, StateMap[str]],
        state_delta_for_room: Dict[str, DeltaState],
        new_forward_extremeties: Dict[str, List[str]],
        backfilled: bool = False,
    ) -> None:
        """Persist a set of events alongside updates to the current state and
        forward extremities tables.

        Args:
            events_and_contexts:
            current_state_for_room: Map from room_id to the current state of
                the room based on forward extremities
            state_delta_for_room: Map from room_id to the delta to apply to
                room state
            new_forward_extremities: Map from room_id to list of event IDs
                that are the new forward extremities of the room.
            backfilled

        Returns:
            Resolves when the events have been persisted
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
        if backfilled:
            stream_ordering_manager = self._backfill_id_gen.get_next_mult(
                len(events_and_contexts)
            )
        else:
            stream_ordering_manager = self._stream_id_gen.get_next_mult(
                len(events_and_contexts)
            )

        async with stream_ordering_manager as stream_orderings:
            for (event, context), stream in zip(events_and_contexts, stream_orderings):
                event.internal_metadata.stream_ordering = stream

            await self.db_pool.runInteraction(
                "persist_events",
                self._persist_events_txn,
                events_and_contexts=events_and_contexts,
                backfilled=backfilled,
                state_delta_for_room=state_delta_for_room,
                new_forward_extremeties=new_forward_extremeties,
            )
            persist_event_counter.inc(len(events_and_contexts))

            if not backfilled:
                # backfilled events have negative stream orderings, so we don't
                # want to set the event_persisted_position to that.
                synapse.metrics.event_persisted_position.set(
                    events_and_contexts[-1][0].internal_metadata.stream_ordering
                )

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

            for room_id, new_state in current_state_for_room.items():
                self.store.get_current_state_ids.prefill((room_id,), new_state)

            for room_id, latest_event_ids in new_forward_extremeties.items():
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
        results = []  # type: List[str]

        def _get_events_which_are_prevs_txn(txn, batch):
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

        def _get_prevs_before_rejected_txn(txn, batch):
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

                for event_id, prev_event_id, metadata, rejected in txn:
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

    @log_function
    def _persist_events_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        backfilled: bool,
        state_delta_for_room: Dict[str, DeltaState] = {},
        new_forward_extremeties: Dict[str, List[str]] = {},
    ):
        """Insert some number of room events into the necessary database tables.

        Rejected events are only inserted into the events table, the events_json table,
        and the rejections table. Things reading from those table will need to check
        whether the event was rejected.

        Args:
            txn
            events_and_contexts: events to persist
            backfilled: True if the events were backfilled
            delete_existing True to purge existing table rows for the events
                from the database. This is useful when retrying due to
                IntegrityError.
            state_delta_for_room: The current-state delta for each room.
            new_forward_extremetie: The new forward extremities for each room.
                For each room, a list of the event ids which are the forward
                extremities.

        """
        all_events_and_contexts = events_and_contexts

        min_stream_order = events_and_contexts[0][0].internal_metadata.stream_ordering
        max_stream_order = events_and_contexts[-1][0].internal_metadata.stream_ordering

        self._update_forward_extremities_txn(
            txn,
            new_forward_extremities=new_forward_extremeties,
            max_stream_order=max_stream_order,
        )

        # Ensure that we don't have the same event twice.
        events_and_contexts = self._filter_events_and_contexts_for_duplicates(
            events_and_contexts
        )

        self._update_room_depths_txn(
            txn, events_and_contexts=events_and_contexts, backfilled=backfilled
        )

        # _update_outliers_txn filters out any events which have already been
        # persisted, and returns the filtered list.
        events_and_contexts = self._update_outliers_txn(
            txn, events_and_contexts=events_and_contexts
        )

        # From this point onwards the events are only events that we haven't
        # seen before.

        self._store_event_txn(txn, events_and_contexts=events_and_contexts)

        # Insert into event_to_state_groups.
        self._store_event_state_mappings_txn(txn, events_and_contexts)

        # We want to store event_auth mappings for rejected events, as they're
        # used in state res v2.
        # This is only necessary if the rejected event appears in an accepted
        # event's auth chain, but its easier for now just to store them (and
        # it doesn't take much storage compared to storing the entire event
        # anyway).
        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_auth",
            values=[
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "auth_id": auth_id,
                }
                for event, _ in events_and_contexts
                for auth_id in event.auth_event_ids()
                if event.is_state()
            ],
        )

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
            backfilled=backfilled,
        )

        # We call this last as it assumes we've inserted the events into
        # room_memberships, where applicable.
        self._update_current_state_txn(txn, state_delta_for_room, min_stream_order)

    def _update_current_state_txn(
        self,
        txn: LoggingTransaction,
        state_delta_by_room: Dict[str, DeltaState],
        stream_id: int,
    ):
        for room_id, delta_state in state_delta_by_room.items():
            to_delete = delta_state.to_delete
            to_insert = delta_state.to_insert

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
                        (stream_id, room_id, type, state_key, event_id, prev_event_id)
                    SELECT ?, room_id, type, state_key, null, event_id
                        FROM current_state_events
                        WHERE room_id = ?
                """
                txn.execute(sql, (stream_id, room_id))

                self.db_pool.simple_delete_txn(
                    txn, table="current_state_events", keyvalues={"room_id": room_id},
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
                    (stream_id, room_id, type, state_key, event_id, prev_event_id)
                    SELECT ?, ?, ?, ?, ?, (
                        SELECT event_id FROM current_state_events
                        WHERE room_id = ? AND type = ? AND state_key = ?
                    )
                """
                txn.executemany(
                    sql,
                    (
                        (
                            stream_id,
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

                txn.executemany(
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
                txn.executemany(
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
                txn.executemany(
                    "DELETE FROM local_current_membership"
                    " WHERE room_id = ? AND user_id = ?",
                    (
                        (room_id, state_key)
                        for etype, state_key in itertools.chain(to_delete, to_insert)
                        if etype == EventTypes.Member and self.is_mine_id(state_key)
                    ),
                )

            if to_insert:
                txn.executemany(
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

            # Figure out the changes of membership to invalidate the
            # `get_rooms_for_user` cache.
            # We find out which membership events we may have deleted
            # and which we have added, then we invlidate the caches for all
            # those users.
            members_changed = {
                state_key
                for ev_type, state_key in itertools.chain(to_delete, to_insert)
                if ev_type == EventTypes.Member
            }

            for member in members_changed:
                txn.call_after(
                    self.store.get_rooms_for_user_with_stream_ordering.invalidate,
                    (member,),
                )

            self.store._invalidate_state_caches_and_stream(
                txn, room_id, members_changed
            )

    def _upsert_room_version_txn(self, txn: LoggingTransaction, room_id: str):
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
        self, txn, new_forward_extremities, max_stream_order
    ):
        for room_id, new_extrem in new_forward_extremities.items():
            self.db_pool.simple_delete_txn(
                txn, table="event_forward_extremities", keyvalues={"room_id": room_id}
            )
            txn.call_after(
                self.store.get_latest_event_ids_in_room.invalidate, (room_id,)
            )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_forward_extremities",
            values=[
                {"event_id": ev_id, "room_id": room_id}
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
            values=[
                {
                    "room_id": room_id,
                    "event_id": event_id,
                    "stream_ordering": max_stream_order,
                }
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
        new_events_and_contexts = (
            OrderedDict()
        )  # type: OrderedDict[str, Tuple[EventBase, EventContext]]
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
        txn,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        backfilled: bool,
    ):
        """Update min_depth for each room

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
            backfilled (bool): True if the events were backfilled
        """
        depth_updates = {}  # type: Dict[str, int]
        for event, context in events_and_contexts:
            # Remove the any existing cache entries for the event_ids
            txn.call_after(self.store._invalidate_get_event_cache, event.event_id)
            if not backfilled:
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

    def _update_outliers_txn(self, txn, events_and_contexts):
        """Update any outliers with new event info.

        This turns outliers into ex-outliers (unless the new event was
        rejected).

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting

        Returns:
            list[(EventBase, EventContext)] new list, without events which
            are already in the events table.
        """
        txn.execute(
            "SELECT event_id, outlier FROM events WHERE event_id in (%s)"
            % (",".join(["?"] * len(events_and_contexts)),),
            [event.event_id for event, _ in events_and_contexts],
        )

        have_persisted = {event_id: outlier for event_id, outlier in txn}

        to_remove = set()
        for event, context in events_and_contexts:
            if event.event_id not in have_persisted:
                continue

            to_remove.add(event)

            if context.rejected:
                # If the event is rejected then we don't care if the event
                # was an outlier or not.
                continue

            outlier_persisted = have_persisted[event.event_id]
            if not event.internal_metadata.is_outlier() and outlier_persisted:
                # We received a copy of an event that we had already stored as
                # an outlier in the database. We now have some state at that
                # so we need to update the state_groups table with that state.

                # insert into event_to_state_groups.
                try:
                    self._store_event_state_mappings_txn(txn, ((event, context),))
                except Exception:
                    logger.exception("")
                    raise

                metadata_json = encode_json(event.internal_metadata.get_dict())

                sql = "UPDATE event_json SET internal_metadata = ? WHERE event_id = ?"
                txn.execute(sql, (metadata_json, event.event_id))

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
                    },
                )

                sql = "UPDATE events SET outlier = ? WHERE event_id = ?"
                txn.execute(sql, (False, event.event_id))

                # Update the event_backward_extremities table now that this
                # event isn't an outlier any more.
                self._update_backward_extremeties(txn, [event])

        return [ec for ec in events_and_contexts if ec[0] not in to_remove]

    def _store_event_txn(self, txn, events_and_contexts):
        """Insert new events into the event and event_json tables

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
        """

        if not events_and_contexts:
            # nothing to do here
            return

        def event_dict(event):
            d = event.get_dict()
            d.pop("redacted", None)
            d.pop("redacted_because", None)
            return d

        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_json",
            values=[
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "internal_metadata": encode_json(
                        event.internal_metadata.get_dict()
                    ),
                    "json": encode_json(event_dict(event)),
                    "format_version": event.format_version,
                }
                for event, _ in events_and_contexts
            ],
        )

        self.db_pool.simple_insert_many_txn(
            txn,
            table="events",
            values=[
                {
                    "instance_name": self._instance_name,
                    "stream_ordering": event.internal_metadata.stream_ordering,
                    "topological_ordering": event.depth,
                    "depth": event.depth,
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "type": event.type,
                    "processed": True,
                    "outlier": event.internal_metadata.is_outlier(),
                    "origin_server_ts": int(event.origin_server_ts),
                    "received_ts": self._clock.time_msec(),
                    "sender": event.sender,
                    "contains_url": (
                        "url" in event.content and isinstance(event.content["url"], str)
                    ),
                }
                for event, _ in events_and_contexts
            ],
        )

        for event, _ in events_and_contexts:
            if not event.internal_metadata.is_redacted():
                # If we're persisting an unredacted event we go and ensure
                # that we mark any redactions that reference this event as
                # requiring censoring.
                self.db_pool.simple_update_txn(
                    txn,
                    table="redactions",
                    keyvalues={"redacts": event.event_id},
                    updatevalues={"have_censored": False},
                )

    def _store_rejected_events_txn(self, txn, events_and_contexts):
        """Add rows to the 'rejections' table for received events which were
        rejected

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting

        Returns:
            list[(EventBase, EventContext)] new list, without the rejected
                events.
        """
        # Remove the rejected events from the list now that we've added them
        # to the events table and the events_json table.
        to_remove = set()
        for event, context in events_and_contexts:
            if context.rejected:
                # Insert the event_id into the rejections table
                self._store_rejections_txn(txn, event.event_id, context.rejected)
                to_remove.add(event)

        return [ec for ec in events_and_contexts if ec[0] not in to_remove]

    def _update_metadata_tables_txn(
        self, txn, events_and_contexts, all_events_and_contexts, backfilled
    ):
        """Update all the miscellaneous tables for new events

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
            all_events_and_contexts (list[(EventBase, EventContext)]): all
                events that we were going to persist. This includes events
                we've already persisted, etc, that wouldn't appear in
                events_and_context.
            backfilled (bool): True if the events were backfilled
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

        for event, context in events_and_contexts:
            if event.type == EventTypes.Redaction and event.redacts is not None:
                # Remove the entries in the event_push_actions table for the
                # redacted event.
                self._remove_push_actions_for_event_id_txn(
                    txn, event.room_id, event.redacts
                )

                # Remove from relations table.
                self._handle_redaction(txn, event.redacts)

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
            backfilled=backfilled,
        )

        # Insert event_reference_hashes table.
        self._store_event_reference_hashes_txn(
            txn, [event for event, _ in events_and_contexts]
        )

        state_events_and_contexts = [
            ec for ec in events_and_contexts if ec[0].is_state()
        ]

        state_values = []
        for event, context in state_events_and_contexts:
            vals = {
                "event_id": event.event_id,
                "room_id": event.room_id,
                "type": event.type,
                "state_key": event.state_key,
            }

            # TODO: How does this work with backfilling?
            if hasattr(event, "replaces_state"):
                vals["prev_state"] = event.replaces_state

            state_values.append(vals)

        self.db_pool.simple_insert_many_txn(
            txn, table="state_events", values=state_values
        )

        # Prefill the event cache
        self._add_to_cache(txn, events_and_contexts)

    def _add_to_cache(self, txn, events_and_contexts):
        to_prefill = []

        rows = []
        N = 200
        for i in range(0, len(events_and_contexts), N):
            ev_map = {e[0].event_id: e[0] for e in events_and_contexts[i : i + N]}
            if not ev_map:
                break

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
                    to_prefill.append(
                        _EventCacheEntry(event=event, redacted_event=None)
                    )

        def prefill():
            for cache_entry in to_prefill:
                self.store._get_event_cache.prefill(
                    (cache_entry[0].event_id,), cache_entry
                )

        txn.call_after(prefill)

    def _store_redaction(self, txn, event):
        # invalidate the cache for the redacted event
        txn.call_after(self.store._invalidate_get_event_cache, event.redacts)

        self.db_pool.simple_insert_txn(
            txn,
            table="redactions",
            values={
                "event_id": event.event_id,
                "redacts": event.redacts,
                "received_ts": self._clock.time_msec(),
            },
        )

    def insert_labels_for_event_txn(
        self, txn, event_id, labels, room_id, topological_ordering
    ):
        """Store the mapping between an event's ID and its labels, with one row per
        (event_id, label) tuple.

        Args:
            txn (LoggingTransaction): The transaction to execute.
            event_id (str): The event's ID.
            labels (list[str]): A list of text labels.
            room_id (str): The ID of the room the event was sent to.
            topological_ordering (int): The position of the event in the room's topology.
        """
        return self.db_pool.simple_insert_many_txn(
            txn=txn,
            table="event_labels",
            values=[
                {
                    "event_id": event_id,
                    "label": label,
                    "room_id": room_id,
                    "topological_ordering": topological_ordering,
                }
                for label in labels
            ],
        )

    def _insert_event_expiry_txn(self, txn, event_id, expiry_ts):
        """Save the expiry timestamp associated with a given event ID.

        Args:
            txn (LoggingTransaction): The database transaction to use.
            event_id (str): The event ID the expiry timestamp is associated with.
            expiry_ts (int): The timestamp at which to expire (delete) the event.
        """
        return self.db_pool.simple_insert_txn(
            txn=txn,
            table="event_expiry",
            values={"event_id": event_id, "expiry_ts": expiry_ts},
        )

    def _store_event_reference_hashes_txn(self, txn, events):
        """Store a hash for a PDU
        Args:
            txn (cursor):
            events (list): list of Events.
        """

        vals = []
        for event in events:
            ref_alg, ref_hash_bytes = compute_event_reference_hash(event)
            vals.append(
                {
                    "event_id": event.event_id,
                    "algorithm": ref_alg,
                    "hash": memoryview(ref_hash_bytes),
                }
            )

        self.db_pool.simple_insert_many_txn(
            txn, table="event_reference_hashes", values=vals
        )

    def _store_room_members_txn(self, txn, events, backfilled):
        """Store a room member in the database.
        """

        def str_or_none(val: Any) -> Optional[str]:
            return val if isinstance(val, str) else None

        self.db_pool.simple_insert_many_txn(
            txn,
            table="room_memberships",
            values=[
                {
                    "event_id": event.event_id,
                    "user_id": event.state_key,
                    "sender": event.user_id,
                    "room_id": event.room_id,
                    "membership": event.membership,
                    "display_name": str_or_none(event.content.get("displayname")),
                    "avatar_url": str_or_none(event.content.get("avatar_url")),
                }
                for event in events
            ],
        )

        for event in events:
            txn.call_after(
                self.store._membership_stream_cache.entity_has_changed,
                event.state_key,
                event.internal_metadata.stream_ordering,
            )
            txn.call_after(
                self.store.get_invited_rooms_for_local_user.invalidate,
                (event.state_key,),
            )

            # We update the local_current_membership table only if the event is
            # "current", i.e., its something that has just happened.
            #
            # This will usually get updated by the `current_state_events` handling,
            # unless its an outlier, and an outlier is only "current" if it's an "out of
            # band membership", like a remote invite or a rejection of a remote invite.
            if (
                self.is_mine_id(event.state_key)
                and not backfilled
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

    def _handle_event_relations(self, txn, event):
        """Handles inserting relation data during peristence of events

        Args:
            txn
            event (EventBase)
        """
        relation = event.content.get("m.relates_to")
        if not relation:
            # No relations
            return

        rel_type = relation.get("rel_type")
        if rel_type not in (
            RelationTypes.ANNOTATION,
            RelationTypes.REFERENCE,
            RelationTypes.REPLACE,
        ):
            # Unknown relation type
            return

        parent_id = relation.get("event_id")
        if not parent_id:
            # Invalid relation
            return

        aggregation_key = relation.get("key")

        self.db_pool.simple_insert_txn(
            txn,
            table="event_relations",
            values={
                "event_id": event.event_id,
                "relates_to_id": parent_id,
                "relation_type": rel_type,
                "aggregation_key": aggregation_key,
            },
        )

        txn.call_after(self.store.get_relations_for_event.invalidate_many, (parent_id,))
        txn.call_after(
            self.store.get_aggregation_groups_for_event.invalidate_many, (parent_id,)
        )

        if rel_type == RelationTypes.REPLACE:
            txn.call_after(self.store.get_applicable_edit.invalidate, (parent_id,))

    def _handle_redaction(self, txn, redacted_event_id):
        """Handles receiving a redaction and checking whether we need to remove
        any redacted relations from the database.

        Args:
            txn
            redacted_event_id (str): The event that was redacted.
        """

        self.db_pool.simple_delete_txn(
            txn, table="event_relations", keyvalues={"event_id": redacted_event_id}
        )

    def _store_room_topic_txn(self, txn, event):
        if hasattr(event, "content") and "topic" in event.content:
            self.store_event_search_txn(
                txn, event, "content.topic", event.content["topic"]
            )

    def _store_room_name_txn(self, txn, event):
        if hasattr(event, "content") and "name" in event.content:
            self.store_event_search_txn(
                txn, event, "content.name", event.content["name"]
            )

    def _store_room_message_txn(self, txn, event):
        if hasattr(event, "content") and "body" in event.content:
            self.store_event_search_txn(
                txn, event, "content.body", event.content["body"]
            )

    def _store_retention_policy_for_room_txn(self, txn, event):
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

    def store_event_search_txn(self, txn, event, key, value):
        """Add event to the search table

        Args:
            txn (cursor):
            event (EventBase):
            key (str):
            value (str):
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
        self, txn, events_and_contexts, all_events_and_contexts
    ):
        """Handles moving push actions from staging table to main
        event_push_actions table for all events in `events_and_contexts`.

        Also ensures that all events in `all_events_and_contexts` are removed
        from the push action staging area.

        Args:
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
            all_events_and_contexts (list[(EventBase, EventContext)]): all
                events that we were going to persist. This includes events
                we've already persisted, etc, that wouldn't appear in
                events_and_context.
        """

        sql = """
            INSERT INTO event_push_actions (
                room_id, event_id, user_id, actions, stream_ordering,
                topological_ordering, notif, highlight, unread
            )
            SELECT ?, event_id, user_id, actions, ?, ?, notif, highlight, unread
            FROM event_push_actions_staging
            WHERE event_id = ?
        """

        if events_and_contexts:
            txn.executemany(
                sql,
                (
                    (
                        event.room_id,
                        event.internal_metadata.stream_ordering,
                        event.depth,
                        event.event_id,
                    )
                    for event, _ in events_and_contexts
                ),
            )

        for event, _ in events_and_contexts:
            user_ids = self.db_pool.simple_select_onecol_txn(
                txn,
                table="event_push_actions_staging",
                keyvalues={"event_id": event.event_id},
                retcol="user_id",
            )

            for uid in user_ids:
                txn.call_after(
                    self.store.get_unread_event_push_actions_by_room_for_user.invalidate_many,
                    (event.room_id, uid),
                )

        # Now we delete the staging area for *all* events that were being
        # persisted.
        txn.executemany(
            "DELETE FROM event_push_actions_staging WHERE event_id = ?",
            ((event.event_id,) for event, _ in all_events_and_contexts),
        )

    def _remove_push_actions_for_event_id_txn(self, txn, room_id, event_id):
        # Sad that we have to blow away the cache for the whole room here
        txn.call_after(
            self.store.get_unread_event_push_actions_by_room_for_user.invalidate_many,
            (room_id,),
        )
        txn.execute(
            "DELETE FROM event_push_actions WHERE room_id = ? AND event_id = ?",
            (room_id, event_id),
        )

    def _store_rejections_txn(self, txn, event_id, reason):
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
        self, txn, events_and_contexts: Iterable[Tuple[EventBase, EventContext]]
    ):
        state_groups = {}
        for event, context in events_and_contexts:
            if event.internal_metadata.is_outlier():
                continue

            # if the event was rejected, just give it the same state as its
            # predecessor.
            if context.rejected:
                state_groups[event.event_id] = context.state_group_before_event
                continue

            state_groups[event.event_id] = context.state_group

        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_to_state_groups",
            values=[
                {"state_group": state_group_id, "event_id": event_id}
                for event_id, state_group_id in state_groups.items()
            ],
        )

        for event_id, state_group_id in state_groups.items():
            txn.call_after(
                self.store._get_state_group_for_event.prefill,
                (event_id,),
                state_group_id,
            )

    def _update_min_depth_for_room_txn(self, txn, room_id, depth):
        min_depth = self.store._get_min_depth_interaction(txn, room_id)

        if min_depth is not None and depth >= min_depth:
            return

        self.db_pool.simple_upsert_txn(
            txn,
            table="room_depth",
            keyvalues={"room_id": room_id},
            values={"min_depth": depth},
        )

    def _handle_mult_prev_events(self, txn, events):
        """
        For the given event, update the event edges table and forward and
        backward extremities tables.
        """
        self.db_pool.simple_insert_many_txn(
            txn,
            table="event_edges",
            values=[
                {
                    "event_id": ev.event_id,
                    "prev_event_id": e_id,
                    "room_id": ev.room_id,
                    "is_state": False,
                }
                for ev in events
                for e_id in ev.prev_event_ids()
            ],
        )

        self._update_backward_extremeties(txn, events)

    def _update_backward_extremeties(self, txn, events):
        """Updates the event_backward_extremities tables based on the new/updated
        events being persisted.

        This is called for new events *and* for events that were outliers, but
        are now being persisted as non-outliers.

        Forward extremities are handled when we first start persisting the events.
        """
        events_by_room = {}  # type: Dict[str, List[EventBase]]
        for ev in events:
            events_by_room.setdefault(ev.room_id, []).append(ev)

        query = (
            "INSERT INTO event_backward_extremities (event_id, room_id)"
            " SELECT ?, ? WHERE NOT EXISTS ("
            " SELECT 1 FROM event_backward_extremities"
            " WHERE event_id = ? AND room_id = ?"
            " )"
            " AND NOT EXISTS ("
            " SELECT 1 FROM events WHERE event_id = ? AND room_id = ? "
            " AND outlier = ?"
            " )"
        )

        txn.executemany(
            query,
            [
                (e_id, ev.room_id, e_id, ev.room_id, e_id, ev.room_id, False)
                for ev in events
                for e_id in ev.prev_event_ids()
                if not ev.internal_metadata.is_outlier()
            ],
        )

        query = (
            "DELETE FROM event_backward_extremities"
            " WHERE event_id = ? AND room_id = ?"
        )
        txn.executemany(
            query,
            [
                (ev.event_id, ev.room_id)
                for ev in events
                if not ev.internal_metadata.is_outlier()
            ],
        )
