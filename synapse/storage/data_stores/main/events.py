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
from collections import Counter as c_counter, OrderedDict, namedtuple
from functools import wraps
from typing import Dict, List, Tuple

from six import iteritems, text_type
from six.moves import range

from canonicaljson import json
from prometheus_client import Counter

from twisted.internet import defer

import synapse.metrics
from synapse.api.constants import EventContentFields, EventTypes
from synapse.api.errors import SynapseError
from synapse.api.room_versions import RoomVersions
from synapse.events import EventBase  # noqa: F401
from synapse.events.snapshot import EventContext  # noqa: F401
from synapse.events.utils import prune_event_dict
from synapse.logging.utils import log_function
from synapse.metrics import BucketCollector
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage._base import make_in_list_sql_clause
from synapse.storage.data_stores.main.event_federation import EventFederationStore
from synapse.storage.data_stores.main.events_worker import EventsWorkerStore
from synapse.storage.data_stores.main.state import StateGroupWorkerStore
from synapse.storage.database import Database, LoggingTransaction
from synapse.storage.persist_events import DeltaState
from synapse.types import RoomStreamToken, StateMap, get_domain_from_id
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.iterutils import batch_iter

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


def _retry_on_integrity_error(func):
    """Wraps a database function so that it gets retried on IntegrityError,
    with `delete_existing=True` passed in.

    Args:
        func: function that returns a Deferred and accepts a `delete_existing` arg
    """

    @wraps(func)
    @defer.inlineCallbacks
    def f(self, *args, **kwargs):
        try:
            res = yield func(self, *args, delete_existing=False, **kwargs)
        except self.database_engine.module.IntegrityError:
            logger.exception("IntegrityError, retrying.")
            res = yield func(self, *args, delete_existing=True, **kwargs)
        return res

    return f


# inherits from EventFederationStore so that we can call _update_backward_extremities
# and _handle_mult_prev_events (though arguably those could both be moved in here)
class EventsStore(
    StateGroupWorkerStore, EventFederationStore, EventsWorkerStore,
):
    def __init__(self, database: Database, db_conn, hs):
        super(EventsStore, self).__init__(database, db_conn, hs)

        # Collect metrics on the number of forward extremities that exist.
        # Counter of number of extremities to count
        self._current_forward_extremities_amount = c_counter()

        BucketCollector(
            "synapse_forward_extremities",
            lambda: self._current_forward_extremities_amount,
            buckets=[1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"],
        )

        # Read the extrems every 60 minutes
        def read_forward_extremities():
            # run as a background process to make sure that the database transactions
            # have a logcontext to report to
            return run_as_background_process(
                "read_forward_extremities", self._read_forward_extremities
            )

        hs.get_clock().looping_call(read_forward_extremities, 60 * 60 * 1000)

        def _censor_redactions():
            return run_as_background_process(
                "_censor_redactions", self._censor_redactions
            )

        if self.hs.config.redaction_retention_period is not None:
            hs.get_clock().looping_call(_censor_redactions, 5 * 60 * 1000)

        self._ephemeral_messages_enabled = hs.config.enable_ephemeral_messages
        self.is_mine_id = hs.is_mine_id

    @defer.inlineCallbacks
    def _read_forward_extremities(self):
        def fetch(txn):
            txn.execute(
                """
                select count(*) c from event_forward_extremities
                group by room_id
                """
            )
            return txn.fetchall()

        res = yield self.db.runInteraction("read_forward_extremities", fetch)
        self._current_forward_extremities_amount = c_counter([x[0] for x in res])

    @_retry_on_integrity_error
    @defer.inlineCallbacks
    def _persist_events_and_state_updates(
        self,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        current_state_for_room: Dict[str, StateMap[str]],
        state_delta_for_room: Dict[str, DeltaState],
        new_forward_extremeties: Dict[str, List[str]],
        backfilled: bool = False,
        delete_existing: bool = False,
    ):
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
            delete_existing

        Returns:
            Deferred: resolves when the events have been persisted
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

        with stream_ordering_manager as stream_orderings:
            for (event, context), stream in zip(events_and_contexts, stream_orderings):
                event.internal_metadata.stream_ordering = stream

            yield self.db.runInteraction(
                "persist_events",
                self._persist_events_txn,
                events_and_contexts=events_and_contexts,
                backfilled=backfilled,
                delete_existing=delete_existing,
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

            for room_id, new_state in iteritems(current_state_for_room):
                self.get_current_state_ids.prefill((room_id,), new_state)

            for room_id, latest_event_ids in iteritems(new_forward_extremeties):
                self.get_latest_event_ids_in_room.prefill(
                    (room_id,), list(latest_event_ids)
                )

    @defer.inlineCallbacks
    def _get_events_which_are_prevs(self, event_ids):
        """Filter the supplied list of event_ids to get those which are prev_events of
        existing (non-outlier/rejected) events.

        Args:
            event_ids (Iterable[str]): event ids to filter

        Returns:
            Deferred[List[str]]: filtered event ids
        """
        results = []

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
            results.extend(r[0] for r in txn if not json.loads(r[1]).get("soft_failed"))

        for chunk in batch_iter(event_ids, 100):
            yield self.db.runInteraction(
                "_get_events_which_are_prevs", _get_events_which_are_prevs_txn, chunk
            )

        return results

    @defer.inlineCallbacks
    def _get_prevs_before_rejected(self, event_ids):
        """Get soft-failed ancestors to remove from the extremities.

        Given a set of events, find all those that have been soft-failed or
        rejected. Returns those soft failed/rejected events and their prev
        events (whether soft-failed/rejected or not), and recurses up the
        prev-event graph until it finds no more soft-failed/rejected events.

        This is used to find extremities that are ancestors of new events, but
        are separated by soft failed events.

        Args:
            event_ids (Iterable[str]): Events to find prev events for. Note
                that these must have already been persisted.

        Returns:
            Deferred[set[str]]
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

                    soft_failed = json.loads(metadata).get("soft_failed")
                    if soft_failed or rejected:
                        to_recursively_check.append(prev_event_id)
                        existing_prevs.add(prev_event_id)

        for chunk in batch_iter(event_ids, 100):
            yield self.db.runInteraction(
                "_get_prevs_before_rejected", _get_prevs_before_rejected_txn, chunk
            )

        return existing_prevs

    @log_function
    def _persist_events_txn(
        self,
        txn: LoggingTransaction,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        backfilled: bool,
        delete_existing: bool = False,
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

        if delete_existing:
            # For paranoia reasons, we go and delete all the existing entries
            # for these events so we can reinsert them.
            # This gets around any problems with some tables already having
            # entries.
            self._delete_existing_rows_txn(txn, events_and_contexts=events_and_contexts)

        self._store_event_txn(txn, events_and_contexts=events_and_contexts)

        # Insert into event_to_state_groups.
        self._store_event_state_mappings_txn(txn, events_and_contexts)

        # We want to store event_auth mappings for rejected events, as they're
        # used in state res v2.
        # This is only necessary if the rejected event appears in an accepted
        # event's auth chain, but its easier for now just to store them (and
        # it doesn't take much storage compared to storing the entire event
        # anyway).
        self.db.simple_insert_many_txn(
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
        for room_id, delta_state in iteritems(state_delta_by_room):
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

                self.db.simple_delete_txn(
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
                        for key, ev_id in iteritems(to_insert)
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
                self._curr_state_delta_stream_cache.entity_has_changed,
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
                    self.get_rooms_for_user_with_stream_ordering.invalidate, (member,)
                )

            self._invalidate_state_caches_and_stream(txn, room_id, members_changed)

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
            event_json = json.loads(row[0])
            content = event_json.get("content", {})
            creator = content.get("creator")
            room_version_id = content.get("room_version", RoomVersions.V1.identifier)

            self.db.simple_upsert_txn(
                txn,
                table="rooms",
                keyvalues={"room_id": room_id},
                values={"room_version": room_version_id},
                insertion_values={"is_public": False, "creator": creator},
            )

    def _update_forward_extremities_txn(
        self, txn, new_forward_extremities, max_stream_order
    ):
        for room_id, new_extrem in iteritems(new_forward_extremities):
            self.db.simple_delete_txn(
                txn, table="event_forward_extremities", keyvalues={"room_id": room_id}
            )
            txn.call_after(self.get_latest_event_ids_in_room.invalidate, (room_id,))

        self.db.simple_insert_many_txn(
            txn,
            table="event_forward_extremities",
            values=[
                {"event_id": ev_id, "room_id": room_id}
                for room_id, new_extrem in iteritems(new_forward_extremities)
                for ev_id in new_extrem
            ],
        )
        # We now insert into stream_ordering_to_exterm a mapping from room_id,
        # new stream_ordering to new forward extremeties in the room.
        # This allows us to later efficiently look up the forward extremeties
        # for a room before a given stream_ordering
        self.db.simple_insert_many_txn(
            txn,
            table="stream_ordering_to_exterm",
            values=[
                {
                    "room_id": room_id,
                    "event_id": event_id,
                    "stream_ordering": max_stream_order,
                }
                for room_id, new_extrem in iteritems(new_forward_extremities)
                for event_id in new_extrem
            ],
        )

    @classmethod
    def _filter_events_and_contexts_for_duplicates(cls, events_and_contexts):
        """Ensure that we don't have the same event twice.

        Pick the earliest non-outlier if there is one, else the earliest one.

        Args:
            events_and_contexts (list[(EventBase, EventContext)]):
        Returns:
            list[(EventBase, EventContext)]: filtered list
        """
        new_events_and_contexts = OrderedDict()
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

    def _update_room_depths_txn(self, txn, events_and_contexts, backfilled):
        """Update min_depth for each room

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]): events
                we are persisting
            backfilled (bool): True if the events were backfilled
        """
        depth_updates = {}
        for event, context in events_and_contexts:
            # Remove the any existing cache entries for the event_ids
            txn.call_after(self._invalidate_get_event_cache, event.event_id)
            if not backfilled:
                txn.call_after(
                    self._events_stream_cache.entity_has_changed,
                    event.room_id,
                    event.internal_metadata.stream_ordering,
                )

            if not event.internal_metadata.is_outlier() and not context.rejected:
                depth_updates[event.room_id] = max(
                    event.depth, depth_updates.get(event.room_id, event.depth)
                )

        for room_id, depth in iteritems(depth_updates):
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
                self.db.simple_insert_txn(
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

    @classmethod
    def _delete_existing_rows_txn(cls, txn, events_and_contexts):
        if not events_and_contexts:
            # nothing to do here
            return

        logger.info("Deleting existing")

        for table in (
            "events",
            "event_auth",
            "event_json",
            "event_edges",
            "event_forward_extremities",
            "event_reference_hashes",
            "event_search",
            "event_to_state_groups",
            "local_invites",
            "state_events",
            "rejections",
            "redactions",
            "room_memberships",
        ):
            txn.executemany(
                "DELETE FROM %s WHERE event_id = ?" % (table,),
                [(ev.event_id,) for ev, _ in events_and_contexts],
            )

        for table in ("event_push_actions",):
            txn.executemany(
                "DELETE FROM %s WHERE room_id = ? AND event_id = ?" % (table,),
                [(ev.room_id, ev.event_id) for ev, _ in events_and_contexts],
            )

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

        self.db.simple_insert_many_txn(
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

        self.db.simple_insert_many_txn(
            txn,
            table="events",
            values=[
                {
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
                        "url" in event.content
                        and isinstance(event.content["url"], text_type)
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
                self.db.simple_update_txn(
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

        self.db.simple_insert_many_txn(txn, table="state_events", values=state_values)

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
            rows = self.db.cursor_to_dict(txn)
            for row in rows:
                event = ev_map[row["event_id"]]
                if not row["rejects"] and not row["redacts"]:
                    to_prefill.append(
                        _EventCacheEntry(event=event, redacted_event=None)
                    )

        def prefill():
            for cache_entry in to_prefill:
                self._get_event_cache.prefill((cache_entry[0].event_id,), cache_entry)

        txn.call_after(prefill)

    def _store_redaction(self, txn, event):
        # invalidate the cache for the redacted event
        txn.call_after(self._invalidate_get_event_cache, event.redacts)

        self.db.simple_insert_txn(
            txn,
            table="redactions",
            values={
                "event_id": event.event_id,
                "redacts": event.redacts,
                "received_ts": self._clock.time_msec(),
            },
        )

    async def _censor_redactions(self):
        """Censors all redactions older than the configured period that haven't
        been censored yet.

        By censor we mean update the event_json table with the redacted event.
        """

        if self.hs.config.redaction_retention_period is None:
            return

        if not (
            await self.db.updates.has_completed_background_update(
                "redactions_have_censored_ts_idx"
            )
        ):
            # We don't want to run this until the appropriate index has been
            # created.
            return

        before_ts = self._clock.time_msec() - self.hs.config.redaction_retention_period

        # We fetch all redactions that:
        #   1. point to an event we have,
        #   2. has a received_ts from before the cut off, and
        #   3. we haven't yet censored.
        #
        # This is limited to 100 events to ensure that we don't try and do too
        # much at once. We'll get called again so this should eventually catch
        # up.
        sql = """
            SELECT redactions.event_id, redacts FROM redactions
            LEFT JOIN events AS original_event ON (
                redacts = original_event.event_id
            )
            WHERE NOT have_censored
            AND redactions.received_ts <= ?
            ORDER BY redactions.received_ts ASC
            LIMIT ?
        """

        rows = await self.db.execute(
            "_censor_redactions_fetch", None, sql, before_ts, 100
        )

        updates = []

        for redaction_id, event_id in rows:
            redaction_event = await self.get_event(redaction_id, allow_none=True)
            original_event = await self.get_event(
                event_id, allow_rejected=True, allow_none=True
            )

            # The SQL above ensures that we have both the redaction and
            # original event, so if the `get_event` calls return None it
            # means that the redaction wasn't allowed. Either way we know that
            # the result won't change so we mark the fact that we've checked.
            if (
                redaction_event
                and original_event
                and original_event.internal_metadata.is_redacted()
            ):
                # Redaction was allowed
                pruned_json = encode_json(
                    prune_event_dict(
                        original_event.room_version, original_event.get_dict()
                    )
                )
            else:
                # Redaction wasn't allowed
                pruned_json = None

            updates.append((redaction_id, event_id, pruned_json))

        def _update_censor_txn(txn):
            for redaction_id, event_id, pruned_json in updates:
                if pruned_json:
                    self._censor_event_txn(txn, event_id, pruned_json)

                self.db.simple_update_one_txn(
                    txn,
                    table="redactions",
                    keyvalues={"event_id": redaction_id},
                    updatevalues={"have_censored": True},
                )

        await self.db.runInteraction("_update_censor_txn", _update_censor_txn)

    def _censor_event_txn(self, txn, event_id, pruned_json):
        """Censor an event by replacing its JSON in the event_json table with the
        provided pruned JSON.

        Args:
            txn (LoggingTransaction): The database transaction.
            event_id (str): The ID of the event to censor.
            pruned_json (str): The pruned JSON
        """
        self.db.simple_update_one_txn(
            txn,
            table="event_json",
            keyvalues={"event_id": event_id},
            updatevalues={"json": pruned_json},
        )

    @defer.inlineCallbacks
    def count_daily_messages(self):
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """

        def _count_messages(txn):
            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_messages", _count_messages)
        return ret

    @defer.inlineCallbacks
    def count_daily_sent_messages(self):
        def _count_messages(txn):
            # This is good enough as if you have silly characters in your own
            # hostname then thats your own fault.
            like_clause = "%:" + self.hs.hostname

            sql = """
                SELECT COALESCE(COUNT(*), 0) FROM events
                WHERE type = 'm.room.message'
                    AND sender LIKE ?
                AND stream_ordering > ?
            """

            txn.execute(sql, (like_clause, self.stream_ordering_day_ago))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_daily_sent_messages", _count_messages)
        return ret

    @defer.inlineCallbacks
    def count_daily_active_rooms(self):
        def _count(txn):
            sql = """
                SELECT COALESCE(COUNT(DISTINCT room_id), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            (count,) = txn.fetchone()
            return count

        ret = yield self.db.runInteraction("count_daily_active_rooms", _count)
        return ret

    def get_current_backfill_token(self):
        """The current minimum token that backfilled events have reached"""
        return -self._backfill_id_gen.get_current_token()

    def get_current_events_token(self):
        """The current maximum token that events have reached"""
        return self._stream_id_gen.get_current_token()

    def get_all_new_forward_event_rows(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_new_forward_event_rows(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? < stream_ordering AND stream_ordering <= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (last_id, current_id, limit))
            new_event_updates = txn.fetchall()

            if len(new_event_updates) == limit:
                upper_bound = new_event_updates[-1][0]
            else:
                upper_bound = current_id

            sql = (
                "SELECT event_stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? < event_stream_ordering"
                " AND event_stream_ordering <= ?"
                " ORDER BY event_stream_ordering DESC"
            )
            txn.execute(sql, (last_id, upper_bound))
            new_event_updates.extend(txn)

            return new_event_updates

        return self.db.runInteraction(
            "get_all_new_forward_event_rows", get_all_new_forward_event_rows
        )

    def get_all_new_backfill_event_rows(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_new_backfill_event_rows(txn):
            sql = (
                "SELECT -e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? > stream_ordering AND stream_ordering >= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            txn.execute(sql, (-last_id, -current_id, limit))
            new_event_updates = txn.fetchall()

            if len(new_event_updates) == limit:
                upper_bound = new_event_updates[-1][0]
            else:
                upper_bound = current_id

            sql = (
                "SELECT -event_stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts, relates_to_id"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " LEFT JOIN event_relations USING (event_id)"
                " WHERE ? > event_stream_ordering"
                " AND event_stream_ordering >= ?"
                " ORDER BY event_stream_ordering DESC"
            )
            txn.execute(sql, (-last_id, -upper_bound))
            new_event_updates.extend(txn.fetchall())

            return new_event_updates

        return self.db.runInteraction(
            "get_all_new_backfill_event_rows", get_all_new_backfill_event_rows
        )

    @cached(num_args=5, max_entries=10)
    def get_all_new_events(
        self,
        last_backfill_id,
        last_forward_id,
        current_backfill_id,
        current_forward_id,
        limit,
    ):
        """Get all the new events that have arrived at the server either as
        new events or as backfilled events"""
        have_backfill_events = last_backfill_id != current_backfill_id
        have_forward_events = last_forward_id != current_forward_id

        if not have_backfill_events and not have_forward_events:
            return defer.succeed(AllNewEventsResult([], [], [], [], []))

        def get_all_new_events_txn(txn):
            sql = (
                "SELECT e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? < stream_ordering AND stream_ordering <= ?"
                " ORDER BY stream_ordering ASC"
                " LIMIT ?"
            )
            if have_forward_events:
                txn.execute(sql, (last_forward_id, current_forward_id, limit))
                new_forward_events = txn.fetchall()

                if len(new_forward_events) == limit:
                    upper_bound = new_forward_events[-1][0]
                else:
                    upper_bound = current_forward_id

                sql = (
                    "SELECT event_stream_ordering, event_id, state_group"
                    " FROM ex_outlier_stream"
                    " WHERE ? > event_stream_ordering"
                    " AND event_stream_ordering >= ?"
                    " ORDER BY event_stream_ordering DESC"
                )
                txn.execute(sql, (last_forward_id, upper_bound))
                forward_ex_outliers = txn.fetchall()
            else:
                new_forward_events = []
                forward_ex_outliers = []

            sql = (
                "SELECT -e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? > stream_ordering AND stream_ordering >= ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )
            if have_backfill_events:
                txn.execute(sql, (-last_backfill_id, -current_backfill_id, limit))
                new_backfill_events = txn.fetchall()

                if len(new_backfill_events) == limit:
                    upper_bound = new_backfill_events[-1][0]
                else:
                    upper_bound = current_backfill_id

                sql = (
                    "SELECT -event_stream_ordering, event_id, state_group"
                    " FROM ex_outlier_stream"
                    " WHERE ? > event_stream_ordering"
                    " AND event_stream_ordering >= ?"
                    " ORDER BY event_stream_ordering DESC"
                )
                txn.execute(sql, (-last_backfill_id, -upper_bound))
                backward_ex_outliers = txn.fetchall()
            else:
                new_backfill_events = []
                backward_ex_outliers = []

            return AllNewEventsResult(
                new_forward_events,
                new_backfill_events,
                forward_ex_outliers,
                backward_ex_outliers,
            )

        return self.db.runInteraction("get_all_new_events", get_all_new_events_txn)

    def purge_history(self, room_id, token, delete_local_events):
        """Deletes room history before a certain point

        Args:
            room_id (str):

            token (str): A topological token to delete events before

            delete_local_events (bool):
                if True, we will delete local events as well as remote ones
                (instead of just marking them as outliers and deleting their
                state groups).

        Returns:
            Deferred[set[int]]: The set of state groups that are referenced by
            deleted events.
        """

        return self.db.runInteraction(
            "purge_history",
            self._purge_history_txn,
            room_id,
            token,
            delete_local_events,
        )

    def _purge_history_txn(self, txn, room_id, token_str, delete_local_events):
        token = RoomStreamToken.parse(token_str)

        # Tables that should be pruned:
        #     event_auth
        #     event_backward_extremities
        #     event_edges
        #     event_forward_extremities
        #     event_json
        #     event_push_actions
        #     event_reference_hashes
        #     event_search
        #     event_to_state_groups
        #     events
        #     rejections
        #     room_depth
        #     state_groups
        #     state_groups_state

        # we will build a temporary table listing the events so that we don't
        # have to keep shovelling the list back and forth across the
        # connection. Annoyingly the python sqlite driver commits the
        # transaction on CREATE, so let's do this first.
        #
        # furthermore, we might already have the table from a previous (failed)
        # purge attempt, so let's drop the table first.

        txn.execute("DROP TABLE IF EXISTS events_to_purge")

        txn.execute(
            "CREATE TEMPORARY TABLE events_to_purge ("
            "    event_id TEXT NOT NULL,"
            "    should_delete BOOLEAN NOT NULL"
            ")"
        )

        # First ensure that we're not about to delete all the forward extremeties
        txn.execute(
            "SELECT e.event_id, e.depth FROM events as e "
            "INNER JOIN event_forward_extremities as f "
            "ON e.event_id = f.event_id "
            "AND e.room_id = f.room_id "
            "WHERE f.room_id = ?",
            (room_id,),
        )
        rows = txn.fetchall()
        max_depth = max(row[1] for row in rows)

        if max_depth < token.topological:
            # We need to ensure we don't delete all the events from the database
            # otherwise we wouldn't be able to send any events (due to not
            # having any backwards extremeties)
            raise SynapseError(
                400, "topological_ordering is greater than forward extremeties"
            )

        logger.info("[purge] looking for events to delete")

        should_delete_expr = "state_key IS NULL"
        should_delete_params = ()
        if not delete_local_events:
            should_delete_expr += " AND event_id NOT LIKE ?"

            # We include the parameter twice since we use the expression twice
            should_delete_params += ("%:" + self.hs.hostname, "%:" + self.hs.hostname)

        should_delete_params += (room_id, token.topological)

        # Note that we insert events that are outliers and aren't going to be
        # deleted, as nothing will happen to them.
        txn.execute(
            "INSERT INTO events_to_purge"
            " SELECT event_id, %s"
            " FROM events AS e LEFT JOIN state_events USING (event_id)"
            " WHERE (NOT outlier OR (%s)) AND e.room_id = ? AND topological_ordering < ?"
            % (should_delete_expr, should_delete_expr),
            should_delete_params,
        )

        # We create the indices *after* insertion as that's a lot faster.

        # create an index on should_delete because later we'll be looking for
        # the should_delete / shouldn't_delete subsets
        txn.execute(
            "CREATE INDEX events_to_purge_should_delete"
            " ON events_to_purge(should_delete)"
        )

        # We do joins against events_to_purge for e.g. calculating state
        # groups to purge, etc., so lets make an index.
        txn.execute("CREATE INDEX events_to_purge_id ON events_to_purge(event_id)")

        txn.execute("SELECT event_id, should_delete FROM events_to_purge")
        event_rows = txn.fetchall()
        logger.info(
            "[purge] found %i events before cutoff, of which %i can be deleted",
            len(event_rows),
            sum(1 for e in event_rows if e[1]),
        )

        logger.info("[purge] Finding new backward extremities")

        # We calculate the new entries for the backward extremeties by finding
        # events to be purged that are pointed to by events we're not going to
        # purge.
        txn.execute(
            "SELECT DISTINCT e.event_id FROM events_to_purge AS e"
            " INNER JOIN event_edges AS ed ON e.event_id = ed.prev_event_id"
            " LEFT JOIN events_to_purge AS ep2 ON ed.event_id = ep2.event_id"
            " WHERE ep2.event_id IS NULL"
        )
        new_backwards_extrems = txn.fetchall()

        logger.info("[purge] replacing backward extremities: %r", new_backwards_extrems)

        txn.execute(
            "DELETE FROM event_backward_extremities WHERE room_id = ?", (room_id,)
        )

        # Update backward extremeties
        txn.executemany(
            "INSERT INTO event_backward_extremities (room_id, event_id)"
            " VALUES (?, ?)",
            [(room_id, event_id) for event_id, in new_backwards_extrems],
        )

        logger.info("[purge] finding state groups referenced by deleted events")

        # Get all state groups that are referenced by events that are to be
        # deleted.
        txn.execute(
            """
            SELECT DISTINCT state_group FROM events_to_purge
            INNER JOIN event_to_state_groups USING (event_id)
        """
        )

        referenced_state_groups = {sg for sg, in txn}
        logger.info(
            "[purge] found %i referenced state groups", len(referenced_state_groups)
        )

        logger.info("[purge] removing events from event_to_state_groups")
        txn.execute(
            "DELETE FROM event_to_state_groups "
            "WHERE event_id IN (SELECT event_id from events_to_purge)"
        )
        for event_id, _ in event_rows:
            txn.call_after(self._get_state_group_for_event.invalidate, (event_id,))

        # Delete all remote non-state events
        for table in (
            "events",
            "event_json",
            "event_auth",
            "event_edges",
            "event_forward_extremities",
            "event_reference_hashes",
            "event_search",
            "rejections",
        ):
            logger.info("[purge] removing events from %s", table)

            txn.execute(
                "DELETE FROM %s WHERE event_id IN ("
                "    SELECT event_id FROM events_to_purge WHERE should_delete"
                ")" % (table,)
            )

        # event_push_actions lacks an index on event_id, and has one on
        # (room_id, event_id) instead.
        for table in ("event_push_actions",):
            logger.info("[purge] removing events from %s", table)

            txn.execute(
                "DELETE FROM %s WHERE room_id = ? AND event_id IN ("
                "    SELECT event_id FROM events_to_purge WHERE should_delete"
                ")" % (table,),
                (room_id,),
            )

        # Mark all state and own events as outliers
        logger.info("[purge] marking remaining events as outliers")
        txn.execute(
            "UPDATE events SET outlier = ?"
            " WHERE event_id IN ("
            "    SELECT event_id FROM events_to_purge "
            "    WHERE NOT should_delete"
            ")",
            (True,),
        )

        # synapse tries to take out an exclusive lock on room_depth whenever it
        # persists events (because upsert), and once we run this update, we
        # will block that for the rest of our transaction.
        #
        # So, let's stick it at the end so that we don't block event
        # persistence.
        #
        # We do this by calculating the minimum depth of the backwards
        # extremities. However, the events in event_backward_extremities
        # are ones we don't have yet so we need to look at the events that
        # point to it via event_edges table.
        txn.execute(
            """
            SELECT COALESCE(MIN(depth), 0)
            FROM event_backward_extremities AS eb
            INNER JOIN event_edges AS eg ON eg.prev_event_id = eb.event_id
            INNER JOIN events AS e ON e.event_id = eg.event_id
            WHERE eb.room_id = ?
        """,
            (room_id,),
        )
        (min_depth,) = txn.fetchone()

        logger.info("[purge] updating room_depth to %d", min_depth)

        txn.execute(
            "UPDATE room_depth SET min_depth = ? WHERE room_id = ?",
            (min_depth, room_id),
        )

        # finally, drop the temp table. this will commit the txn in sqlite,
        # so make sure to keep this actually last.
        txn.execute("DROP TABLE events_to_purge")

        logger.info("[purge] done")

        return referenced_state_groups

    def purge_room(self, room_id):
        """Deletes all record of a room

        Args:
            room_id (str)

        Returns:
            Deferred[List[int]]: The list of state groups to delete.
        """

        return self.db.runInteraction("purge_room", self._purge_room_txn, room_id)

    def _purge_room_txn(self, txn, room_id):
        # First we fetch all the state groups that should be deleted, before
        # we delete that information.
        txn.execute(
            """
                SELECT DISTINCT state_group FROM events
                INNER JOIN event_to_state_groups USING(event_id)
                WHERE events.room_id = ?
            """,
            (room_id,),
        )

        state_groups = [row[0] for row in txn]

        # Now we delete tables which lack an index on room_id but have one on event_id
        for table in (
            "event_auth",
            "event_edges",
            "event_push_actions_staging",
            "event_reference_hashes",
            "event_relations",
            "event_to_state_groups",
            "redactions",
            "rejections",
            "state_events",
        ):
            logger.info("[purge] removing %s from %s", room_id, table)

            txn.execute(
                """
                DELETE FROM %s WHERE event_id IN (
                  SELECT event_id FROM events WHERE room_id=?
                )
                """
                % (table,),
                (room_id,),
            )

        # and finally, the tables with an index on room_id (or no useful index)
        for table in (
            "current_state_events",
            "event_backward_extremities",
            "event_forward_extremities",
            "event_json",
            "event_push_actions",
            "event_search",
            "events",
            "group_rooms",
            "public_room_list_stream",
            "receipts_graph",
            "receipts_linearized",
            "room_aliases",
            "room_depth",
            "room_memberships",
            "room_stats_state",
            "room_stats_current",
            "room_stats_historical",
            "room_stats_earliest_token",
            "rooms",
            "stream_ordering_to_exterm",
            "users_in_public_rooms",
            "users_who_share_private_rooms",
            # no useful index, but let's clear them anyway
            "appservice_room_list",
            "e2e_room_keys",
            "event_push_summary",
            "pusher_throttle",
            "group_summary_rooms",
            "local_invites",
            "room_account_data",
            "room_tags",
            "local_current_membership",
        ):
            logger.info("[purge] removing %s from %s", room_id, table)
            txn.execute("DELETE FROM %s WHERE room_id=?" % (table,), (room_id,))

        # Other tables we do NOT need to clear out:
        #
        #  - blocked_rooms
        #    This is important, to make sure that we don't accidentally rejoin a blocked
        #    room after it was purged
        #
        #  - user_directory
        #    This has a room_id column, but it is unused
        #

        # Other tables that we might want to consider clearing out include:
        #
        #  - event_reports
        #       Given that these are intended for abuse management my initial
        #       inclination is to leave them in place.
        #
        #  - current_state_delta_stream
        #  - ex_outlier_stream
        #  - room_tags_revisions
        #       The problem with these is that they are largeish and there is no room_id
        #       index on them. In any case we should be clearing out 'stream' tables
        #       periodically anyway (#5888)

        # TODO: we could probably usefully do a bunch of cache invalidation here

        logger.info("[purge] done")

        return state_groups

    async def is_event_after(self, event_id1, event_id2):
        """Returns True if event_id1 is after event_id2 in the stream
        """
        to_1, so_1 = await self._get_event_ordering(event_id1)
        to_2, so_2 = await self._get_event_ordering(event_id2)
        return (to_1, so_1) > (to_2, so_2)

    @cachedInlineCallbacks(max_entries=5000)
    def _get_event_ordering(self, event_id):
        res = yield self.db.simple_select_one(
            table="events",
            retcols=["topological_ordering", "stream_ordering"],
            keyvalues={"event_id": event_id},
            allow_none=True,
        )

        if not res:
            raise SynapseError(404, "Could not find event %s" % (event_id,))

        return (int(res["topological_ordering"]), int(res["stream_ordering"]))

    def get_all_updated_current_state_deltas(self, from_token, to_token, limit):
        def get_all_updated_current_state_deltas_txn(txn):
            sql = """
                SELECT stream_id, room_id, type, state_key, event_id
                FROM current_state_delta_stream
                WHERE ? < stream_id AND stream_id <= ?
                ORDER BY stream_id ASC LIMIT ?
            """
            txn.execute(sql, (from_token, to_token, limit))
            return txn.fetchall()

        return self.db.runInteraction(
            "get_all_updated_current_state_deltas",
            get_all_updated_current_state_deltas_txn,
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
        return self.db.simple_insert_many_txn(
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
        return self.db.simple_insert_txn(
            txn=txn,
            table="event_expiry",
            values={"event_id": event_id, "expiry_ts": expiry_ts},
        )

    @defer.inlineCallbacks
    def expire_event(self, event_id):
        """Retrieve and expire an event that has expired, and delete its associated
        expiry timestamp. If the event can't be retrieved, delete its associated
        timestamp so we don't try to expire it again in the future.

        Args:
             event_id (str): The ID of the event to delete.
        """
        # Try to retrieve the event's content from the database or the event cache.
        event = yield self.get_event(event_id)

        def delete_expired_event_txn(txn):
            # Delete the expiry timestamp associated with this event from the database.
            self._delete_event_expiry_txn(txn, event_id)

            if not event:
                # If we can't find the event, log a warning and delete the expiry date
                # from the database so that we don't try to expire it again in the
                # future.
                logger.warning(
                    "Can't expire event %s because we don't have it.", event_id
                )
                return

            # Prune the event's dict then convert it to JSON.
            pruned_json = encode_json(
                prune_event_dict(event.room_version, event.get_dict())
            )

            # Update the event_json table to replace the event's JSON with the pruned
            # JSON.
            self._censor_event_txn(txn, event.event_id, pruned_json)

            # We need to invalidate the event cache entry for this event because we
            # changed its content in the database. We can't call
            # self._invalidate_cache_and_stream because self.get_event_cache isn't of the
            # right type.
            txn.call_after(self._get_event_cache.invalidate, (event.event_id,))
            # Send that invalidation to replication so that other workers also invalidate
            # the event cache.
            self._send_invalidation_to_replication(
                txn, "_get_event_cache", (event.event_id,)
            )

        yield self.db.runInteraction("delete_expired_event", delete_expired_event_txn)

    def _delete_event_expiry_txn(self, txn, event_id):
        """Delete the expiry timestamp associated with an event ID without deleting the
        actual event.

        Args:
            txn (LoggingTransaction): The transaction to use to perform the deletion.
            event_id (str): The event ID to delete the associated expiry timestamp of.
        """
        return self.db.simple_delete_txn(
            txn=txn, table="event_expiry", keyvalues={"event_id": event_id}
        )

    def get_next_event_to_expire(self):
        """Retrieve the entry with the lowest expiry timestamp in the event_expiry
        table, or None if there's no more event to expire.

        Returns: Deferred[Optional[Tuple[str, int]]]
            A tuple containing the event ID as its first element and an expiry timestamp
            as its second one, if there's at least one row in the event_expiry table.
            None otherwise.
        """

        def get_next_event_to_expire_txn(txn):
            txn.execute(
                """
                SELECT event_id, expiry_ts FROM event_expiry
                ORDER BY expiry_ts ASC LIMIT 1
                """
            )

            return txn.fetchone()

        return self.db.runInteraction(
            desc="get_next_event_to_expire", func=get_next_event_to_expire_txn
        )


AllNewEventsResult = namedtuple(
    "AllNewEventsResult",
    [
        "new_forward_events",
        "new_backfill_events",
        "forward_ex_outliers",
        "backward_ex_outliers",
    ],
)
