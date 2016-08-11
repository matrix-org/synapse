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
from ._base import SQLBaseStore, _RollbackButIsFineException

from twisted.internet import defer, reactor

from synapse.events import FrozenEvent, USE_FROZEN_DICTS
from synapse.events.utils import prune_event

from synapse.util.async import ObservableDeferred
from synapse.util.logcontext import preserve_fn, PreserveLoggingContext
from synapse.util.logutils import log_function
from synapse.api.constants import EventTypes
from synapse.api.errors import SynapseError

from canonicaljson import encode_canonical_json
from collections import deque, namedtuple, OrderedDict
from functools import wraps

import synapse
import synapse.metrics


import logging
import math
import ujson as json

logger = logging.getLogger(__name__)


metrics = synapse.metrics.get_metrics_for(__name__)
persist_event_counter = metrics.register_counter("persisted_events")


def encode_json(json_object):
    if USE_FROZEN_DICTS:
        # ujson doesn't like frozen_dicts
        return encode_canonical_json(json_object)
    else:
        return json.dumps(json_object, ensure_ascii=False)

# These values are used in the `enqueus_event` and `_do_fetch` methods to
# control how we batch/bulk fetch events from the database.
# The values are plucked out of thing air to make initial sync run faster
# on jki.re
# TODO: Make these configurable.
EVENT_QUEUE_THREADS = 3  # Max number of threads that will fetch events
EVENT_QUEUE_ITERATIONS = 3  # No. times we block waiting for requests for events
EVENT_QUEUE_TIMEOUT_S = 0.1  # Timeout when waiting for requests for events


class _EventPeristenceQueue(object):
    """Queues up events so that they can be persisted in bulk with only one
    concurrent transaction per room.
    """

    _EventPersistQueueItem = namedtuple("_EventPersistQueueItem", (
        "events_and_contexts", "current_state", "backfilled", "deferred",
    ))

    def __init__(self):
        self._event_persist_queues = {}
        self._currently_persisting_rooms = set()

    def add_to_queue(self, room_id, events_and_contexts, backfilled, current_state):
        """Add events to the queue, with the given persist_event options.
        """
        queue = self._event_persist_queues.setdefault(room_id, deque())
        if queue:
            end_item = queue[-1]
            if end_item.current_state or current_state:
                # We perist events with current_state set to True one at a time
                pass
            if end_item.backfilled == backfilled:
                end_item.events_and_contexts.extend(events_and_contexts)
                return end_item.deferred.observe()

        deferred = ObservableDeferred(defer.Deferred())

        queue.append(self._EventPersistQueueItem(
            events_and_contexts=events_and_contexts,
            backfilled=backfilled,
            current_state=current_state,
            deferred=deferred,
        ))

        return deferred.observe()

    def handle_queue(self, room_id, per_item_callback):
        """Attempts to handle the queue for a room if not already being handled.

        The given callback will be invoked with for each item in the queue,1
        of type _EventPersistQueueItem. The per_item_callback will continuously
        be called with new items, unless the queue becomnes empty. The return
        value of the function will be given to the deferreds waiting on the item,
        exceptions will be passed to the deferres as well.

        This function should therefore be called whenever anything is added
        to the queue.

        If another callback is currently handling the queue then it will not be
        invoked.
        """

        if room_id in self._currently_persisting_rooms:
            return

        self._currently_persisting_rooms.add(room_id)

        @defer.inlineCallbacks
        def handle_queue_loop():
            try:
                queue = self._get_drainining_queue(room_id)
                for item in queue:
                    try:
                        ret = yield per_item_callback(item)
                        item.deferred.callback(ret)
                    except Exception as e:
                        item.deferred.errback(e)
            finally:
                queue = self._event_persist_queues.pop(room_id, None)
                if queue:
                    self._event_persist_queues[room_id] = queue
                self._currently_persisting_rooms.discard(room_id)

        preserve_fn(handle_queue_loop)()

    def _get_drainining_queue(self, room_id):
        queue = self._event_persist_queues.setdefault(room_id, deque())

        try:
            while True:
                yield queue.popleft()
        except IndexError:
            # Queue has been drained.
            pass


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
            res = yield func(self, *args, **kwargs)
        except self.database_engine.module.IntegrityError:
            logger.exception("IntegrityError, retrying.")
            res = yield func(self, *args, delete_existing=True, **kwargs)
        defer.returnValue(res)

    return f


class EventsStore(SQLBaseStore):
    EVENT_ORIGIN_SERVER_TS_NAME = "event_origin_server_ts"
    EVENT_FIELDS_SENDER_URL_UPDATE_NAME = "event_fields_sender_url"

    def __init__(self, hs):
        super(EventsStore, self).__init__(hs)
        self._clock = hs.get_clock()
        self.register_background_update_handler(
            self.EVENT_ORIGIN_SERVER_TS_NAME, self._background_reindex_origin_server_ts
        )
        self.register_background_update_handler(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME,
            self._background_reindex_fields_sender,
        )

        self._event_persist_queue = _EventPeristenceQueue()

    def persist_events(self, events_and_contexts, backfilled=False):
        """
        Write events to the database
        Args:
            events_and_contexts: list of tuples of (event, context)
            backfilled: ?
        """
        partitioned = {}
        for event, ctx in events_and_contexts:
            partitioned.setdefault(event.room_id, []).append((event, ctx))

        deferreds = []
        for room_id, evs_ctxs in partitioned.items():
            d = self._event_persist_queue.add_to_queue(
                room_id, evs_ctxs,
                backfilled=backfilled,
                current_state=None,
            )
            deferreds.append(d)

        for room_id in partitioned.keys():
            self._maybe_start_persisting(room_id)

        return defer.gatherResults(deferreds, consumeErrors=True)

    @defer.inlineCallbacks
    @log_function
    def persist_event(self, event, context, current_state=None, backfilled=False):
        deferred = self._event_persist_queue.add_to_queue(
            event.room_id, [(event, context)],
            backfilled=backfilled,
            current_state=current_state,
        )

        self._maybe_start_persisting(event.room_id)

        yield deferred

        max_persisted_id = yield self._stream_id_gen.get_current_token()
        defer.returnValue((event.internal_metadata.stream_ordering, max_persisted_id))

    def _maybe_start_persisting(self, room_id):
        @defer.inlineCallbacks
        def persisting_queue(item):
            if item.current_state:
                for event, context in item.events_and_contexts:
                    # There should only ever be one item in
                    # events_and_contexts when current_state is
                    # not None
                    yield self._persist_event(
                        event, context,
                        current_state=item.current_state,
                        backfilled=item.backfilled,
                    )
            else:
                yield self._persist_events(
                    item.events_and_contexts,
                    backfilled=item.backfilled,
                )

        self._event_persist_queue.handle_queue(room_id, persisting_queue)

    @_retry_on_integrity_error
    @defer.inlineCallbacks
    def _persist_events(self, events_and_contexts, backfilled=False,
                        delete_existing=False):
        if not events_and_contexts:
            return

        if backfilled:
            stream_ordering_manager = self._backfill_id_gen.get_next_mult(
                len(events_and_contexts)
            )
        else:
            stream_ordering_manager = self._stream_id_gen.get_next_mult(
                len(events_and_contexts)
            )

        state_group_id_manager = self._state_groups_id_gen.get_next_mult(
            len(events_and_contexts)
        )
        with stream_ordering_manager as stream_orderings:
            with state_group_id_manager as state_group_ids:
                for (event, context), stream, state_group_id in zip(
                    events_and_contexts, stream_orderings, state_group_ids
                ):
                    event.internal_metadata.stream_ordering = stream
                    # Assign a state group_id in case a new id is needed for
                    # this context. In theory we only need to assign this
                    # for contexts that have current_state and aren't outliers
                    # but that make the code more complicated. Assigning an ID
                    # per event only causes the state_group_ids to grow as fast
                    # as the stream_ordering so in practise shouldn't be a problem.
                    context.new_state_group_id = state_group_id

                chunks = [
                    events_and_contexts[x:x + 100]
                    for x in xrange(0, len(events_and_contexts), 100)
                ]

                for chunk in chunks:
                    # We can't easily parallelize these since different chunks
                    # might contain the same event. :(
                    yield self.runInteraction(
                        "persist_events",
                        self._persist_events_txn,
                        events_and_contexts=chunk,
                        backfilled=backfilled,
                        delete_existing=delete_existing,
                    )
                    persist_event_counter.inc_by(len(chunk))

    @_retry_on_integrity_error
    @defer.inlineCallbacks
    @log_function
    def _persist_event(self, event, context, current_state=None, backfilled=False,
                       delete_existing=False):
        try:
            with self._stream_id_gen.get_next() as stream_ordering:
                with self._state_groups_id_gen.get_next() as state_group_id:
                    event.internal_metadata.stream_ordering = stream_ordering
                    context.new_state_group_id = state_group_id
                    yield self.runInteraction(
                        "persist_event",
                        self._persist_event_txn,
                        event=event,
                        context=context,
                        current_state=current_state,
                        backfilled=backfilled,
                        delete_existing=delete_existing,
                    )
                    persist_event_counter.inc()
        except _RollbackButIsFineException:
            pass

    @defer.inlineCallbacks
    def get_event(self, event_id, check_redacted=True,
                  get_prev_content=False, allow_rejected=False,
                  allow_none=False):
        """Get an event from the database by event_id.

        Args:
            event_id (str): The event_id of the event to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.
            allow_none (bool): If True, return None if no event found, if
                False throw an exception.

        Returns:
            Deferred : A FrozenEvent.
        """
        events = yield self._get_events(
            [event_id],
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        if not events and not allow_none:
            raise SynapseError(404, "Could not find event %s" % (event_id,))

        defer.returnValue(events[0] if events else None)

    @defer.inlineCallbacks
    def get_events(self, event_ids, check_redacted=True,
                   get_prev_content=False, allow_rejected=False):
        """Get events from the database

        Args:
            event_ids (list): The event_ids of the events to fetch
            check_redacted (bool): If True, check if event has been redacted
                and redact it.
            get_prev_content (bool): If True and event is a state event,
                include the previous states content in the unsigned field.
            allow_rejected (bool): If True return rejected events.

        Returns:
            Deferred : Dict from event_id to event.
        """
        events = yield self._get_events(
            event_ids,
            check_redacted=check_redacted,
            get_prev_content=get_prev_content,
            allow_rejected=allow_rejected,
        )

        defer.returnValue({e.event_id: e for e in events})

    @log_function
    def _persist_event_txn(self, txn, event, context, current_state, backfilled=False,
                           delete_existing=False):
        # We purposefully do this first since if we include a `current_state`
        # key, we *want* to update the `current_state_events` table
        if current_state:
            txn.call_after(self._get_current_state_for_key.invalidate_all)
            txn.call_after(self.get_rooms_for_user.invalidate_all)
            txn.call_after(self.get_users_in_room.invalidate, (event.room_id,))
            txn.call_after(self.get_joined_hosts_for_room.invalidate, (event.room_id,))

            # Add an entry to the current_state_resets table to record the point
            # where we clobbered the current state
            stream_order = event.internal_metadata.stream_ordering
            self._simple_insert_txn(
                txn,
                table="current_state_resets",
                values={"event_stream_ordering": stream_order}
            )

            self._simple_delete_txn(
                txn,
                table="current_state_events",
                keyvalues={"room_id": event.room_id},
            )

            for s in current_state:
                self._simple_insert_txn(
                    txn,
                    "current_state_events",
                    {
                        "event_id": s.event_id,
                        "room_id": s.room_id,
                        "type": s.type,
                        "state_key": s.state_key,
                    }
                )

        return self._persist_events_txn(
            txn,
            [(event, context)],
            backfilled=backfilled,
            delete_existing=delete_existing,
        )

    @log_function
    def _persist_events_txn(self, txn, events_and_contexts, backfilled,
                            delete_existing=False):
        """Insert some number of room events into the necessary database tables.

        Rejected events are only inserted into the events table, the events_json table,
        and the rejections table. Things reading from those table will need to check
        whether the event was rejected.

        If delete_existing is True then existing events will be purged from the
        database before insertion. This is useful when retrying due to IntegrityError.
        """
        # Ensure that we don't have the same event twice.
        # Pick the earliest non-outlier if there is one, else the earliest one.
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

        events_and_contexts = new_events_and_contexts.values()

        depth_updates = {}
        for event, context in events_and_contexts:
            # Remove the any existing cache entries for the event_ids
            txn.call_after(self._invalidate_get_event_cache, event.event_id)
            if not backfilled:
                txn.call_after(
                    self._events_stream_cache.entity_has_changed,
                    event.room_id, event.internal_metadata.stream_ordering,
                )

            if not event.internal_metadata.is_outlier() and not context.rejected:
                depth_updates[event.room_id] = max(
                    event.depth, depth_updates.get(event.room_id, event.depth)
                )

        for room_id, depth in depth_updates.items():
            self._update_min_depth_for_room_txn(txn, room_id, depth)

        txn.execute(
            "SELECT event_id, outlier FROM events WHERE event_id in (%s)" % (
                ",".join(["?"] * len(events_and_contexts)),
            ),
            [event.event_id for event, _ in events_and_contexts]
        )

        have_persisted = {
            event_id: outlier
            for event_id, outlier in txn.fetchall()
        }

        to_remove = set()
        for event, context in events_and_contexts:
            if context.rejected:
                # If the event is rejected then we don't care if the event
                # was an outlier or not.
                if event.event_id in have_persisted:
                    # If we have already seen the event then ignore it.
                    to_remove.add(event)
                continue

            if event.event_id not in have_persisted:
                continue

            to_remove.add(event)

            outlier_persisted = have_persisted[event.event_id]
            if not event.internal_metadata.is_outlier() and outlier_persisted:
                # We received a copy of an event that we had already stored as
                # an outlier in the database. We now have some state at that
                # so we need to update the state_groups table with that state.

                # insert into the state_group, state_groups_state and
                # event_to_state_groups tables.
                self._store_mult_state_groups_txn(txn, ((event, context),))

                metadata_json = encode_json(
                    event.internal_metadata.get_dict()
                ).decode("UTF-8")

                sql = (
                    "UPDATE event_json SET internal_metadata = ?"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (metadata_json, event.event_id,)
                )

                # Add an entry to the ex_outlier_stream table to replicate the
                # change in outlier status to our workers.
                stream_order = event.internal_metadata.stream_ordering
                state_group_id = context.state_group or context.new_state_group_id
                self._simple_insert_txn(
                    txn,
                    table="ex_outlier_stream",
                    values={
                        "event_stream_ordering": stream_order,
                        "event_id": event.event_id,
                        "state_group": state_group_id,
                    }
                )

                sql = (
                    "UPDATE events SET outlier = ?"
                    " WHERE event_id = ?"
                )
                txn.execute(
                    sql,
                    (False, event.event_id,)
                )

                # Update the event_backward_extremities table now that this
                # event isn't an outlier any more.
                self._update_extremeties(txn, [event])

        events_and_contexts = [
            ec for ec in events_and_contexts if ec[0] not in to_remove
        ]

        if not events_and_contexts:
            # Make sure we don't pass an empty list to functions that expect to
            # be storing at least one element.
            return

        # From this point onwards the events are only events that we haven't
        # seen before.

        def event_dict(event):
            return {
                k: v
                for k, v in event.get_dict().items()
                if k not in [
                    "redacted",
                    "redacted_because",
                ]
            }

        if delete_existing:
            # For paranoia reasons, we go and delete all the existing entries
            # for these events so we can reinsert them.
            # This gets around any problems with some tables already having
            # entries.

            logger.info("Deleting existing")

            for table in (
                "events",
                "event_auth",
                "event_json",
                "event_content_hashes",
                "event_destinations",
                "event_edge_hashes",
                "event_edges",
                "event_forward_extremities",
                "event_push_actions",
                "event_reference_hashes",
                "event_search",
                "event_signatures",
                "event_to_state_groups",
                "guest_access",
                "history_visibility",
                "local_invites",
                "room_names",
                "state_events",
                "rejections",
                "redactions",
                "room_memberships",
                "state_events"
            ):
                txn.executemany(
                    "DELETE FROM %s WHERE event_id = ?" % (table,),
                    [(ev.event_id,) for ev, _ in events_and_contexts]
                )

        self._simple_insert_many_txn(
            txn,
            table="event_json",
            values=[
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "internal_metadata": encode_json(
                        event.internal_metadata.get_dict()
                    ).decode("UTF-8"),
                    "json": encode_json(event_dict(event)).decode("UTF-8"),
                }
                for event, _ in events_and_contexts
            ],
        )

        self._simple_insert_many_txn(
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
                    "content": encode_json(event.content).decode("UTF-8"),
                    "origin_server_ts": int(event.origin_server_ts),
                    "received_ts": self._clock.time_msec(),
                    "sender": event.sender,
                    "contains_url": (
                        "url" in event.content
                        and isinstance(event.content["url"], basestring)
                    ),
                }
                for event, _ in events_and_contexts
            ],
        )

        # Remove the rejected events from the list now that we've added them
        # to the events table and the events_json table.
        to_remove = set()
        for event, context in events_and_contexts:
            if context.rejected:
                # Insert the event_id into the rejections table
                self._store_rejections_txn(
                    txn, event.event_id, context.rejected
                )
                to_remove.add(event)

        events_and_contexts = [
            ec for ec in events_and_contexts if ec[0] not in to_remove
        ]

        if not events_and_contexts:
            # Make sure we don't pass an empty list to functions that expect to
            # be storing at least one element.
            return

        # From this point onwards the events are only ones that weren't rejected.

        for event, context in events_and_contexts:
            # Insert all the push actions into the event_push_actions table.
            if context.push_actions:
                self._set_push_actions_for_event_and_users_txn(
                    txn, event, context.push_actions
                )

            if event.type == EventTypes.Redaction and event.redacts is not None:
                # Remove the entries in the event_push_actions table for the
                # redacted event.
                self._remove_push_actions_for_event_id_txn(
                    txn, event.room_id, event.redacts
                )

        self._simple_insert_many_txn(
            txn,
            table="event_auth",
            values=[
                {
                    "event_id": event.event_id,
                    "room_id": event.room_id,
                    "auth_id": auth_id,
                }
                for event, _ in events_and_contexts
                for auth_id, _ in event.auth_events
            ],
        )

        # Insert into the state_groups, state_groups_state, and
        # event_to_state_groups tables.
        self._store_mult_state_groups_txn(txn, events_and_contexts)

        # Update the event_forward_extremities, event_backward_extremities and
        # event_edges tables.
        self._handle_mult_prev_events(
            txn,
            events=[event for event, _ in events_and_contexts],
        )

        for event, _ in events_and_contexts:
            if event.type == EventTypes.Name:
                # Insert into the room_names and event_search tables.
                self._store_room_name_txn(txn, event)
            elif event.type == EventTypes.Topic:
                # Insert into the topics table and event_search table.
                self._store_room_topic_txn(txn, event)
            elif event.type == EventTypes.Message:
                # Insert into the event_search table.
                self._store_room_message_txn(txn, event)
            elif event.type == EventTypes.Redaction:
                # Insert into the redactions table.
                self._store_redaction(txn, event)
            elif event.type == EventTypes.RoomHistoryVisibility:
                # Insert into the event_search table.
                self._store_history_visibility_txn(txn, event)
            elif event.type == EventTypes.GuestAccess:
                # Insert into the event_search table.
                self._store_guest_access_txn(txn, event)

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

        self._simple_insert_many_txn(
            txn,
            table="state_events",
            values=state_values,
        )

        self._simple_insert_many_txn(
            txn,
            table="event_edges",
            values=[
                {
                    "event_id": event.event_id,
                    "prev_event_id": prev_id,
                    "room_id": event.room_id,
                    "is_state": True,
                }
                for event, _ in state_events_and_contexts
                for prev_id, _ in event.prev_state
            ],
        )

        # Prefill the event cache
        self._add_to_cache(txn, events_and_contexts)

        if backfilled:
            # Backfilled events come before the current state so we don't need
            # to update the current state table
            return

        for event, _ in state_events_and_contexts:
            if event.internal_metadata.is_outlier():
                # Outlier events shouldn't clobber the current state.
                continue

            txn.call_after(
                self._get_current_state_for_key.invalidate,
                (event.room_id, event.type, event.state_key,)
            )

            self._simple_upsert_txn(
                txn,
                "current_state_events",
                keyvalues={
                    "room_id": event.room_id,
                    "type": event.type,
                    "state_key": event.state_key,
                },
                values={
                    "event_id": event.event_id,
                }
            )

        return

    def _add_to_cache(self, txn, events_and_contexts):
        to_prefill = []

        rows = []
        N = 200
        for i in range(0, len(events_and_contexts), N):
            ev_map = {
                e[0].event_id: e[0]
                for e in events_and_contexts[i:i + N]
            }
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
                " WHERE e.event_id IN (%s)"
            ) % (",".join(["?"] * len(ev_map)),)

            txn.execute(sql, ev_map.keys())
            rows = self.cursor_to_dict(txn)
            for row in rows:
                event = ev_map[row["event_id"]]
                if not row["rejects"] and not row["redacts"]:
                    to_prefill.append(_EventCacheEntry(
                        event=event,
                        redacted_event=None,
                    ))

        def prefill():
            for cache_entry in to_prefill:
                self._get_event_cache.prefill((cache_entry[0].event_id,), cache_entry)
        txn.call_after(prefill)

    def _store_redaction(self, txn, event):
        # invalidate the cache for the redacted event
        txn.call_after(self._invalidate_get_event_cache, event.redacts)
        txn.execute(
            "INSERT INTO redactions (event_id, redacts) VALUES (?,?)",
            (event.event_id, event.redacts)
        )

    @defer.inlineCallbacks
    def have_events_in_timeline(self, event_ids):
        """Given a list of event ids, check if we have already processed and
        stored them as non outliers.
        """
        rows = yield self._simple_select_many_batch(
            table="events",
            retcols=("event_id",),
            column="event_id",
            iterable=list(event_ids),
            keyvalues={"outlier": False},
            desc="have_events_in_timeline",
        )

        defer.returnValue(set(r["event_id"] for r in rows))

    def have_events(self, event_ids):
        """Given a list of event ids, check if we have already processed them.

        Returns:
            dict: Has an entry for each event id we already have seen. Maps to
            the rejected reason string if we rejected the event, else maps to
            None.
        """
        if not event_ids:
            return defer.succeed({})

        def f(txn):
            sql = (
                "SELECT e.event_id, reason FROM events as e "
                "LEFT JOIN rejections as r ON e.event_id = r.event_id "
                "WHERE e.event_id = ?"
            )

            res = {}
            for event_id in event_ids:
                txn.execute(sql, (event_id,))
                row = txn.fetchone()
                if row:
                    _, rejected = row
                    res[event_id] = rejected

            return res

        return self.runInteraction(
            "have_events", f,
        )

    @defer.inlineCallbacks
    def _get_events(self, event_ids, check_redacted=True,
                    get_prev_content=False, allow_rejected=False):
        if not event_ids:
            defer.returnValue([])

        event_id_list = event_ids
        event_ids = set(event_ids)

        event_entry_map = self._get_events_from_cache(
            event_ids,
            allow_rejected=allow_rejected,
        )

        missing_events_ids = [e for e in event_ids if e not in event_entry_map]

        if missing_events_ids:
            missing_events = yield self._enqueue_events(
                missing_events_ids,
                check_redacted=check_redacted,
                allow_rejected=allow_rejected,
            )

            event_entry_map.update(missing_events)

        events = []
        for event_id in event_id_list:
            entry = event_entry_map.get(event_id, None)
            if not entry:
                continue

            if allow_rejected or not entry.event.rejected_reason:
                if check_redacted and entry.redacted_event:
                    event = entry.redacted_event
                else:
                    event = entry.event

                events.append(event)

                if get_prev_content:
                    if "replaces_state" in event.unsigned:
                        prev = yield self.get_event(
                            event.unsigned["replaces_state"],
                            get_prev_content=False,
                            allow_none=True,
                        )
                        if prev:
                            event.unsigned = dict(event.unsigned)
                            event.unsigned["prev_content"] = prev.content
                            event.unsigned["prev_sender"] = prev.sender

        defer.returnValue(events)

    def _invalidate_get_event_cache(self, event_id):
            self._get_event_cache.invalidate((event_id,))

    def _get_events_from_cache(self, events, allow_rejected):
        event_map = {}

        for event_id in events:
            ret = self._get_event_cache.get((event_id,), None)
            if not ret:
                continue

            if allow_rejected or not ret.event.rejected_reason:
                event_map[event_id] = ret
            else:
                event_map[event_id] = None

        return event_map

    def _do_fetch(self, conn):
        """Takes a database connection and waits for requests for events from
        the _event_fetch_list queue.
        """
        event_list = []
        i = 0
        while True:
            try:
                with self._event_fetch_lock:
                    event_list = self._event_fetch_list
                    self._event_fetch_list = []

                    if not event_list:
                        single_threaded = self.database_engine.single_threaded
                        if single_threaded or i > EVENT_QUEUE_ITERATIONS:
                            self._event_fetch_ongoing -= 1
                            return
                        else:
                            self._event_fetch_lock.wait(EVENT_QUEUE_TIMEOUT_S)
                            i += 1
                            continue
                    i = 0

                event_id_lists = zip(*event_list)[0]
                event_ids = [
                    item for sublist in event_id_lists for item in sublist
                ]

                rows = self._new_transaction(
                    conn, "do_fetch", [], None, self._fetch_event_rows, event_ids
                )

                row_dict = {
                    r["event_id"]: r
                    for r in rows
                }

                # We only want to resolve deferreds from the main thread
                def fire(lst, res):
                    for ids, d in lst:
                        if not d.called:
                            try:
                                with PreserveLoggingContext():
                                    d.callback([
                                        res[i]
                                        for i in ids
                                        if i in res
                                    ])
                            except:
                                logger.exception("Failed to callback")
                with PreserveLoggingContext():
                    reactor.callFromThread(fire, event_list, row_dict)
            except Exception as e:
                logger.exception("do_fetch")

                # We only want to resolve deferreds from the main thread
                def fire(evs):
                    for _, d in evs:
                        if not d.called:
                            with PreserveLoggingContext():
                                d.errback(e)

                if event_list:
                    with PreserveLoggingContext():
                        reactor.callFromThread(fire, event_list)

    @defer.inlineCallbacks
    def _enqueue_events(self, events, check_redacted=True, allow_rejected=False):
        """Fetches events from the database using the _event_fetch_list. This
        allows batch and bulk fetching of events - it allows us to fetch events
        without having to create a new transaction for each request for events.
        """
        if not events:
            defer.returnValue({})

        events_d = defer.Deferred()
        with self._event_fetch_lock:
            self._event_fetch_list.append(
                (events, events_d)
            )

            self._event_fetch_lock.notify()

            if self._event_fetch_ongoing < EVENT_QUEUE_THREADS:
                self._event_fetch_ongoing += 1
                should_start = True
            else:
                should_start = False

        if should_start:
            with PreserveLoggingContext():
                self.runWithConnection(
                    self._do_fetch
                )

        with PreserveLoggingContext():
            rows = yield events_d

        if not allow_rejected:
            rows[:] = [r for r in rows if not r["rejects"]]

        res = yield defer.gatherResults(
            [
                preserve_fn(self._get_event_from_row)(
                    row["internal_metadata"], row["json"], row["redacts"],
                    rejected_reason=row["rejects"],
                )
                for row in rows
            ],
            consumeErrors=True
        )

        defer.returnValue({
            e.event.event_id: e
            for e in res if e
        })

    def _fetch_event_rows(self, txn, events):
        rows = []
        N = 200
        for i in range(1 + len(events) / N):
            evs = events[i * N:(i + 1) * N]
            if not evs:
                break

            sql = (
                "SELECT "
                " e.event_id as event_id, "
                " e.internal_metadata,"
                " e.json,"
                " r.redacts as redacts,"
                " rej.event_id as rejects "
                " FROM event_json as e"
                " LEFT JOIN rejections as rej USING (event_id)"
                " LEFT JOIN redactions as r ON e.event_id = r.redacts"
                " WHERE e.event_id IN (%s)"
            ) % (",".join(["?"] * len(evs)),)

            txn.execute(sql, evs)
            rows.extend(self.cursor_to_dict(txn))

        return rows

    @defer.inlineCallbacks
    def _get_event_from_row(self, internal_metadata, js, redacted,
                            rejected_reason=None):
        d = json.loads(js)
        internal_metadata = json.loads(internal_metadata)

        if rejected_reason:
            rejected_reason = yield self._simple_select_one_onecol(
                table="rejections",
                keyvalues={"event_id": rejected_reason},
                retcol="reason",
                desc="_get_event_from_row_rejected_reason",
            )

        original_ev = FrozenEvent(
            d,
            internal_metadata_dict=internal_metadata,
            rejected_reason=rejected_reason,
        )

        redacted_event = None
        if redacted:
            redacted_event = prune_event(original_ev)

            redaction_id = yield self._simple_select_one_onecol(
                table="redactions",
                keyvalues={"redacts": redacted_event.event_id},
                retcol="event_id",
                desc="_get_event_from_row_redactions",
            )

            redacted_event.unsigned["redacted_by"] = redaction_id
            # Get the redaction event.

            because = yield self.get_event(
                redaction_id,
                check_redacted=False,
                allow_none=True,
            )

            if because:
                # It's fine to do add the event directly, since get_pdu_json
                # will serialise this field correctly
                redacted_event.unsigned["redacted_because"] = because

        cache_entry = _EventCacheEntry(
            event=original_ev,
            redacted_event=redacted_event,
        )

        self._get_event_cache.prefill((original_ev.event_id,), cache_entry)

        defer.returnValue(cache_entry)

    @defer.inlineCallbacks
    def count_daily_messages(self):
        """
        Returns an estimate of the number of messages sent in the last day.

        If it has been significantly less or more than one day since the last
        call to this function, it will return None.
        """
        def _count_messages(txn):
            now = self.hs.get_clock().time()

            txn.execute(
                "SELECT reported_stream_token, reported_time FROM stats_reporting"
            )
            last_reported = self.cursor_to_dict(txn)

            txn.execute(
                "SELECT stream_ordering"
                " FROM events"
                " ORDER BY stream_ordering DESC"
                " LIMIT 1"
            )
            now_reporting = self.cursor_to_dict(txn)
            if not now_reporting:
                logger.info("Calculating daily messages skipped; no now_reporting")
                return None
            now_reporting = now_reporting[0]["stream_ordering"]

            txn.execute("DELETE FROM stats_reporting")
            txn.execute(
                "INSERT INTO stats_reporting"
                " (reported_stream_token, reported_time)"
                " VALUES (?, ?)",
                (now_reporting, now,)
            )

            if not last_reported:
                logger.info("Calculating daily messages skipped; no last_reported")
                return None

            # Close enough to correct for our purposes.
            yesterday = (now - 24 * 60 * 60)
            since_yesterday_seconds = yesterday - last_reported[0]["reported_time"]
            any_since_yesterday = math.fabs(since_yesterday_seconds) > 60 * 60
            if any_since_yesterday:
                logger.info(
                    "Calculating daily messages skipped; since_yesterday_seconds: %d" %
                    (since_yesterday_seconds,)
                )
                return None

            txn.execute(
                "SELECT COUNT(*) as messages"
                " FROM events NATURAL JOIN event_json"
                " WHERE json like '%m.room.message%'"
                " AND stream_ordering > ?"
                " AND stream_ordering <= ?",
                (
                    last_reported[0]["reported_stream_token"],
                    now_reporting,
                )
            )
            rows = self.cursor_to_dict(txn)
            if not rows:
                logger.info("Calculating daily messages skipped; messages count missing")
                return None
            return rows[0]["messages"]

        ret = yield self.runInteraction("count_messages", _count_messages)
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def _background_reindex_fields_sender(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        INSERT_CLUMP_SIZE = 1000

        def reindex_txn(txn):
            sql = (
                "SELECT stream_ordering, event_id, json FROM events"
                " INNER JOIN event_json USING (event_id)"
                " WHERE ? <= stream_ordering AND stream_ordering < ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = txn.fetchall()
            if not rows:
                return 0

            min_stream_id = rows[-1][0]

            update_rows = []
            for row in rows:
                try:
                    event_id = row[1]
                    event_json = json.loads(row[2])
                    sender = event_json["sender"]
                    content = event_json["content"]

                    contains_url = "url" in content
                    if contains_url:
                        contains_url &= isinstance(content["url"], basestring)
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                update_rows.append((sender, contains_url, event_id))

            sql = (
                "UPDATE events SET sender = ?, contains_url = ? WHERE event_id = ?"
            )

            for index in range(0, len(update_rows), INSERT_CLUMP_SIZE):
                clump = update_rows[index:index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows)
            }

            self._background_update_progress_txn(
                txn, self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, progress
            )

            return len(rows)

        result = yield self.runInteraction(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME, reindex_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME)

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _background_reindex_origin_server_ts(self, progress, batch_size):
        target_min_stream_id = progress["target_min_stream_id_inclusive"]
        max_stream_id = progress["max_stream_id_exclusive"]
        rows_inserted = progress.get("rows_inserted", 0)

        INSERT_CLUMP_SIZE = 1000

        def reindex_search_txn(txn):
            sql = (
                "SELECT stream_ordering, event_id FROM events"
                " WHERE ? <= stream_ordering AND stream_ordering < ?"
                " ORDER BY stream_ordering DESC"
                " LIMIT ?"
            )

            txn.execute(sql, (target_min_stream_id, max_stream_id, batch_size))

            rows = txn.fetchall()
            if not rows:
                return 0

            min_stream_id = rows[-1][0]
            event_ids = [row[1] for row in rows]

            events = self._get_events_txn(txn, event_ids)

            rows = []
            for event in events:
                try:
                    event_id = event.event_id
                    origin_server_ts = event.origin_server_ts
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                rows.append((origin_server_ts, event_id))

            sql = (
                "UPDATE events SET origin_server_ts = ? WHERE event_id = ?"
            )

            for index in range(0, len(rows), INSERT_CLUMP_SIZE):
                clump = rows[index:index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows)
            }

            self._background_update_progress_txn(
                txn, self.EVENT_ORIGIN_SERVER_TS_NAME, progress
            )

            return len(rows)

        result = yield self.runInteraction(
            self.EVENT_ORIGIN_SERVER_TS_NAME, reindex_search_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_ORIGIN_SERVER_TS_NAME)

        defer.returnValue(result)

    def get_current_backfill_token(self):
        """The current minimum token that backfilled events have reached"""
        return -self._backfill_id_gen.get_current_token()

    def get_all_new_events(self, last_backfill_id, last_forward_id,
                           current_backfill_id, current_forward_id, limit):
        """Get all the new events that have arrived at the server either as
        new events or as backfilled events"""
        have_backfill_events = last_backfill_id != current_backfill_id
        have_forward_events = last_forward_id != current_forward_id

        if not have_backfill_events and not have_forward_events:
            return defer.succeed(AllNewEventsResult([], [], [], [], []))

        def get_all_new_events_txn(txn):
            sql = (
                "SELECT e.stream_ordering, ej.internal_metadata, ej.json, eg.state_group"
                " FROM events as e"
                " JOIN event_json as ej"
                " ON e.event_id = ej.event_id AND e.room_id = ej.room_id"
                " LEFT JOIN event_to_state_groups as eg"
                " ON e.event_id = eg.event_id"
                " WHERE ? < e.stream_ordering AND e.stream_ordering <= ?"
                " ORDER BY e.stream_ordering ASC"
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
                    "SELECT event_stream_ordering FROM current_state_resets"
                    " WHERE ? < event_stream_ordering"
                    " AND event_stream_ordering <= ?"
                    " ORDER BY event_stream_ordering ASC"
                )
                txn.execute(sql, (last_forward_id, upper_bound))
                state_resets = txn.fetchall()

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
                state_resets = []
                forward_ex_outliers = []

            sql = (
                "SELECT -e.stream_ordering, ej.internal_metadata, ej.json,"
                " eg.state_group"
                " FROM events as e"
                " JOIN event_json as ej"
                " ON e.event_id = ej.event_id AND e.room_id = ej.room_id"
                " LEFT JOIN event_to_state_groups as eg"
                " ON e.event_id = eg.event_id"
                " WHERE ? > e.stream_ordering AND e.stream_ordering >= ?"
                " ORDER BY e.stream_ordering DESC"
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
                new_forward_events, new_backfill_events,
                forward_ex_outliers, backward_ex_outliers,
                state_resets,
            )
        return self.runInteraction("get_all_new_events", get_all_new_events_txn)

    def delete_old_state(self, room_id, topological_ordering):
        return self.runInteraction(
            "delete_old_state",
            self._delete_old_state_txn, room_id, topological_ordering
        )

    def _delete_old_state_txn(self, txn, room_id, topological_ordering):
        """Deletes old room state
        """

        # Tables that should be pruned:
        #     event_auth
        #     event_backward_extremities
        #     event_content_hashes
        #     event_destinations
        #     event_edge_hashes
        #     event_edges
        #     event_forward_extremities
        #     event_json
        #     event_push_actions
        #     event_reference_hashes
        #     event_search
        #     event_signatures
        #     event_to_state_groups
        #     events
        #     rejections
        #     room_depth
        #     state_groups
        #     state_groups_state

        # First ensure that we're not about to delete all the forward extremeties
        txn.execute(
            "SELECT e.event_id, e.depth FROM events as e "
            "INNER JOIN event_forward_extremities as f "
            "ON e.event_id = f.event_id "
            "AND e.room_id = f.room_id "
            "WHERE f.room_id = ?",
            (room_id,)
        )
        rows = txn.fetchall()
        max_depth = max(row[0] for row in rows)

        if max_depth <= topological_ordering:
            # We need to ensure we don't delete all the events from the datanase
            # otherwise we wouldn't be able to send any events (due to not
            # having any backwards extremeties)
            raise SynapseError(
                400, "topological_ordering is greater than forward extremeties"
            )

        txn.execute(
            "SELECT event_id, state_key FROM events"
            " LEFT JOIN state_events USING (room_id, event_id)"
            " WHERE room_id = ? AND topological_ordering < ?",
            (room_id, topological_ordering,)
        )
        event_rows = txn.fetchall()

        # We calculate the new entries for the backward extremeties by finding
        # all events that point to events that are to be purged
        txn.execute(
            "SELECT DISTINCT e.event_id FROM events as e"
            " INNER JOIN event_edges as ed ON e.event_id = ed.prev_event_id"
            " INNER JOIN events as e2 ON e2.event_id = ed.event_id"
            " WHERE e.room_id = ? AND e.topological_ordering < ?"
            " AND e2.topological_ordering >= ?",
            (room_id, topological_ordering, topological_ordering)
        )
        new_backwards_extrems = txn.fetchall()

        txn.execute(
            "DELETE FROM event_backward_extremities WHERE room_id = ?",
            (room_id,)
        )

        # Update backward extremeties
        txn.executemany(
            "INSERT INTO event_backward_extremities (room_id, event_id)"
            " VALUES (?, ?)",
            [
                (room_id, event_id) for event_id, in new_backwards_extrems
            ]
        )

        # Get all state groups that are only referenced by events that are
        # to be deleted.
        txn.execute(
            "SELECT state_group FROM event_to_state_groups"
            " INNER JOIN events USING (event_id)"
            " WHERE state_group IN ("
            "   SELECT DISTINCT state_group FROM events"
            "   INNER JOIN event_to_state_groups USING (event_id)"
            "   WHERE room_id = ? AND topological_ordering < ?"
            " )"
            " GROUP BY state_group HAVING MAX(topological_ordering) < ?",
            (room_id, topological_ordering, topological_ordering)
        )
        state_rows = txn.fetchall()
        txn.executemany(
            "DELETE FROM state_groups_state WHERE state_group = ?",
            state_rows
        )
        txn.executemany(
            "DELETE FROM state_groups WHERE id = ?",
            state_rows
        )
        # Delete all non-state
        txn.executemany(
            "DELETE FROM event_to_state_groups WHERE event_id = ?",
            [(event_id,) for event_id, _ in event_rows]
        )

        txn.execute(
            "UPDATE room_depth SET min_depth = ? WHERE room_id = ?",
            (topological_ordering, room_id,)
        )

        # Delete all remote non-state events
        to_delete = [
            (event_id,) for event_id, state_key in event_rows
            if state_key is None and not self.hs.is_mine_id(event_id)
        ]
        for table in (
            "events",
            "event_json",
            "event_auth",
            "event_content_hashes",
            "event_destinations",
            "event_edge_hashes",
            "event_edges",
            "event_forward_extremities",
            "event_push_actions",
            "event_reference_hashes",
            "event_search",
            "event_signatures",
            "rejections",
        ):
            txn.executemany(
                "DELETE FROM %s WHERE event_id = ?" % (table,),
                to_delete
            )

        txn.executemany(
            "DELETE FROM events WHERE event_id = ?",
            to_delete
        )
        # Mark all state and own events as outliers
        txn.executemany(
            "UPDATE events SET outlier = ?"
            " WHERE event_id = ?",
            [
                (True, event_id,) for event_id, state_key in event_rows
                if state_key is not None or self.hs.is_mine_id(event_id)
            ]
        )


AllNewEventsResult = namedtuple("AllNewEventsResult", [
    "new_forward_events", "new_backfill_events",
    "forward_ex_outliers", "backward_ex_outliers",
    "state_resets"
])
