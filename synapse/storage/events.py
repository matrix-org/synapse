# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018 New Vector Ltd
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
from collections import OrderedDict, deque, namedtuple
from functools import wraps

from six import iteritems, text_type
from six.moves import range

from canonicaljson import json
from prometheus_client import Counter

from twisted.internet import defer

import synapse.metrics
from synapse.api.constants import EventTypes
from synapse.api.errors import SynapseError
from synapse.events import EventBase  # noqa: F401
from synapse.events.snapshot import EventContext  # noqa: F401
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.state import StateResolutionStore
from synapse.storage.background_updates import BackgroundUpdateStore
from synapse.storage.event_federation import EventFederationStore
from synapse.storage.events_worker import EventsWorkerStore
from synapse.storage.state import StateGroupWorkerStore
from synapse.types import RoomStreamToken, get_domain_from_id
from synapse.util import batch_iter
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.caches.descriptors import cached, cachedInlineCallbacks
from synapse.util.frozenutils import frozendict_json_encoder
from synapse.util.logcontext import PreserveLoggingContext, make_deferred_yieldable
from synapse.util.logutils import log_function
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)

persist_event_counter = Counter("synapse_storage_events_persisted_events", "")
event_counter = Counter(
    "synapse_storage_events_persisted_events_sep",
    "",
    ["type", "origin_type", "origin_entity"],
)

# The number of times we are recalculating the current state
state_delta_counter = Counter("synapse_storage_events_state_delta", "")

# The number of times we are recalculating state when there is only a
# single forward extremity
state_delta_single_event_counter = Counter(
    "synapse_storage_events_state_delta_single_event", ""
)

# The number of times we are reculating state when we could have resonably
# calculated the delta when we calculated the state for an event we were
# persisting.
state_delta_reuse_delta_counter = Counter(
    "synapse_storage_events_state_delta_reuse_delta", ""
)


def encode_json(json_object):
    """
    Encode a Python object as JSON and return it in a Unicode string.
    """
    out = frozendict_json_encoder.encode(json_object)
    if isinstance(out, bytes):
        out = out.decode("utf8")
    return out


class _EventPeristenceQueue(object):
    """Queues up events so that they can be persisted in bulk with only one
    concurrent transaction per room.
    """

    _EventPersistQueueItem = namedtuple(
        "_EventPersistQueueItem", ("events_and_contexts", "backfilled", "deferred")
    )

    def __init__(self):
        self._event_persist_queues = {}
        self._currently_persisting_rooms = set()

    def add_to_queue(self, room_id, events_and_contexts, backfilled):
        """Add events to the queue, with the given persist_event options.

        NB: due to the normal usage pattern of this method, it does *not*
        follow the synapse logcontext rules, and leaves the logcontext in
        place whether or not the returned deferred is ready.

        Args:
            room_id (str):
            events_and_contexts (list[(EventBase, EventContext)]):
            backfilled (bool):

        Returns:
            defer.Deferred: a deferred which will resolve once the events are
                persisted. Runs its callbacks *without* a logcontext.
        """
        queue = self._event_persist_queues.setdefault(room_id, deque())
        if queue:
            # if the last item in the queue has the same `backfilled` setting,
            # we can just add these new events to that item.
            end_item = queue[-1]
            if end_item.backfilled == backfilled:
                end_item.events_and_contexts.extend(events_and_contexts)
                return end_item.deferred.observe()

        deferred = ObservableDeferred(defer.Deferred(), consumeErrors=True)

        queue.append(
            self._EventPersistQueueItem(
                events_and_contexts=events_and_contexts,
                backfilled=backfilled,
                deferred=deferred,
            )
        )

        return deferred.observe()

    def handle_queue(self, room_id, per_item_callback):
        """Attempts to handle the queue for a room if not already being handled.

        The given callback will be invoked with for each item in the queue,
        of type _EventPersistQueueItem. The per_item_callback will continuously
        be called with new items, unless the queue becomnes empty. The return
        value of the function will be given to the deferreds waiting on the item,
        exceptions will be passed to the deferreds as well.

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
                    except Exception:
                        with PreserveLoggingContext():
                            item.deferred.errback()
                    else:
                        with PreserveLoggingContext():
                            item.deferred.callback(ret)
            finally:
                queue = self._event_persist_queues.pop(room_id, None)
                if queue:
                    self._event_persist_queues[room_id] = queue
                self._currently_persisting_rooms.discard(room_id)

        # set handle_queue_loop off in the background
        run_as_background_process("persist_events", handle_queue_loop)

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


# inherits from EventFederationStore so that we can call _update_backward_extremities
# and _handle_mult_prev_events (though arguably those could both be moved in here)
class EventsStore(
    StateGroupWorkerStore,
    EventFederationStore,
    EventsWorkerStore,
    BackgroundUpdateStore,
):
    EVENT_ORIGIN_SERVER_TS_NAME = "event_origin_server_ts"
    EVENT_FIELDS_SENDER_URL_UPDATE_NAME = "event_fields_sender_url"

    def __init__(self, db_conn, hs):
        super(EventsStore, self).__init__(db_conn, hs)
        self.register_background_update_handler(
            self.EVENT_ORIGIN_SERVER_TS_NAME, self._background_reindex_origin_server_ts
        )
        self.register_background_update_handler(
            self.EVENT_FIELDS_SENDER_URL_UPDATE_NAME,
            self._background_reindex_fields_sender,
        )

        self.register_background_index_update(
            "event_contains_url_index",
            index_name="event_contains_url_index",
            table="events",
            columns=["room_id", "topological_ordering", "stream_ordering"],
            where_clause="contains_url = true AND outlier = false",
        )

        # an event_id index on event_search is useful for the purge_history
        # api. Plus it means we get to enforce some integrity with a UNIQUE
        # clause
        self.register_background_index_update(
            "event_search_event_id_idx",
            index_name="event_search_event_id_idx",
            table="event_search",
            columns=["event_id"],
            unique=True,
            psql_only=True,
        )

        self._event_persist_queue = _EventPeristenceQueue()

        self._state_resolution_handler = hs.get_state_resolution_handler()

    @defer.inlineCallbacks
    def persist_events(self, events_and_contexts, backfilled=False):
        """
        Write events to the database
        Args:
            events_and_contexts: list of tuples of (event, context)
            backfilled (bool): Whether the results are retrieved from federation
                via backfill or not. Used to determine if they're "new" events
                which might update the current state etc.

        Returns:
            Deferred[int]: the stream ordering of the latest persisted event
        """
        partitioned = {}
        for event, ctx in events_and_contexts:
            partitioned.setdefault(event.room_id, []).append((event, ctx))

        deferreds = []
        for room_id, evs_ctxs in iteritems(partitioned):
            d = self._event_persist_queue.add_to_queue(
                room_id, evs_ctxs, backfilled=backfilled
            )
            deferreds.append(d)

        for room_id in partitioned:
            self._maybe_start_persisting(room_id)

        yield make_deferred_yieldable(
            defer.gatherResults(deferreds, consumeErrors=True)
        )

        max_persisted_id = yield self._stream_id_gen.get_current_token()

        defer.returnValue(max_persisted_id)

    @defer.inlineCallbacks
    @log_function
    def persist_event(self, event, context, backfilled=False):
        """

        Args:
            event (EventBase):
            context (EventContext):
            backfilled (bool):

        Returns:
            Deferred: resolves to (int, int): the stream ordering of ``event``,
            and the stream ordering of the latest persisted event
        """
        deferred = self._event_persist_queue.add_to_queue(
            event.room_id, [(event, context)], backfilled=backfilled
        )

        self._maybe_start_persisting(event.room_id)

        yield make_deferred_yieldable(deferred)

        max_persisted_id = yield self._stream_id_gen.get_current_token()
        defer.returnValue((event.internal_metadata.stream_ordering, max_persisted_id))

    def _maybe_start_persisting(self, room_id):
        @defer.inlineCallbacks
        def persisting_queue(item):
            with Measure(self._clock, "persist_events"):
                yield self._persist_events(
                    item.events_and_contexts, backfilled=item.backfilled
                )

        self._event_persist_queue.handle_queue(room_id, persisting_queue)

    @_retry_on_integrity_error
    @defer.inlineCallbacks
    def _persist_events(
        self, events_and_contexts, backfilled=False, delete_existing=False
    ):
        """Persist events to db

        Args:
            events_and_contexts (list[(EventBase, EventContext)]):
            backfilled (bool):
            delete_existing (bool):

        Returns:
            Deferred: resolves when the events have been persisted
        """
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

        with stream_ordering_manager as stream_orderings:
            for (event, context), stream in zip(events_and_contexts, stream_orderings):
                event.internal_metadata.stream_ordering = stream

            chunks = [
                events_and_contexts[x : x + 100]
                for x in range(0, len(events_and_contexts), 100)
            ]

            for chunk in chunks:
                # We can't easily parallelize these since different chunks
                # might contain the same event. :(

                # NB: Assumes that we are only persisting events for one room
                # at a time.

                # map room_id->list[event_ids] giving the new forward
                # extremities in each room
                new_forward_extremeties = {}

                # map room_id->(type,state_key)->event_id tracking the full
                # state in each room after adding these events.
                # This is simply used to prefill the get_current_state_ids
                # cache
                current_state_for_room = {}

                # map room_id->(to_delete, to_insert) where to_delete is a list
                # of type/state keys to remove from current state, and to_insert
                # is a map (type,key)->event_id giving the state delta in each
                # room
                state_delta_for_room = {}

                if not backfilled:
                    with Measure(self._clock, "_calculate_state_and_extrem"):
                        # Work out the new "current state" for each room.
                        # We do this by working out what the new extremities are and then
                        # calculating the state from that.
                        events_by_room = {}
                        for event, context in chunk:
                            events_by_room.setdefault(event.room_id, []).append(
                                (event, context)
                            )

                        for room_id, ev_ctx_rm in iteritems(events_by_room):
                            latest_event_ids = yield self.get_latest_event_ids_in_room(
                                room_id
                            )
                            new_latest_event_ids = yield self._calculate_new_extremities(
                                room_id, ev_ctx_rm, latest_event_ids
                            )

                            latest_event_ids = set(latest_event_ids)
                            if new_latest_event_ids == latest_event_ids:
                                # No change in extremities, so no change in state
                                continue

                            # there should always be at least one forward extremity.
                            # (except during the initial persistence of the send_join
                            # results, in which case there will be no existing
                            # extremities, so we'll `continue` above and skip this bit.)
                            assert new_latest_event_ids, "No forward extremities left!"

                            new_forward_extremeties[room_id] = new_latest_event_ids

                            len_1 = (
                                len(latest_event_ids) == 1
                                and len(new_latest_event_ids) == 1
                            )
                            if len_1:
                                all_single_prev_not_state = all(
                                    len(event.prev_event_ids()) == 1
                                    and not event.is_state()
                                    for event, ctx in ev_ctx_rm
                                )
                                # Don't bother calculating state if they're just
                                # a long chain of single ancestor non-state events.
                                if all_single_prev_not_state:
                                    continue

                            state_delta_counter.inc()
                            if len(new_latest_event_ids) == 1:
                                state_delta_single_event_counter.inc()

                                # This is a fairly handwavey check to see if we could
                                # have guessed what the delta would have been when
                                # processing one of these events.
                                # What we're interested in is if the latest extremities
                                # were the same when we created the event as they are
                                # now. When this server creates a new event (as opposed
                                # to receiving it over federation) it will use the
                                # forward extremities as the prev_events, so we can
                                # guess this by looking at the prev_events and checking
                                # if they match the current forward extremities.
                                for ev, _ in ev_ctx_rm:
                                    prev_event_ids = set(ev.prev_event_ids())
                                    if latest_event_ids == prev_event_ids:
                                        state_delta_reuse_delta_counter.inc()
                                        break

                            logger.info("Calculating state delta for room %s", room_id)
                            with Measure(
                                self._clock, "persist_events.get_new_state_after_events"
                            ):
                                res = yield self._get_new_state_after_events(
                                    room_id,
                                    ev_ctx_rm,
                                    latest_event_ids,
                                    new_latest_event_ids,
                                )
                                current_state, delta_ids = res

                            # If either are not None then there has been a change,
                            # and we need to work out the delta (or use that
                            # given)
                            if delta_ids is not None:
                                # If there is a delta we know that we've
                                # only added or replaced state, never
                                # removed keys entirely.
                                state_delta_for_room[room_id] = ([], delta_ids)
                            elif current_state is not None:
                                with Measure(
                                    self._clock, "persist_events.calculate_state_delta"
                                ):
                                    delta = yield self._calculate_state_delta(
                                        room_id, current_state
                                    )
                                state_delta_for_room[room_id] = delta

                            # If we have the current_state then lets prefill
                            # the cache with it.
                            if current_state is not None:
                                current_state_for_room[room_id] = current_state

                yield self.runInteraction(
                    "persist_events",
                    self._persist_events_txn,
                    events_and_contexts=chunk,
                    backfilled=backfilled,
                    delete_existing=delete_existing,
                    state_delta_for_room=state_delta_for_room,
                    new_forward_extremeties=new_forward_extremeties,
                )
                persist_event_counter.inc(len(chunk))

                if not backfilled:
                    # backfilled events have negative stream orderings, so we don't
                    # want to set the event_persisted_position to that.
                    synapse.metrics.event_persisted_position.set(
                        chunk[-1][0].internal_metadata.stream_ordering
                    )

                for event, context in chunk:
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
    def _calculate_new_extremities(self, room_id, event_contexts, latest_event_ids):
        """Calculates the new forward extremities for a room given events to
        persist.

        Assumes that we are only persisting events for one room at a time.
        """

        # we're only interested in new events which aren't outliers and which aren't
        # being rejected.
        new_events = [
            event
            for event, ctx in event_contexts
            if not event.internal_metadata.is_outlier()
            and not ctx.rejected
            and not event.internal_metadata.is_soft_failed()
        ]

        # start with the existing forward extremities
        result = set(latest_event_ids)

        # add all the new events to the list
        result.update(event.event_id for event in new_events)

        # Now remove all events which are prev_events of any of the new events
        result.difference_update(
            e_id for event in new_events for e_id in event.prev_event_ids()
        )

        # Finally, remove any events which are prev_events of any existing events.
        existing_prevs = yield self._get_events_which_are_prevs(result)
        result.difference_update(existing_prevs)

        defer.returnValue(result)

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

        def _get_events(txn, batch):
            sql = """
            SELECT prev_event_id
            FROM event_edges
                INNER JOIN events USING (event_id)
                LEFT JOIN rejections USING (event_id)
            WHERE
                prev_event_id IN (%s)
                AND NOT events.outlier
                AND rejections.event_id IS NULL
            """ % (
                ",".join("?" for _ in batch),
            )

            txn.execute(sql, batch)
            results.extend(r[0] for r in txn)

        for chunk in batch_iter(event_ids, 100):
            yield self.runInteraction("_get_events_which_are_prevs", _get_events, chunk)

        defer.returnValue(results)

    @defer.inlineCallbacks
    def _get_new_state_after_events(
        self, room_id, events_context, old_latest_event_ids, new_latest_event_ids
    ):
        """Calculate the current state dict after adding some new events to
        a room

        Args:
            room_id (str):
                room to which the events are being added. Used for logging etc

            events_context (list[(EventBase, EventContext)]):
                events and contexts which are being added to the room

            old_latest_event_ids (iterable[str]):
                the old forward extremities for the room.

            new_latest_event_ids (iterable[str]):
                the new forward extremities for the room.

        Returns:
            Deferred[tuple[dict[(str,str), str]|None, dict[(str,str), str]|None]]:
            Returns a tuple of two state maps, the first being the full new current
            state and the second being the delta to the existing current state.
            If both are None then there has been no change.

            If there has been a change then we only return the delta if its
            already been calculated. Conversely if we do know the delta then
            the new current state is only returned if we've already calculated
            it.
        """
        # map from state_group to ((type, key) -> event_id) state map
        state_groups_map = {}

        # Map from (prev state group, new state group) -> delta state dict
        state_group_deltas = {}

        for ev, ctx in events_context:
            if ctx.state_group is None:
                # This should only happen for outlier events.
                if not ev.internal_metadata.is_outlier():
                    raise Exception(
                        "Context for new event %s has no state "
                        "group" % (ev.event_id,)
                    )
                continue

            if ctx.state_group in state_groups_map:
                continue

            # We're only interested in pulling out state that has already
            # been cached in the context. We'll pull stuff out of the DB later
            # if necessary.
            current_state_ids = ctx.get_cached_current_state_ids()
            if current_state_ids is not None:
                state_groups_map[ctx.state_group] = current_state_ids

            if ctx.prev_group:
                state_group_deltas[(ctx.prev_group, ctx.state_group)] = ctx.delta_ids

        # We need to map the event_ids to their state groups. First, let's
        # check if the event is one we're persisting, in which case we can
        # pull the state group from its context.
        # Otherwise we need to pull the state group from the database.

        # Set of events we need to fetch groups for. (We know none of the old
        # extremities are going to be in events_context).
        missing_event_ids = set(old_latest_event_ids)

        event_id_to_state_group = {}
        for event_id in new_latest_event_ids:
            # First search in the list of new events we're adding.
            for ev, ctx in events_context:
                if event_id == ev.event_id and ctx.state_group is not None:
                    event_id_to_state_group[event_id] = ctx.state_group
                    break
            else:
                # If we couldn't find it, then we'll need to pull
                # the state from the database
                missing_event_ids.add(event_id)

        if missing_event_ids:
            # Now pull out the state groups for any missing events from DB
            event_to_groups = yield self._get_state_group_for_events(missing_event_ids)
            event_id_to_state_group.update(event_to_groups)

        # State groups of old_latest_event_ids
        old_state_groups = set(
            event_id_to_state_group[evid] for evid in old_latest_event_ids
        )

        # State groups of new_latest_event_ids
        new_state_groups = set(
            event_id_to_state_group[evid] for evid in new_latest_event_ids
        )

        # If they old and new groups are the same then we don't need to do
        # anything.
        if old_state_groups == new_state_groups:
            defer.returnValue((None, None))

        if len(new_state_groups) == 1 and len(old_state_groups) == 1:
            # If we're going from one state group to another, lets check if
            # we have a delta for that transition. If we do then we can just
            # return that.

            new_state_group = next(iter(new_state_groups))
            old_state_group = next(iter(old_state_groups))

            delta_ids = state_group_deltas.get((old_state_group, new_state_group), None)
            if delta_ids is not None:
                # We have a delta from the existing to new current state,
                # so lets just return that. If we happen to already have
                # the current state in memory then lets also return that,
                # but it doesn't matter if we don't.
                new_state = state_groups_map.get(new_state_group)
                defer.returnValue((new_state, delta_ids))

        # Now that we have calculated new_state_groups we need to get
        # their state IDs so we can resolve to a single state set.
        missing_state = new_state_groups - set(state_groups_map)
        if missing_state:
            group_to_state = yield self._get_state_for_groups(missing_state)
            state_groups_map.update(group_to_state)

        if len(new_state_groups) == 1:
            # If there is only one state group, then we know what the current
            # state is.
            defer.returnValue((state_groups_map[new_state_groups.pop()], None))

        # Ok, we need to defer to the state handler to resolve our state sets.

        state_groups = {sg: state_groups_map[sg] for sg in new_state_groups}

        events_map = {ev.event_id: ev for ev, _ in events_context}

        # We need to get the room version, which is in the create event.
        # Normally that'd be in the database, but its also possible that we're
        # currently trying to persist it.
        room_version = None
        for ev, _ in events_context:
            if ev.type == EventTypes.Create and ev.state_key == "":
                room_version = ev.content.get("room_version", "1")
                break

        if not room_version:
            room_version = yield self.get_room_version(room_id)

        logger.debug("calling resolve_state_groups from preserve_events")
        res = yield self._state_resolution_handler.resolve_state_groups(
            room_id,
            room_version,
            state_groups,
            events_map,
            state_res_store=StateResolutionStore(self),
        )

        defer.returnValue((res.state, None))

    @defer.inlineCallbacks
    def _calculate_state_delta(self, room_id, current_state):
        """Calculate the new state deltas for a room.

        Assumes that we are only persisting events for one room at a time.

        Returns:
            tuple[list, dict] (to_delete, to_insert): where to_delete are the
            type/state_keys to remove from current_state_events and `to_insert`
            are the updates to current_state_events.
        """
        existing_state = yield self.get_current_state_ids(room_id)

        to_delete = [key for key in existing_state if key not in current_state]

        to_insert = {
            key: ev_id
            for key, ev_id in iteritems(current_state)
            if ev_id != existing_state.get(key)
        }

        defer.returnValue((to_delete, to_insert))

    @log_function
    def _persist_events_txn(
        self,
        txn,
        events_and_contexts,
        backfilled,
        delete_existing=False,
        state_delta_for_room={},
        new_forward_extremeties={},
    ):
        """Insert some number of room events into the necessary database tables.

        Rejected events are only inserted into the events table, the events_json table,
        and the rejections table. Things reading from those table will need to check
        whether the event was rejected.

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            events_and_contexts (list[(EventBase, EventContext)]):
                events to persist
            backfilled (bool): True if the events were backfilled
            delete_existing (bool): True to purge existing table rows for the
                events from the database. This is useful when retrying due to
                IntegrityError.
            state_delta_for_room (dict[str, (list, dict)]):
                The current-state delta for each room. For each room, a tuple
                (to_delete, to_insert), being a list of type/state keys to be
                removed from the current state, and a state set to be added to
                the current state.
            new_forward_extremeties (dict[str, list[str]]):
                The new forward extremities for each room. For each room, a
                list of the event ids which are the forward extremities.

        """
        all_events_and_contexts = events_and_contexts

        min_stream_order = events_and_contexts[0][0].internal_metadata.stream_ordering
        max_stream_order = events_and_contexts[-1][0].internal_metadata.stream_ordering

        self._update_current_state_txn(txn, state_delta_for_room, min_stream_order)

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

    def _update_current_state_txn(self, txn, state_delta_by_room, stream_id):
        for room_id, current_state_tuple in iteritems(state_delta_by_room):
            to_delete, to_insert = current_state_tuple

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
                        None,
                        room_id,
                        etype,
                        state_key,
                    )
                    for etype, state_key in to_delete
                    # We sanity check that we're deleting rather than updating
                    if (etype, state_key) not in to_insert
                ),
            )
            txn.executemany(
                sql,
                (
                    (
                        stream_id,
                        room_id,
                        etype,
                        state_key,
                        ev_id,
                        room_id,
                        etype,
                        state_key,
                    )
                    for (etype, state_key), ev_id in iteritems(to_insert)
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

            self._simple_insert_many_txn(
                txn,
                table="current_state_events",
                values=[
                    {
                        "event_id": ev_id,
                        "room_id": room_id,
                        "type": key[0],
                        "state_key": key[1],
                    }
                    for key, ev_id in iteritems(to_insert)
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
            members_changed = set(
                state_key
                for ev_type, state_key in itertools.chain(to_delete, to_insert)
                if ev_type == EventTypes.Member
            )

            for member in members_changed:
                txn.call_after(
                    self.get_rooms_for_user_with_stream_ordering.invalidate, (member,)
                )

            self._invalidate_state_caches_and_stream(txn, room_id, members_changed)

    def _update_forward_extremities_txn(
        self, txn, new_forward_extremities, max_stream_order
    ):
        for room_id, new_extrem in iteritems(new_forward_extremities):
            self._simple_delete_txn(
                txn, table="event_forward_extremities", keyvalues={"room_id": room_id}
            )
            txn.call_after(self.get_latest_event_ids_in_room.invalidate, (room_id,))

        self._simple_insert_many_txn(
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
        self._simple_insert_many_txn(
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

                sql = (
                    "UPDATE event_json SET internal_metadata = ?" " WHERE event_id = ?"
                )
                txn.execute(sql, (metadata_json, event.event_id))

                # Add an entry to the ex_outlier_stream table to replicate the
                # change in outlier status to our workers.
                stream_order = event.internal_metadata.stream_ordering
                state_group_id = context.state_group
                self._simple_insert_txn(
                    txn,
                    table="ex_outlier_stream",
                    values={
                        "event_stream_ordering": stream_order,
                        "event_id": event.event_id,
                        "state_group": state_group_id,
                    },
                )

                sql = "UPDATE events SET outlier = ?" " WHERE event_id = ?"
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
            "guest_access",
            "history_visibility",
            "local_invites",
            "room_names",
            "state_events",
            "rejections",
            "redactions",
            "room_memberships",
            "topics",
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

        self._simple_insert_many_txn(
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

        # Update the event_forward_extremities, event_backward_extremities and
        # event_edges tables.
        self._handle_mult_prev_events(
            txn, events=[event for event, _ in events_and_contexts]
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

        self._simple_insert_many_txn(txn, table="state_events", values=state_values)

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
                " WHERE e.event_id IN (%s)"
            ) % (",".join(["?"] * len(ev_map)),)

            txn.execute(sql, list(ev_map))
            rows = self.cursor_to_dict(txn)
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
        txn.execute(
            "INSERT INTO redactions (event_id, redacts) VALUES (?,?)",
            (event.event_id, event.redacts),
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
            count, = txn.fetchone()
            return count

        ret = yield self.runInteraction("count_messages", _count_messages)
        defer.returnValue(ret)

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
            count, = txn.fetchone()
            return count

        ret = yield self.runInteraction("count_daily_sent_messages", _count_messages)
        defer.returnValue(ret)

    @defer.inlineCallbacks
    def count_daily_active_rooms(self):
        def _count(txn):
            sql = """
                SELECT COALESCE(COUNT(DISTINCT room_id), 0) FROM events
                WHERE type = 'm.room.message'
                AND stream_ordering > ?
            """
            txn.execute(sql, (self.stream_ordering_day_ago,))
            count, = txn.fetchone()
            return count

        ret = yield self.runInteraction("count_daily_active_rooms", _count)
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
                        contains_url &= isinstance(content["url"], text_type)
                except (KeyError, AttributeError):
                    # If the event is missing a necessary field then
                    # skip over it.
                    continue

                update_rows.append((sender, contains_url, event_id))

            sql = "UPDATE events SET sender = ?, contains_url = ? WHERE event_id = ?"

            for index in range(0, len(update_rows), INSERT_CLUMP_SIZE):
                clump = update_rows[index : index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows),
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

            rows_to_update = []

            chunks = [event_ids[i : i + 100] for i in range(0, len(event_ids), 100)]
            for chunk in chunks:
                ev_rows = self._simple_select_many_txn(
                    txn,
                    table="event_json",
                    column="event_id",
                    iterable=chunk,
                    retcols=["event_id", "json"],
                    keyvalues={},
                )

                for row in ev_rows:
                    event_id = row["event_id"]
                    event_json = json.loads(row["json"])
                    try:
                        origin_server_ts = event_json["origin_server_ts"]
                    except (KeyError, AttributeError):
                        # If the event is missing a necessary field then
                        # skip over it.
                        continue

                    rows_to_update.append((origin_server_ts, event_id))

            sql = "UPDATE events SET origin_server_ts = ? WHERE event_id = ?"

            for index in range(0, len(rows_to_update), INSERT_CLUMP_SIZE):
                clump = rows_to_update[index : index + INSERT_CLUMP_SIZE]
                txn.executemany(sql, clump)

            progress = {
                "target_min_stream_id_inclusive": target_min_stream_id,
                "max_stream_id_exclusive": min_stream_id,
                "rows_inserted": rows_inserted + len(rows_to_update),
            }

            self._background_update_progress_txn(
                txn, self.EVENT_ORIGIN_SERVER_TS_NAME, progress
            )

            return len(rows_to_update)

        result = yield self.runInteraction(
            self.EVENT_ORIGIN_SERVER_TS_NAME, reindex_search_txn
        )

        if not result:
            yield self._end_background_update(self.EVENT_ORIGIN_SERVER_TS_NAME)

        defer.returnValue(result)

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
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
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
                " state_key, redacts"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? < event_stream_ordering"
                " AND event_stream_ordering <= ?"
                " ORDER BY event_stream_ordering DESC"
            )
            txn.execute(sql, (last_id, upper_bound))
            new_event_updates.extend(txn)

            return new_event_updates

        return self.runInteraction(
            "get_all_new_forward_event_rows", get_all_new_forward_event_rows
        )

    def get_all_new_backfill_event_rows(self, last_id, current_id, limit):
        if last_id == current_id:
            return defer.succeed([])

        def get_all_new_backfill_event_rows(txn):
            sql = (
                "SELECT -e.stream_ordering, e.event_id, e.room_id, e.type,"
                " state_key, redacts"
                " FROM events AS e"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
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
                " state_key, redacts"
                " FROM events AS e"
                " INNER JOIN ex_outlier_stream USING (event_id)"
                " LEFT JOIN redactions USING (event_id)"
                " LEFT JOIN state_events USING (event_id)"
                " WHERE ? > event_stream_ordering"
                " AND event_stream_ordering >= ?"
                " ORDER BY event_stream_ordering DESC"
            )
            txn.execute(sql, (-last_id, -upper_bound))
            new_event_updates.extend(txn.fetchall())

            return new_event_updates

        return self.runInteraction(
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

        return self.runInteraction("get_all_new_events", get_all_new_events_txn)

    def purge_history(self, room_id, token, delete_local_events):
        """Deletes room history before a certain point

        Args:
            room_id (str):

            token (str): A topological token to delete events before

            delete_local_events (bool):
                if True, we will delete local events as well as remote ones
                (instead of just marking them as outliers and deleting their
                state groups).
        """

        return self.runInteraction(
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
        txn.execute("CREATE INDEX events_to_purge_id" " ON events_to_purge(event_id)")

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

        logger.info("[purge] finding redundant state groups")

        # Get all state groups that are referenced by events that are to be
        # deleted. We then go and check if they are referenced by other events
        # or state groups, and if not we delete them.
        txn.execute(
            """
            SELECT DISTINCT state_group FROM events_to_purge
            INNER JOIN event_to_state_groups USING (event_id)
        """
        )

        referenced_state_groups = set(sg for sg, in txn)
        logger.info(
            "[purge] found %i referenced state groups", len(referenced_state_groups)
        )

        logger.info("[purge] finding state groups that can be deleted")

        _ = self._find_unreferenced_groups_during_purge(txn, referenced_state_groups)
        state_groups_to_delete, remaining_state_groups = _

        logger.info(
            "[purge] found %i state groups to delete", len(state_groups_to_delete)
        )

        logger.info(
            "[purge] de-delta-ing %i remaining state groups",
            len(remaining_state_groups),
        )

        # Now we turn the state groups that reference to-be-deleted state
        # groups to non delta versions.
        for sg in remaining_state_groups:
            logger.info("[purge] de-delta-ing remaining state group %s", sg)
            curr_state = self._get_state_groups_from_groups_txn(txn, [sg])
            curr_state = curr_state[sg]

            self._simple_delete_txn(
                txn, table="state_groups_state", keyvalues={"state_group": sg}
            )

            self._simple_delete_txn(
                txn, table="state_group_edges", keyvalues={"state_group": sg}
            )

            self._simple_insert_many_txn(
                txn,
                table="state_groups_state",
                values=[
                    {
                        "state_group": sg,
                        "room_id": room_id,
                        "type": key[0],
                        "state_key": key[1],
                        "event_id": state_id,
                    }
                    for key, state_id in iteritems(curr_state)
                ],
            )

        logger.info("[purge] removing redundant state groups")
        txn.executemany(
            "DELETE FROM state_groups_state WHERE state_group = ?",
            ((sg,) for sg in state_groups_to_delete),
        )
        txn.executemany(
            "DELETE FROM state_groups WHERE id = ?",
            ((sg,) for sg in state_groups_to_delete),
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
        min_depth, = txn.fetchone()

        logger.info("[purge] updating room_depth to %d", min_depth)

        txn.execute(
            "UPDATE room_depth SET min_depth = ? WHERE room_id = ?",
            (min_depth, room_id),
        )

        # finally, drop the temp table. this will commit the txn in sqlite,
        # so make sure to keep this actually last.
        txn.execute("DROP TABLE events_to_purge")

        logger.info("[purge] done")

    def _find_unreferenced_groups_during_purge(self, txn, state_groups):
        """Used when purging history to figure out which state groups can be
        deleted and which need to be de-delta'ed (due to one of its prev groups
        being scheduled for deletion).

        Args:
            txn
            state_groups (set[int]): Set of state groups referenced by events
                that are going to be deleted.

        Returns:
            tuple[set[int], set[int]]: The set of state groups that can be
            deleted and the set of state groups that need to be de-delta'ed
        """
        # Graph of state group -> previous group
        graph = {}

        # Set of events that we have found to be referenced by events
        referenced_groups = set()

        # Set of state groups we've already seen
        state_groups_seen = set(state_groups)

        # Set of state groups to handle next.
        next_to_search = set(state_groups)
        while next_to_search:
            # We bound size of groups we're looking up at once, to stop the
            # SQL query getting too big
            if len(next_to_search) < 100:
                current_search = next_to_search
                next_to_search = set()
            else:
                current_search = set(itertools.islice(next_to_search, 100))
                next_to_search -= current_search

            # Check if state groups are referenced
            sql = """
                SELECT DISTINCT state_group FROM event_to_state_groups
                LEFT JOIN events_to_purge AS ep USING (event_id)
                WHERE state_group IN (%s) AND ep.event_id IS NULL
            """ % (
                ",".join("?" for _ in current_search),
            )
            txn.execute(sql, list(current_search))

            referenced = set(sg for sg, in txn)
            referenced_groups |= referenced

            # We don't continue iterating up the state group graphs for state
            # groups that are referenced.
            current_search -= referenced

            rows = self._simple_select_many_txn(
                txn,
                table="state_group_edges",
                column="prev_state_group",
                iterable=current_search,
                keyvalues={},
                retcols=("prev_state_group", "state_group"),
            )

            prevs = set(row["state_group"] for row in rows)
            # We don't bother re-handling groups we've already seen
            prevs -= state_groups_seen
            next_to_search |= prevs
            state_groups_seen |= prevs

            for row in rows:
                # Note: Each state group can have at most one prev group
                graph[row["state_group"]] = row["prev_state_group"]

        to_delete = state_groups_seen - referenced_groups

        to_dedelta = set()
        for sg in referenced_groups:
            prev_sg = graph.get(sg)
            if prev_sg and prev_sg in to_delete:
                to_dedelta.add(sg)

        return to_delete, to_dedelta

    @defer.inlineCallbacks
    def is_event_after(self, event_id1, event_id2):
        """Returns True if event_id1 is after event_id2 in the stream
        """
        to_1, so_1 = yield self._get_event_ordering(event_id1)
        to_2, so_2 = yield self._get_event_ordering(event_id2)
        defer.returnValue((to_1, so_1) > (to_2, so_2))

    @cachedInlineCallbacks(max_entries=5000)
    def _get_event_ordering(self, event_id):
        res = yield self._simple_select_one(
            table="events",
            retcols=["topological_ordering", "stream_ordering"],
            keyvalues={"event_id": event_id},
            allow_none=True,
        )

        if not res:
            raise SynapseError(404, "Could not find event %s" % (event_id,))

        defer.returnValue(
            (int(res["topological_ordering"]), int(res["stream_ordering"]))
        )

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

        return self.runInteraction(
            "get_all_updated_current_state_deltas",
            get_all_updated_current_state_deltas_txn,
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
