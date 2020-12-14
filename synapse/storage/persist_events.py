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
from collections import deque, namedtuple
from typing import Dict, Iterable, List, Optional, Set, Tuple

from prometheus_client import Counter, Histogram

from twisted.internet import defer

from synapse.api.constants import EventTypes, Membership
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.metrics.background_process_metrics import run_as_background_process
from synapse.storage.databases import Databases
from synapse.storage.databases.main.events import DeltaState
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.types import (
    Collection,
    PersistedEventPosition,
    RoomStreamToken,
    StateMap,
    get_domain_from_id,
)
from synapse.util.async_helpers import ObservableDeferred
from synapse.util.metrics import Measure

logger = logging.getLogger(__name__)

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

# The number of forward extremities for each new event.
forward_extremities_counter = Histogram(
    "synapse_storage_events_forward_extremities_persisted",
    "Number of forward extremities for each new event",
    buckets=(1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"),
)

# The number of stale forward extremities for each new event. Stale extremities
# are those that were in the previous set of extremities as well as the new.
stale_forward_extremities_counter = Histogram(
    "synapse_storage_events_stale_forward_extremities_persisted",
    "Number of unchanged forward extremities for each new event",
    buckets=(0, 1, 2, 3, 5, 7, 10, 15, 20, 50, 100, 200, 500, "+Inf"),
)

state_resolutions_during_persistence = Counter(
    "synapse_storage_events_state_resolutions_during_persistence",
    "Number of times we had to do state res to calculate new current state",
)

potential_times_prune_extremities = Counter(
    "synapse_storage_events_potential_times_prune_extremities",
    "Number of times we might be able to prune extremities",
)

times_pruned_extremities = Counter(
    "synapse_storage_events_times_pruned_extremities",
    "Number of times we were actually be able to prune extremities",
)


class _EventPeristenceQueue:
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
            persisted. Runs its callbacks *without* a logcontext. The result
            is the same as that returned by the callback passed to
            `handle_queue`.
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

        async def handle_queue_loop():
            try:
                queue = self._get_drainining_queue(room_id)
                for item in queue:
                    try:
                        ret = await per_item_callback(item)
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


class EventsPersistenceStorage:
    """High level interface for handling persisting newly received events.

    Takes care of batching up events by room, and calculating the necessary
    current state and forward extremity changes.
    """

    def __init__(self, hs, stores: Databases):
        # We ultimately want to split out the state store from the main store,
        # so we use separate variables here even though they point to the same
        # store for now.
        self.main_store = stores.main
        self.state_store = stores.state

        assert stores.persist_events
        self.persist_events_store = stores.persist_events

        self._clock = hs.get_clock()
        self._instance_name = hs.get_instance_name()
        self.is_mine_id = hs.is_mine_id
        self._event_persist_queue = _EventPeristenceQueue()
        self._state_resolution_handler = hs.get_state_resolution_handler()

    async def persist_events(
        self,
        events_and_contexts: Iterable[Tuple[EventBase, EventContext]],
        backfilled: bool = False,
    ) -> Tuple[List[EventBase], RoomStreamToken]:
        """
        Write events to the database
        Args:
            events_and_contexts: list of tuples of (event, context)
            backfilled: Whether the results are retrieved from federation
                via backfill or not. Used to determine if they're "new" events
                which might update the current state etc.

        Returns:
            List of events persisted, the current position room stream position.
            The list of events persisted may not be the same as those passed in
            if they were deduplicated due to an event already existing that
            matched the transcation ID; the existing event is returned in such
            a case.
        """
        partitioned = {}  # type: Dict[str, List[Tuple[EventBase, EventContext]]]
        for event, ctx in events_and_contexts:
            partitioned.setdefault(event.room_id, []).append((event, ctx))

        deferreds = []
        for room_id, evs_ctxs in partitioned.items():
            d = self._event_persist_queue.add_to_queue(
                room_id, evs_ctxs, backfilled=backfilled
            )
            deferreds.append(d)

        for room_id in partitioned:
            self._maybe_start_persisting(room_id)

        # Each deferred returns a map from event ID to existing event ID if the
        # event was deduplicated. (The dict may also include other entries if
        # the event was persisted in a batch with other events).
        #
        # Since we use `defer.gatherResults` we need to merge the returned list
        # of dicts into one.
        ret_vals = await make_deferred_yieldable(
            defer.gatherResults(deferreds, consumeErrors=True)
        )
        replaced_events = {}
        for d in ret_vals:
            replaced_events.update(d)

        events = []
        for event, _ in events_and_contexts:
            existing_event_id = replaced_events.get(event.event_id)
            if existing_event_id:
                events.append(await self.main_store.get_event(existing_event_id))
            else:
                events.append(event)

        return (
            events,
            self.main_store.get_room_max_token(),
        )

    async def persist_event(
        self, event: EventBase, context: EventContext, backfilled: bool = False
    ) -> Tuple[EventBase, PersistedEventPosition, RoomStreamToken]:
        """
        Returns:
            The event, stream ordering of `event`, and the stream ordering of the
            latest persisted event. The returned event may not match the given
            event if it was deduplicated due to an existing event matching the
            transaction ID.
        """
        deferred = self._event_persist_queue.add_to_queue(
            event.room_id, [(event, context)], backfilled=backfilled
        )

        self._maybe_start_persisting(event.room_id)

        # The deferred returns a map from event ID to existing event ID if the
        # event was deduplicated. (The dict may also include other entries if
        # the event was persisted in a batch with other events.)
        replaced_events = await make_deferred_yieldable(deferred)
        replaced_event = replaced_events.get(event.event_id)
        if replaced_event:
            event = await self.main_store.get_event(replaced_event)

        event_stream_id = event.internal_metadata.stream_ordering
        # stream ordering should have been assigned by now
        assert event_stream_id

        pos = PersistedEventPosition(self._instance_name, event_stream_id)
        return event, pos, self.main_store.get_room_max_token()

    def _maybe_start_persisting(self, room_id: str):
        """Pokes the `_event_persist_queue` to start handling new items in the
        queue, if not already in progress.

        Causes the deferreds returned by `add_to_queue` to resolve with: a
        dictionary of event ID to event ID we didn't persist as we already had
        another event persisted with the same TXN ID.
        """

        async def persisting_queue(item):
            with Measure(self._clock, "persist_events"):
                return await self._persist_events(
                    item.events_and_contexts, backfilled=item.backfilled
                )

        self._event_persist_queue.handle_queue(room_id, persisting_queue)

    async def _persist_events(
        self,
        events_and_contexts: List[Tuple[EventBase, EventContext]],
        backfilled: bool = False,
    ) -> Dict[str, str]:
        """Calculates the change to current state and forward extremities, and
        persists the given events and with those updates.

        Returns:
            A dictionary of event ID to event ID we didn't persist as we already
            had another event persisted with the same TXN ID.
        """
        replaced_events = {}  # type: Dict[str, str]
        if not events_and_contexts:
            return replaced_events

        # Check if any of the events have a transaction ID that has already been
        # persisted, and if so we don't persist it again.
        #
        # We should have checked this a long time before we get here, but it's
        # possible that different send event requests race in such a way that
        # they both pass the earlier checks. Checking here isn't racey as we can
        # have only one `_persist_events` per room being called at a time.
        replaced_events = await self.main_store.get_already_persisted_events(
            (event for event, _ in events_and_contexts)
        )

        if replaced_events:
            events_and_contexts = [
                (e, ctx)
                for e, ctx in events_and_contexts
                if e.event_id not in replaced_events
            ]

            if not events_and_contexts:
                return replaced_events

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

            # Set of remote users which were in rooms the server has left. We
            # should check if we still share any rooms and if not we mark their
            # device lists as stale.
            potentially_left_users = set()  # type: Set[str]

            if not backfilled:
                with Measure(self._clock, "_calculate_state_and_extrem"):
                    # Work out the new "current state" for each room.
                    # We do this by working out what the new extremities are and then
                    # calculating the state from that.
                    events_by_room = (
                        {}
                    )  # type: Dict[str, List[Tuple[EventBase, EventContext]]]
                    for event, context in chunk:
                        events_by_room.setdefault(event.room_id, []).append(
                            (event, context)
                        )

                    for room_id, ev_ctx_rm in events_by_room.items():
                        latest_event_ids = await self.main_store.get_latest_event_ids_in_room(
                            room_id
                        )
                        new_latest_event_ids = await self._calculate_new_extremities(
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

                        logger.debug("Calculating state delta for room %s", room_id)
                        with Measure(
                            self._clock, "persist_events.get_new_state_after_events"
                        ):
                            res = await self._get_new_state_after_events(
                                room_id,
                                ev_ctx_rm,
                                latest_event_ids,
                                new_latest_event_ids,
                            )
                            current_state, delta_ids, new_latest_event_ids = res

                            # there should always be at least one forward extremity.
                            # (except during the initial persistence of the send_join
                            # results, in which case there will be no existing
                            # extremities, so we'll `continue` above and skip this bit.)
                            assert new_latest_event_ids, "No forward extremities left!"

                            new_forward_extremeties[room_id] = new_latest_event_ids

                        # If either are not None then there has been a change,
                        # and we need to work out the delta (or use that
                        # given)
                        delta = None
                        if delta_ids is not None:
                            # If there is a delta we know that we've
                            # only added or replaced state, never
                            # removed keys entirely.
                            delta = DeltaState([], delta_ids)
                        elif current_state is not None:
                            with Measure(
                                self._clock, "persist_events.calculate_state_delta"
                            ):
                                delta = await self._calculate_state_delta(
                                    room_id, current_state
                                )

                        if delta:
                            # If we have a change of state then lets check
                            # whether we're actually still a member of the room,
                            # or if our last user left. If we're no longer in
                            # the room then we delete the current state and
                            # extremities.
                            is_still_joined = await self._is_server_still_joined(
                                room_id,
                                ev_ctx_rm,
                                delta,
                                current_state,
                                potentially_left_users,
                            )
                            if not is_still_joined:
                                logger.info("Server no longer in room %s", room_id)
                                latest_event_ids = []
                                current_state = {}
                                delta.no_longer_in_room = True

                            state_delta_for_room[room_id] = delta

                        # If we have the current_state then lets prefill
                        # the cache with it.
                        if current_state is not None:
                            current_state_for_room[room_id] = current_state

            await self.persist_events_store._persist_events_and_state_updates(
                chunk,
                current_state_for_room=current_state_for_room,
                state_delta_for_room=state_delta_for_room,
                new_forward_extremeties=new_forward_extremeties,
                backfilled=backfilled,
            )

            await self._handle_potentially_left_users(potentially_left_users)

        return replaced_events

    async def _calculate_new_extremities(
        self,
        room_id: str,
        event_contexts: List[Tuple[EventBase, EventContext]],
        latest_event_ids: Collection[str],
    ):
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

        latest_event_ids = set(latest_event_ids)

        # start with the existing forward extremities
        result = set(latest_event_ids)

        # add all the new events to the list
        result.update(event.event_id for event in new_events)

        # Now remove all events which are prev_events of any of the new events
        result.difference_update(
            e_id for event in new_events for e_id in event.prev_event_ids()
        )

        # Remove any events which are prev_events of any existing events.
        existing_prevs = await self.persist_events_store._get_events_which_are_prevs(
            result
        )  # type: Collection[str]
        result.difference_update(existing_prevs)

        # Finally handle the case where the new events have soft-failed prev
        # events. If they do we need to remove them and their prev events,
        # otherwise we end up with dangling extremities.
        existing_prevs = await self.persist_events_store._get_prevs_before_rejected(
            e_id for event in new_events for e_id in event.prev_event_ids()
        )
        result.difference_update(existing_prevs)

        # We only update metrics for events that change forward extremities
        # (e.g. we ignore backfill/outliers/etc)
        if result != latest_event_ids:
            forward_extremities_counter.observe(len(result))
            stale = latest_event_ids & result
            stale_forward_extremities_counter.observe(len(stale))

        return result

    async def _get_new_state_after_events(
        self,
        room_id: str,
        events_context: List[Tuple[EventBase, EventContext]],
        old_latest_event_ids: Set[str],
        new_latest_event_ids: Set[str],
    ) -> Tuple[Optional[StateMap[str]], Optional[StateMap[str]], Set[str]]:
        """Calculate the current state dict after adding some new events to
        a room

        Args:
            room_id:
                room to which the events are being added. Used for logging etc

            events_context:
                events and contexts which are being added to the room

            old_latest_event_ids:
                the old forward extremities for the room.

            new_latest_event_ids :
                the new forward extremities for the room.

        Returns:
            Returns a tuple of two state maps and a set of new forward
            extremities.

            The first state map is the full new current state and the second
            is the delta to the existing current state. If both are None then
            there has been no change.

            The function may prune some old entries from the set of new
            forward extremities if it's safe to do so.

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
            event_to_groups = await self.main_store._get_state_group_for_events(
                missing_event_ids
            )
            event_id_to_state_group.update(event_to_groups)

        # State groups of old_latest_event_ids
        old_state_groups = {
            event_id_to_state_group[evid] for evid in old_latest_event_ids
        }

        # State groups of new_latest_event_ids
        new_state_groups = {
            event_id_to_state_group[evid] for evid in new_latest_event_ids
        }

        # If they old and new groups are the same then we don't need to do
        # anything.
        if old_state_groups == new_state_groups:
            return None, None, new_latest_event_ids

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
                return new_state, delta_ids, new_latest_event_ids

        # Now that we have calculated new_state_groups we need to get
        # their state IDs so we can resolve to a single state set.
        missing_state = new_state_groups - set(state_groups_map)
        if missing_state:
            group_to_state = await self.state_store._get_state_for_groups(missing_state)
            state_groups_map.update(group_to_state)

        if len(new_state_groups) == 1:
            # If there is only one state group, then we know what the current
            # state is.
            return state_groups_map[new_state_groups.pop()], None, new_latest_event_ids

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
            room_version = await self.main_store.get_room_version_id(room_id)

        logger.debug("calling resolve_state_groups from preserve_events")

        # Avoid a circular import.
        from synapse.state import StateResolutionStore

        res = await self._state_resolution_handler.resolve_state_groups(
            room_id,
            room_version,
            state_groups,
            events_map,
            state_res_store=StateResolutionStore(self.main_store),
        )

        state_resolutions_during_persistence.inc()

        # If the returned state matches the state group of one of the new
        # forward extremities then we check if we are able to prune some state
        # extremities.
        if res.state_group and res.state_group in new_state_groups:
            new_latest_event_ids = await self._prune_extremities(
                room_id,
                new_latest_event_ids,
                res.state_group,
                event_id_to_state_group,
                events_context,
            )

        return res.state, None, new_latest_event_ids

    async def _prune_extremities(
        self,
        room_id: str,
        new_latest_event_ids: Set[str],
        resolved_state_group: int,
        event_id_to_state_group: Dict[str, int],
        events_context: List[Tuple[EventBase, EventContext]],
    ) -> Set[str]:
        """See if we can prune any of the extremities after calculating the
        resolved state.
        """
        potential_times_prune_extremities.inc()

        # We keep all the extremities that have the same state group, and
        # see if we can drop the others.
        new_new_extrems = {
            e
            for e in new_latest_event_ids
            if event_id_to_state_group[e] == resolved_state_group
        }

        dropped_extrems = set(new_latest_event_ids) - new_new_extrems

        logger.debug("Might drop extremities: %s", dropped_extrems)

        # We only drop events from the extremities list if:
        #   1. we're not currently persisting them;
        #   2. they're not our own events (or are dummy events); and
        #   3. they're either:
        #       1. over N hours old and more than N events ago (we use depth to
        #          calculate); or
        #       2. we are persisting an event from the same domain and more than
        #          M events ago.
        #
        # The idea is that we don't want to drop events that are "legitimate"
        # extremities (that we would want to include as prev events), only
        # "stuck" extremities that are e.g. due to a gap in the graph.
        #
        # Note that we either drop all of them or none of them. If we only drop
        # some of the events we don't know if state res would come to the same
        # conclusion.

        for ev, _ in events_context:
            if ev.event_id in dropped_extrems:
                logger.debug(
                    "Not dropping extremities: %s is being persisted", ev.event_id
                )
                return new_latest_event_ids

        dropped_events = await self.main_store.get_events(
            dropped_extrems,
            allow_rejected=True,
            redact_behaviour=EventRedactBehaviour.AS_IS,
        )

        new_senders = {get_domain_from_id(e.sender) for e, _ in events_context}

        one_day_ago = self._clock.time_msec() - 24 * 60 * 60 * 1000
        current_depth = max(e.depth for e, _ in events_context)
        for event in dropped_events.values():
            # If the event is a local dummy event then we should check it
            # doesn't reference any local events, as we want to reference those
            # if we send any new events.
            #
            # Note we do this recursively to handle the case where a dummy event
            # references a dummy event that only references remote events.
            #
            # Ideally we'd figure out a way of still being able to drop old
            # dummy events that reference local events, but this is good enough
            # as a first cut.
            events_to_check = [event]
            while events_to_check:
                new_events = set()
                for event_to_check in events_to_check:
                    if self.is_mine_id(event_to_check.sender):
                        if event_to_check.type != EventTypes.Dummy:
                            logger.debug("Not dropping own event")
                            return new_latest_event_ids
                        new_events.update(event_to_check.prev_event_ids())

                prev_events = await self.main_store.get_events(
                    new_events,
                    allow_rejected=True,
                    redact_behaviour=EventRedactBehaviour.AS_IS,
                )
                events_to_check = prev_events.values()

            if (
                event.origin_server_ts < one_day_ago
                and event.depth < current_depth - 100
            ):
                continue

            # We can be less conservative about dropping extremities from the
            # same domain, though we do want to wait a little bit (otherwise
            # we'll immediately remove all extremities from a given server).
            if (
                get_domain_from_id(event.sender) in new_senders
                and event.depth < current_depth - 20
            ):
                continue

            logger.debug(
                "Not dropping as too new and not in new_senders: %s", new_senders,
            )

            return new_latest_event_ids

        times_pruned_extremities.inc()

        logger.info(
            "Pruning forward extremities in room %s: from %s -> %s",
            room_id,
            new_latest_event_ids,
            new_new_extrems,
        )
        return new_new_extrems

    async def _calculate_state_delta(
        self, room_id: str, current_state: StateMap[str]
    ) -> DeltaState:
        """Calculate the new state deltas for a room.

        Assumes that we are only persisting events for one room at a time.
        """
        existing_state = await self.main_store.get_current_state_ids(room_id)

        to_delete = [key for key in existing_state if key not in current_state]

        to_insert = {
            key: ev_id
            for key, ev_id in current_state.items()
            if ev_id != existing_state.get(key)
        }

        return DeltaState(to_delete=to_delete, to_insert=to_insert)

    async def _is_server_still_joined(
        self,
        room_id: str,
        ev_ctx_rm: List[Tuple[EventBase, EventContext]],
        delta: DeltaState,
        current_state: Optional[StateMap[str]],
        potentially_left_users: Set[str],
    ) -> bool:
        """Check if the server will still be joined after the given events have
        been persised.

        Args:
            room_id
            ev_ctx_rm
            delta: The delta of current state between what is in the database
                and what the new current state will be.
            current_state: The new current state if it already been calculated,
                otherwise None.
            potentially_left_users: If the server has left the room, then joined
                remote users will be added to this set to indicate that the
                server may no longer be sharing a room with them.
        """

        if not any(
            self.is_mine_id(state_key)
            for typ, state_key in itertools.chain(delta.to_delete, delta.to_insert)
            if typ == EventTypes.Member
        ):
            # There have been no changes to membership of our users, so nothing
            # has changed and we assume we're still in the room.
            return True

        # Check if any of the given events are a local join that appear in the
        # current state
        events_to_check = []  # Event IDs that aren't an event we're persisting
        for (typ, state_key), event_id in delta.to_insert.items():
            if typ != EventTypes.Member or not self.is_mine_id(state_key):
                continue

            for event, _ in ev_ctx_rm:
                if event_id == event.event_id:
                    if event.membership == Membership.JOIN:
                        return True

            # The event is not in `ev_ctx_rm`, so we need to pull it out of
            # the DB.
            events_to_check.append(event_id)

        # Check if any of the changes that we don't have events for are joins.
        if events_to_check:
            rows = await self.main_store.get_membership_from_event_ids(events_to_check)
            is_still_joined = any(row["membership"] == Membership.JOIN for row in rows)
            if is_still_joined:
                return True

        # None of the new state events are local joins, so we check the database
        # to see if there are any other local users in the room. We ignore users
        # whose state has changed as we've already their new state above.
        users_to_ignore = [
            state_key
            for typ, state_key in itertools.chain(delta.to_insert, delta.to_delete)
            if typ == EventTypes.Member and self.is_mine_id(state_key)
        ]

        if await self.main_store.is_local_host_in_room_ignoring_users(
            room_id, users_to_ignore
        ):
            return True

        # The server will leave the room, so we go and find out which remote
        # users will still be joined when we leave.
        if current_state is None:
            current_state = await self.main_store.get_current_state_ids(room_id)
            current_state = dict(current_state)
            for key in delta.to_delete:
                current_state.pop(key, None)

            current_state.update(delta.to_insert)

        remote_event_ids = [
            event_id
            for (typ, state_key,), event_id in current_state.items()
            if typ == EventTypes.Member and not self.is_mine_id(state_key)
        ]
        rows = await self.main_store.get_membership_from_event_ids(remote_event_ids)
        potentially_left_users.update(
            row["user_id"] for row in rows if row["membership"] == Membership.JOIN
        )

        return False

    async def _handle_potentially_left_users(self, user_ids: Set[str]):
        """Given a set of remote users check if the server still shares a room with
        them. If not then mark those users' device cache as stale.
        """

        if not user_ids:
            return

        joined_users = await self.main_store.get_users_server_still_shares_room_with(
            user_ids
        )
        left_users = user_ids - joined_users

        for user_id in left_users:
            await self.main_store.mark_remote_user_device_list_as_unsubscribed(user_id)
