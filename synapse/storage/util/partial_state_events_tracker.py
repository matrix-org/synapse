# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from collections import defaultdict
from typing import Collection, Dict, Set

from twisted.internet import defer
from twisted.internet.defer import Deferred

from synapse.logging.context import PreserveLoggingContext, make_deferred_yieldable
from synapse.logging.opentracing import trace_with_opname
from synapse.storage.databases.main.events_worker import EventsWorkerStore
from synapse.storage.databases.main.room import RoomWorkerStore
from synapse.util import unwrapFirstError
from synapse.util.cancellation import cancellable

logger = logging.getLogger(__name__)


class PartialStateEventsTracker:
    """Keeps track of which events have partial state, after a partial-state join"""

    def __init__(self, store: EventsWorkerStore):
        self._store = store
        # a map from event id to a set of Deferreds which are waiting for that event to be
        # un-partial-stated.
        self._observers: Dict[str, Set[Deferred[None]]] = defaultdict(set)

    def notify_un_partial_stated(self, event_id: str) -> None:
        """Notify that we now have full state for a given event

        Called by the state-resynchronization loop whenever we resynchronize the state
        for a particular event. Unblocks any callers to await_full_state() for that
        event.

        Args:
            event_id: the event that now has full state.
        """
        observers = self._observers.pop(event_id, None)
        if not observers:
            return
        logger.info(
            "Notifying %i things waiting for un-partial-stating of event %s",
            len(observers),
            event_id,
        )
        with PreserveLoggingContext():
            for o in observers:
                o.callback(None)

    @trace_with_opname("PartialStateEventsTracker.await_full_state")
    @cancellable
    async def await_full_state(self, event_ids: Collection[str]) -> None:
        """Wait for all the given events to have full state.

        Args:
            event_ids: the list of event ids that we want full state for
        """
        # first try the happy path: if there are no partial-state events, we can return
        # quickly
        partial_state_event_ids = [
            ev
            for ev, p in (await self._store.get_partial_state_events(event_ids)).items()
            if p
        ]

        if not partial_state_event_ids:
            return

        logger.info(
            "Awaiting un-partial-stating of events %s",
            partial_state_event_ids,
            stack_info=True,
        )

        # create an observer for each lazy-joined event
        observers: Dict[str, Deferred[None]] = {
            event_id: Deferred() for event_id in partial_state_event_ids
        }
        for event_id, observer in observers.items():
            self._observers[event_id].add(observer)

        try:
            # some of them may have been un-lazy-joined between us checking the db and
            # registering the observer, in which case we'd wait forever for the
            # notification. Call back the observers now.
            for event_id, partial in (
                await self._store.get_partial_state_events(observers.keys())
            ).items():
                # there may have been a call to notify_un_partial_stated during the
                # db query, so the observers may already have been called.
                if not partial and not observers[event_id].called:
                    observers[event_id].callback(None)

            await make_deferred_yieldable(
                defer.gatherResults(
                    observers.values(),
                    consumeErrors=True,
                )
            ).addErrback(unwrapFirstError)
            logger.info("Events %s all un-partial-stated", observers.keys())
        finally:
            # remove any observers we created. This should happen when the notification
            # is received, but that might not happen for two reasons:
            #   (a) we're bailing out early on an exception (including us being
            #       cancelled during the await)
            #   (b) the event got de-lazy-joined before we set up the observer.
            for event_id, observer in observers.items():
                observer_set = self._observers.get(event_id)
                if observer_set:
                    observer_set.discard(observer)
                    if not observer_set:
                        del self._observers[event_id]


class PartialCurrentStateTracker:
    """Keeps track of which rooms have partial state, after partial-state joins"""

    def __init__(self, store: RoomWorkerStore):
        self._store = store

        # a map from room id to a set of Deferreds which are waiting for that room to be
        # un-partial-stated.
        self._observers: Dict[str, Set[Deferred[None]]] = defaultdict(set)

    def notify_un_partial_stated(self, room_id: str) -> None:
        """Notify that we now have full current state for a given room

        Unblocks any callers to await_full_state() for that room.

        Args:
            room_id: the room that now has full current state.
        """
        observers = self._observers.pop(room_id, None)
        if not observers:
            return
        logger.info(
            "Notifying %i things waiting for un-partial-stating of room %s",
            len(observers),
            room_id,
        )
        with PreserveLoggingContext():
            for o in observers:
                o.callback(None)

    @trace_with_opname("PartialCurrentStateTracker.await_full_state")
    @cancellable
    async def await_full_state(self, room_id: str) -> None:
        # We add the deferred immediately so that the DB call to check for
        # partial state doesn't race when we unpartial the room.
        d: Deferred[None] = Deferred()
        self._observers.setdefault(room_id, set()).add(d)

        try:
            # Check if the room has partial current state or not.
            has_partial_state = await self._store.is_partial_state_room(room_id)
            if not has_partial_state:
                return

            logger.info(
                "Awaiting un-partial-stating of room %s",
                room_id,
                stack_info=True,
            )

            await make_deferred_yieldable(d)

            logger.info("Room has un-partial-stated")
        finally:
            # Remove the added observer, and remove the room entry if its empty.
            ds = self._observers.get(room_id)
            if ds is not None:
                ds.discard(d)
                if not ds:
                    self._observers.pop(room_id, None)
