# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Iterable, List, Optional, Tuple

from prometheus_client import Counter

from synapse import event_auth
from synapse.api.constants import EventTypes, RejectedReason
from synapse.api.errors import AuthError, RequestSendFailed
from synapse.api.room_versions import KNOWN_ROOM_VERSIONS
from synapse.event_auth import auth_types_for_event
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.handlers._base import BaseHandler
from synapse.types import MutableStateMap, StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)

soft_failed_event_counter = Counter(
    "synapse_federation_soft_failed_events_total",
    "Events received over federation that we marked as soft_failed",
)


class FederationEventHandler(BaseHandler):
    """Handles events that originated from federation.

    Responsible for handing incoming events and passing them on to the rest
    of the homeserver (including auth and state conflict resolutions)
    """

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.store = hs.get_datastore()
        self.storage = hs.get_storage()
        self.state_store = self.storage.state

        self.state_handler = hs.get_state_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self._event_auth_handler = hs.get_event_auth_handler()

        self.federation_client = hs.get_federation_client()

        # TODO: remove once we don't need to call back to the FederationHandler
        self._hs = hs

    async def _check_event_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        state: Optional[Iterable[EventBase]] = None,
        claimed_auth_event_map: Optional[StateMap[EventBase]] = None,
        backfilled: bool = False,
    ) -> EventContext:
        """
        Checks whether an event should be rejected (for failing auth checks).

        Args:
            origin: The host the event originates from.
            event: The event itself.
            context:
                The event context.

            state:
                The state events used to check the event for soft-fail. If this is
                not provided the current state events will be used.

            claimed_auth_event_map:
                A map of (type, state_key) => event for the event's claimed auth_events.
                Possibly incomplete, and possibly including events that are not yet
                persisted, or authed, or in the right room.

                Only populated where we may not already have persisted these events -
                for example, when populating outliers, or the state for a backwards
                extremity.

            backfilled: True if the event was backfilled.

        Returns:
            The updated context object.
        """
        room_version = await self.store.get_room_version_id(event.room_id)
        room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

        if claimed_auth_event_map:
            # if we have a copy of the auth events from the event, use that as the
            # basis for auth.
            auth_events = claimed_auth_event_map
        else:
            # otherwise, we calculate what the auth events *should* be, and use that
            prev_state_ids = await context.get_prev_state_ids()
            auth_events_ids = self._event_auth_handler.compute_auth_events(
                event, prev_state_ids, for_verification=True
            )
            auth_events_x = await self.store.get_events(auth_events_ids)
            auth_events = {(e.type, e.state_key): e for e in auth_events_x.values()}

        try:
            (
                context,
                auth_events_for_auth,
            ) = await self._update_auth_events_and_context_for_auth(
                origin, event, context, auth_events
            )
        except Exception:
            # We don't really mind if the above fails, so lets not fail
            # processing if it does. However, it really shouldn't fail so
            # let's still log as an exception since we'll still want to fix
            # any bugs.
            logger.exception(
                "Failed to double check auth events for %s with remote. "
                "Ignoring failure and continuing processing of event.",
                event.event_id,
            )
            auth_events_for_auth = auth_events

        try:
            event_auth.check(room_version_obj, event, auth_events=auth_events_for_auth)
        except AuthError as e:
            logger.warning("Failed auth resolution for %r because %s", event, e)
            context.rejected = RejectedReason.AUTH_ERROR

        if not context.rejected:
            await self._check_for_soft_fail(event, state, backfilled, origin=origin)

        if event.type == EventTypes.GuestAccess and not context.rejected:
            await self.maybe_kick_guest_users(event)

        # If we are going to send this event over federation we precaclculate
        # the joined hosts.
        if event.internal_metadata.get_send_on_behalf_of():
            await self.event_creation_handler.cache_joined_hosts_for_event(
                event, context
            )

        return context

    async def _check_for_soft_fail(
        self,
        event: EventBase,
        state: Optional[Iterable[EventBase]],
        backfilled: bool,
        origin: str,
    ) -> None:
        """Checks if we should soft fail the event; if so, marks the event as
        such.

        Args:
            event
            state: The state at the event if we don't have all the event's prev events
            backfilled: Whether the event is from backfill
            origin: The host the event originates from.
        """
        # For new (non-backfilled and non-outlier) events we check if the event
        # passes auth based on the current state. If it doesn't then we
        # "soft-fail" the event.
        if backfilled or event.internal_metadata.is_outlier():
            return

        extrem_ids_list = await self.store.get_latest_event_ids_in_room(event.room_id)
        extrem_ids = set(extrem_ids_list)
        prev_event_ids = set(event.prev_event_ids())

        if extrem_ids == prev_event_ids:
            # If they're the same then the current state is the same as the
            # state at the event, so no point rechecking auth for soft fail.
            return

        room_version = await self.store.get_room_version_id(event.room_id)
        room_version_obj = KNOWN_ROOM_VERSIONS[room_version]

        # Calculate the "current state".
        if state is not None:
            # If we're explicitly given the state then we won't have all the
            # prev events, and so we have a gap in the graph. In this case
            # we want to be a little careful as we might have been down for
            # a while and have an incorrect view of the current state,
            # however we still want to do checks as gaps are easy to
            # maliciously manufacture.
            #
            # So we use a "current state" that is actually a state
            # resolution across the current forward extremities and the
            # given state at the event. This should correctly handle cases
            # like bans, especially with state res v2.

            state_sets_d = await self.state_store.get_state_groups(
                event.room_id, extrem_ids
            )
            state_sets: List[Iterable[EventBase]] = list(state_sets_d.values())
            state_sets.append(state)
            current_states = await self.state_handler.resolve_events(
                room_version, state_sets, event
            )
            current_state_ids: StateMap[str] = {
                k: e.event_id for k, e in current_states.items()
            }
        else:
            current_state_ids = await self.state_handler.get_current_state_ids(
                event.room_id, latest_event_ids=extrem_ids
            )

        logger.debug(
            "Doing soft-fail check for %s: state %s",
            event.event_id,
            current_state_ids,
        )

        # Now check if event pass auth against said current state
        auth_types = auth_types_for_event(room_version_obj, event)
        current_state_ids_list = [
            e for k, e in current_state_ids.items() if k in auth_types
        ]

        auth_events_map = await self.store.get_events(current_state_ids_list)
        current_auth_events = {
            (e.type, e.state_key): e for e in auth_events_map.values()
        }

        try:
            event_auth.check(room_version_obj, event, auth_events=current_auth_events)
        except AuthError as e:
            logger.warning(
                "Soft-failing %r (from %s) because %s",
                event,
                e,
                origin,
                extra={
                    "room_id": event.room_id,
                    "mxid": event.sender,
                    "hs": origin,
                },
            )
            soft_failed_event_counter.inc()
            event.internal_metadata.soft_failed = True

    async def _update_auth_events_and_context_for_auth(
        self,
        origin: str,
        event: EventBase,
        context: EventContext,
        input_auth_events: StateMap[EventBase],
    ) -> Tuple[EventContext, StateMap[EventBase]]:
        """Helper for _check_event_auth. See there for docs.

        Checks whether a given event has the expected auth events. If it
        doesn't then we talk to the remote server to compare state to see if
        we can come to a consensus (e.g. if one server missed some valid
        state).

        This attempts to resolve any potential divergence of state between
        servers, but is not essential and so failures should not block further
        processing of the event.

        Args:
            origin:
            event:
            context:

            input_auth_events:
                Map from (event_type, state_key) to event

                Normally, our calculated auth_events based on the state of the room
                at the event's position in the DAG, though occasionally (eg if the
                event is an outlier), may be the auth events claimed by the remote
                server.

        Returns:
            updated context, updated auth event map
        """
        # take a copy of input_auth_events before we modify it.
        auth_events: MutableStateMap[EventBase] = dict(input_auth_events)

        event_auth_events = set(event.auth_event_ids())

        # missing_auth is the set of the event's auth_events which we don't yet have
        # in auth_events.
        missing_auth = event_auth_events.difference(
            e.event_id for e in auth_events.values()
        )

        # if we have missing events, we need to fetch those events from somewhere.
        #
        # we start by checking if they are in the store, and then try calling /event_auth/.
        if missing_auth:
            have_events = await self.store.have_seen_events(event.room_id, missing_auth)
            logger.debug("Events %s are in the store", have_events)
            missing_auth.difference_update(have_events)

        if missing_auth:
            # If we don't have all the auth events, we need to get them.
            logger.info("auth_events contains unknown events: %s", missing_auth)
            try:
                try:
                    remote_auth_chain = await self.federation_client.get_event_auth(
                        origin, event.room_id, event.event_id
                    )
                except RequestSendFailed as e1:
                    # The other side isn't around or doesn't implement the
                    # endpoint, so lets just bail out.
                    logger.info("Failed to get event auth from remote: %s", e1)
                    return context, auth_events

                seen_remotes = await self.store.have_seen_events(
                    event.room_id, [e.event_id for e in remote_auth_chain]
                )

                for e in remote_auth_chain:
                    if e.event_id in seen_remotes:
                        continue

                    if e.event_id == event.event_id:
                        continue

                    try:
                        auth_ids = e.auth_event_ids()
                        auth = {
                            (e.type, e.state_key): e
                            for e in remote_auth_chain
                            if e.event_id in auth_ids or e.type == EventTypes.Create
                        }
                        e.internal_metadata.outlier = True

                        logger.debug(
                            "_check_event_auth %s missing_auth: %s",
                            event.event_id,
                            e.event_id,
                        )
                        missing_auth_event_context = (
                            await self.state_handler.compute_event_context(e)
                        )
                        await self._hs.get_federation_handler()._auth_and_persist_event(
                            origin,
                            e,
                            missing_auth_event_context,
                            claimed_auth_event_map=auth,
                        )

                        if e.event_id in event_auth_events:
                            auth_events[(e.type, e.state_key)] = e
                    except AuthError:
                        pass

            except Exception:
                logger.exception("Failed to get auth chain")

        if event.internal_metadata.is_outlier():
            # XXX: given that, for an outlier, we'll be working with the
            # event's *claimed* auth events rather than those we calculated:
            # (a) is there any point in this test, since different_auth below will
            # obviously be empty
            # (b) alternatively, why don't we do it earlier?
            logger.info("Skipping auth_event fetch for outlier")
            return context, auth_events

        different_auth = event_auth_events.difference(
            e.event_id for e in auth_events.values()
        )

        if not different_auth:
            return context, auth_events

        logger.info(
            "auth_events refers to events which are not in our calculated auth "
            "chain: %s",
            different_auth,
        )

        # XXX: currently this checks for redactions but I'm not convinced that is
        # necessary?
        different_events = await self.store.get_events_as_list(different_auth)

        for d in different_events:
            if d.room_id != event.room_id:
                logger.warning(
                    "Event %s refers to auth_event %s which is in a different room",
                    event.event_id,
                    d.event_id,
                )

                # don't attempt to resolve the claimed auth events against our own
                # in this case: just use our own auth events.
                #
                # XXX: should we reject the event in this case? It feels like we should,
                # but then shouldn't we also do so if we've failed to fetch any of the
                # auth events?
                return context, auth_events

        # now we state-resolve between our own idea of the auth events, and the remote's
        # idea of them.

        local_state = auth_events.values()
        remote_auth_events = dict(auth_events)
        remote_auth_events.update({(d.type, d.state_key): d for d in different_events})
        remote_state = remote_auth_events.values()

        room_version = await self.store.get_room_version_id(event.room_id)
        new_state = await self.state_handler.resolve_events(
            room_version, (local_state, remote_state), event
        )

        logger.info(
            "After state res: updating auth_events with new state %s",
            {
                (d.type, d.state_key): d.event_id
                for d in new_state.values()
                if auth_events.get((d.type, d.state_key)) != d
            },
        )

        auth_events.update(new_state)

        context = await self._update_context_for_auth_events(
            event, context, auth_events
        )

        return context, auth_events

    async def _update_context_for_auth_events(
        self, event: EventBase, context: EventContext, auth_events: StateMap[EventBase]
    ) -> EventContext:
        """Update the state_ids in an event context after auth event resolution,
        storing the changes as a new state group.

        Args:
            event: The event we're handling the context for

            context: initial event context

            auth_events: Events to update in the event context.

        Returns:
            new event context
        """
        # exclude the state key of the new event from the current_state in the context.
        if event.is_state():
            event_key: Optional[Tuple[str, str]] = (event.type, event.state_key)
        else:
            event_key = None
        state_updates = {
            k: a.event_id for k, a in auth_events.items() if k != event_key
        }

        current_state_ids = await context.get_current_state_ids()
        current_state_ids = dict(current_state_ids)  # type: ignore

        current_state_ids.update(state_updates)

        prev_state_ids = await context.get_prev_state_ids()
        prev_state_ids = dict(prev_state_ids)

        prev_state_ids.update({k: a.event_id for k, a in auth_events.items()})

        # create a new state group as a delta from the existing one.
        prev_group = context.state_group
        state_group = await self.state_store.store_state_group(
            event.event_id,
            event.room_id,
            prev_group=prev_group,
            delta_ids=state_updates,
            current_state_ids=current_state_ids,
        )

        return EventContext.with_state(
            state_group=state_group,
            state_group_before_event=context.state_group_before_event,
            current_state_ids=current_state_ids,
            prev_state_ids=prev_state_ids,
            prev_group=prev_group,
            delta_ids=state_updates,
        )
