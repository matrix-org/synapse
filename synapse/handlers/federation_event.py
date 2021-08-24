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
from typing import TYPE_CHECKING, Optional, Tuple

from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError, RequestSendFailed
from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.handlers._base import BaseHandler
from synapse.types import MutableStateMap, StateMap

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


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

        self.federation_client = hs.get_federation_client()

        # TODO: remove once we don't need to call back to the FederationHandler
        self._hs = hs

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
