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

from synapse.events import EventBase
from synapse.events.snapshot import EventContext
from synapse.handlers._base import BaseHandler
from synapse.types import StateMap

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

        self.storage = hs.get_storage()
        self.state_store = self.storage.state

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
