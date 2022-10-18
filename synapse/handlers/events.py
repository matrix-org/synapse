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

import logging
import random
from typing import TYPE_CHECKING, Iterable, List, Optional

from synapse.api.constants import EduTypes, EventTypes, Membership, PresenceState
from synapse.api.errors import AuthError, SynapseError
from synapse.events import EventBase
from synapse.events.utils import SerializeEventConfig
from synapse.handlers.presence import format_user_presence_state
from synapse.storage.databases.main.events_worker import EventRedactBehaviour
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, UserID
from synapse.visibility import filter_events_for_client

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class EventStreamHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.hs = hs

        self.notifier = hs.get_notifier()
        self.state = hs.get_state_handler()
        self._server_notices_sender = hs.get_server_notices_sender()
        self._event_serializer = hs.get_event_client_serializer()

    async def get_stream(
        self,
        auth_user_id: str,
        pagin_config: PaginationConfig,
        timeout: int = 0,
        as_client_event: bool = True,
        affect_presence: bool = True,
        room_id: Optional[str] = None,
        is_guest: bool = False,
    ) -> JsonDict:
        """Fetches the events stream for a given user."""

        if room_id:
            blocked = await self.store.is_room_blocked(room_id)
            if blocked:
                raise SynapseError(403, "This room has been blocked on this server")

        # send any outstanding server notices to the user.
        await self._server_notices_sender.on_user_syncing(auth_user_id)

        auth_user = UserID.from_string(auth_user_id)
        presence_handler = self.hs.get_presence_handler()

        context = await presence_handler.user_syncing(
            auth_user_id,
            affect_presence=affect_presence,
            presence_state=PresenceState.ONLINE,
        )
        with context:
            if timeout:
                # If they've set a timeout set a minimum limit.
                timeout = max(timeout, 500)

                # Add some randomness to this value to try and mitigate against
                # thundering herds on restart.
                timeout = random.randint(int(timeout * 0.9), int(timeout * 1.1))

            stream_result = await self.notifier.get_events_for(
                auth_user,
                pagin_config,
                timeout,
                is_guest=is_guest,
                explicit_room_id=room_id,
            )
            events = stream_result.events

            time_now = self.clock.time_msec()

            # When the user joins a new room, or another user joins a currently
            # joined room, we need to send down presence for those users.
            to_add: List[JsonDict] = []
            for event in events:
                if not isinstance(event, EventBase):
                    continue
                if event.type == EventTypes.Member:
                    if event.membership != Membership.JOIN:
                        continue
                    # Send down presence.
                    if event.state_key == auth_user_id:
                        # Send down presence for everyone in the room.
                        users: Iterable[str] = await self.store.get_users_in_room(
                            event.room_id
                        )
                    else:
                        users = [event.state_key]

                    states = await presence_handler.get_states(users)
                    to_add.extend(
                        {
                            "type": EduTypes.PRESENCE,
                            "content": format_user_presence_state(state, time_now),
                        }
                        for state in states
                    )

            events.extend(to_add)

            chunks = self._event_serializer.serialize_events(
                events,
                time_now,
                config=SerializeEventConfig(as_client_event=as_client_event),
            )

            chunk = {
                "chunk": chunks,
                "start": await stream_result.start_token.to_string(self.store),
                "end": await stream_result.end_token.to_string(self.store),
            }

            return chunk


class EventHandler:
    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()

    async def get_event(
        self,
        user: UserID,
        room_id: Optional[str],
        event_id: str,
        show_redacted: bool = False,
    ) -> Optional[EventBase]:
        """Retrieve a single specified event.

        Args:
            user: The local user requesting the event
            room_id: The expected room id. We'll return None if the
                event's room does not match.
            event_id: The event ID to obtain.
            show_redacted: Should the full content of redacted events be returned?
        Returns:
            An event, or None if there is no event matching this ID.
        Raises:
            SynapseError if there was a problem retrieving this event, or
            AuthError if the user does not have the rights to inspect this
            event.
        """
        redact_behaviour = (
            EventRedactBehaviour.as_is if show_redacted else EventRedactBehaviour.redact
        )
        event = await self.store.get_event(
            event_id, check_room_id=room_id, redact_behaviour=redact_behaviour
        )

        if not event:
            return None

        is_user_in_room = await self.store.check_local_user_in_room(
            user_id=user.to_string(), room_id=event.room_id
        )
        # The user is peeking if they aren't in the room already
        is_peeking = not is_user_in_room

        filtered = await filter_events_for_client(
            self._storage_controllers, user.to_string(), [event], is_peeking=is_peeking
        )

        if not filtered:
            raise AuthError(403, "You don't have permission to access that event.")

        return event
