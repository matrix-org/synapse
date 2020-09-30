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

import logging
import random
from typing import TYPE_CHECKING, Iterable, List, Optional

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import AuthError, SynapseError
from synapse.events import EventBase
from synapse.handlers.presence import format_user_presence_state
from synapse.logging.utils import log_function
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, UserID
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class EventStreamHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.clock = hs.get_clock()

        self.notifier = hs.get_notifier()
        self.state = hs.get_state_handler()
        self._server_notices_sender = hs.get_server_notices_sender()
        self._event_serializer = hs.get_event_client_serializer()

    @log_function
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
        """Fetches the events stream for a given user.
        """

        if room_id:
            blocked = await self.store.is_room_blocked(room_id)
            if blocked:
                raise SynapseError(403, "This room has been blocked on this server")

        # send any outstanding server notices to the user.
        await self._server_notices_sender.on_user_syncing(auth_user_id)

        auth_user = UserID.from_string(auth_user_id)
        presence_handler = self.hs.get_presence_handler()

        context = await presence_handler.user_syncing(
            auth_user_id, affect_presence=affect_presence
        )
        with context:
            if timeout:
                # If they've set a timeout set a minimum limit.
                timeout = max(timeout, 500)

                # Add some randomness to this value to try and mitigate against
                # thundering herds on restart.
                timeout = random.randint(int(timeout * 0.9), int(timeout * 1.1))

            events, tokens = await self.notifier.get_events_for(
                auth_user,
                pagin_config,
                timeout,
                is_guest=is_guest,
                explicit_room_id=room_id,
            )

            time_now = self.clock.time_msec()

            # When the user joins a new room, or another user joins a currently
            # joined room, we need to send down presence for those users.
            to_add = []  # type: List[JsonDict]
            for event in events:
                if not isinstance(event, EventBase):
                    continue
                if event.type == EventTypes.Member:
                    if event.membership != Membership.JOIN:
                        continue
                    # Send down presence.
                    if event.state_key == auth_user_id:
                        # Send down presence for everyone in the room.
                        users = await self.state.get_current_users_in_room(
                            event.room_id
                        )  # type: Iterable[str]
                    else:
                        users = [event.state_key]

                    states = await presence_handler.get_states(users)
                    to_add.extend(
                        {
                            "type": EventTypes.Presence,
                            "content": format_user_presence_state(state, time_now),
                        }
                        for state in states
                    )

            events.extend(to_add)

            chunks = await self._event_serializer.serialize_events(
                events,
                time_now,
                as_client_event=as_client_event,
                # We don't bundle "live" events, as otherwise clients
                # will end up double counting annotations.
                bundle_aggregations=False,
            )

            chunk = {
                "chunk": chunks,
                "start": await tokens[0].to_string(self.store),
                "end": await tokens[1].to_string(self.store),
            }

            return chunk


class EventHandler(BaseHandler):
    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.storage = hs.get_storage()

    async def get_event(
        self, user: UserID, room_id: Optional[str], event_id: str
    ) -> Optional[EventBase]:
        """Retrieve a single specified event.

        Args:
            user: The user requesting the event
            room_id: The expected room id. We'll return None if the
                event's room does not match.
            event_id: The event ID to obtain.
        Returns:
            An event, or None if there is no event matching this ID.
        Raises:
            SynapseError if there was a problem retrieving this event, or
            AuthError if the user does not have the rights to inspect this
            event.
        """
        event = await self.store.get_event(event_id, check_room_id=room_id)

        if not event:
            return None

        users = await self.store.get_users_in_room(event.room_id)
        is_peeking = user.to_string() not in users

        filtered = await filter_events_for_client(
            self.storage, user.to_string(), [event], is_peeking=is_peeking
        )

        if not filtered:
            raise AuthError(403, "You don't have permission to access that event.")

        return event
