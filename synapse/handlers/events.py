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

from twisted.internet import defer

from synapse.util.logutils import log_function
from synapse.types import UserID
from synapse.events.utils import serialize_event
from synapse.api.constants import Membership, EventTypes
from synapse.events import EventBase

from ._base import BaseHandler

import logging
import random


logger = logging.getLogger(__name__)


class EventStreamHandler(BaseHandler):

    def __init__(self, hs):
        super(EventStreamHandler, self).__init__(hs)

        # Count of active streams per user
        self._streams_per_user = {}
        # Grace timers per user to delay the "stopped" signal
        self._stop_timer_per_user = {}

        self.distributor = hs.get_distributor()
        self.distributor.declare("started_user_eventstream")
        self.distributor.declare("stopped_user_eventstream")

        self.clock = hs.get_clock()

        self.notifier = hs.get_notifier()
        self.state = hs.get_state_handler()

    @defer.inlineCallbacks
    @log_function
    def get_stream(self, auth_user_id, pagin_config, timeout=0,
                   as_client_event=True, affect_presence=True,
                   only_keys=None, room_id=None, is_guest=False):
        """Fetches the events stream for a given user.

        If `only_keys` is not None, events from keys will be sent down.
        """
        auth_user = UserID.from_string(auth_user_id)
        presence_handler = self.hs.get_presence_handler()

        context = yield presence_handler.user_syncing(
            auth_user_id, affect_presence=affect_presence,
        )
        with context:
            if timeout:
                # If they've set a timeout set a minimum limit.
                timeout = max(timeout, 500)

                # Add some randomness to this value to try and mitigate against
                # thundering herds on restart.
                timeout = random.randint(int(timeout * 0.9), int(timeout * 1.1))

            events, tokens = yield self.notifier.get_events_for(
                auth_user, pagin_config, timeout,
                only_keys=only_keys,
                is_guest=is_guest, explicit_room_id=room_id
            )

            # When the user joins a new room, or another user joins a currently
            # joined room, we need to send down presence for those users.
            to_add = []
            for event in events:
                if not isinstance(event, EventBase):
                    continue
                if event.type == EventTypes.Member:
                    if event.membership != Membership.JOIN:
                        continue
                    # Send down presence.
                    if event.state_key == auth_user_id:
                        # Send down presence for everyone in the room.
                        users = yield self.state.get_current_user_in_room(event.room_id)
                        states = yield presence_handler.get_states(
                            users,
                            as_event=True,
                        )
                        to_add.extend(states)
                    else:

                        ev = yield presence_handler.get_state(
                            UserID.from_string(event.state_key),
                            as_event=True,
                        )
                        to_add.append(ev)

            events.extend(to_add)

            time_now = self.clock.time_msec()

            chunks = [
                serialize_event(e, time_now, as_client_event) for e in events
            ]

            chunk = {
                "chunk": chunks,
                "start": tokens[0].to_string(),
                "end": tokens[1].to_string(),
            }

            defer.returnValue(chunk)


class EventHandler(BaseHandler):

    @defer.inlineCallbacks
    def get_event(self, user, event_id):
        """Retrieve a single specified event.

        Args:
            user (synapse.types.UserID): The user requesting the event
            event_id (str): The event ID to obtain.
        Returns:
            dict: An event, or None if there is no event matching this ID.
        Raises:
            SynapseError if there was a problem retrieving this event, or
            AuthError if the user does not have the rights to inspect this
            event.
        """
        event = yield self.store.get_event(event_id)

        if not event:
            defer.returnValue(None)
            return

        if hasattr(event, "room_id"):
            yield self.auth.check_joined_room(event.room_id, user.to_string())

        defer.returnValue(event)
