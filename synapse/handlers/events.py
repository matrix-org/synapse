# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from ._base import BaseHandler

import logging
import random


logger = logging.getLogger(__name__)


def started_user_eventstream(distributor, user):
    return distributor.fire("started_user_eventstream", user)


def stopped_user_eventstream(distributor, user):
    return distributor.fire("stopped_user_eventstream", user)


def user_joined_room(distributor, user, room_id):
    return distributor.fire("user_joined_room", user, room_id)


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

    @defer.inlineCallbacks
    def started_stream(self, user):
        """Tells the presence handler that we have started an eventstream for
        the user:

        Args:
            user (User): The user who started a stream.
        Returns:
            A deferred that completes once their presence has been updated.
        """
        if user not in self._streams_per_user:
            # Make sure we set the streams per user to 1 here rather than
            # setting it to zero and incrementing the value below.
            # Otherwise this may race with stopped_stream causing the
            # user to be erased from the map before we have a chance
            # to increment it.
            self._streams_per_user[user] = 1
            if user in self._stop_timer_per_user:
                try:
                    self.clock.cancel_call_later(
                        self._stop_timer_per_user.pop(user)
                    )
                except:
                    logger.exception("Failed to cancel event timer")
            else:
                yield started_user_eventstream(self.distributor, user)
        else:
            self._streams_per_user[user] += 1

    def stopped_stream(self, user):
        """If there are no streams for a user this starts a timer that will
        notify the presence handler that we haven't got an event stream for
        the user unless the user starts a new stream in 30 seconds.

        Args:
            user (User): The user who stopped a stream.
        """
        self._streams_per_user[user] -= 1
        if not self._streams_per_user[user]:
            del self._streams_per_user[user]

            # 30 seconds of grace to allow the client to reconnect again
            #   before we think they're gone
            def _later():
                logger.debug("_later stopped_user_eventstream %s", user)

                self._stop_timer_per_user.pop(user, None)

                return stopped_user_eventstream(self.distributor, user)

            logger.debug("Scheduling _later: for %s", user)
            self._stop_timer_per_user[user] = (
                self.clock.call_later(30, _later)
            )

    @defer.inlineCallbacks
    @log_function
    def get_stream(self, auth_user_id, pagin_config, timeout=0,
                   as_client_event=True, affect_presence=True,
                   only_room_events=False, room_id=None, is_guest=False):
        """Fetches the events stream for a given user.

        If `only_room_events` is `True` only room events will be returned.
        """
        auth_user = UserID.from_string(auth_user_id)

        try:
            if affect_presence:
                yield self.started_stream(auth_user)

            if timeout:
                # If they've set a timeout set a minimum limit.
                timeout = max(timeout, 500)

                # Add some randomness to this value to try and mitigate against
                # thundering herds on restart.
                timeout = random.randint(int(timeout*0.9), int(timeout*1.1))

            if is_guest:
                yield user_joined_room(self.distributor, auth_user, room_id)

            events, tokens = yield self.notifier.get_events_for(
                auth_user, pagin_config, timeout,
                only_room_events=only_room_events,
                is_guest=is_guest, guest_room_id=room_id
            )

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

        finally:
            if affect_presence:
                self.stopped_stream(auth_user)


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
