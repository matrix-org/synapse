# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from synapse.api.constants import Membership
from synapse.api.events.room import RoomMemberEvent

from twisted.internet import defer
from twisted.internet import reactor

import logging

logger = logging.getLogger(__name__)


class Notifier(object):

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.hs = hs
        self.stored_event_listeners = {}

    @defer.inlineCallbacks
    def on_new_room_event(self, event, store_id):
        """Called when there is a new room event which may potentially be sent
        down listening users' event streams.

        This function looks for interested *users* who may want to be notified
        for this event. This is different to users requesting from the event
        stream which looks for interested *events* for this user.

        Args:
            event (SynapseEvent): The new event, which must have a room_id
            store_id (int): The ID of this event after it was stored with the
            data store.
        '"""
        member_list = yield self.store.get_room_members(room_id=event.room_id,
                                                        membership="join")
        if not member_list:
            member_list = []

        member_list = [u.user_id for u in member_list]

        # invites MUST prod the person being invited, who won't be in the room.
        if (event.type == RoomMemberEvent.TYPE and
                event.content["membership"] == Membership.INVITE):
            member_list.append(event.target_user_id)

        for user_id in member_list:
            if user_id in self.stored_event_listeners:
                self._notify_and_callback(
                    user_id=user_id,
                    event_data=event.get_dict(),
                    stream_type=event.type,
                    store_id=store_id)

    def on_new_user_event(self, user_id, event_data, stream_type, store_id):
        if user_id in self.stored_event_listeners:
            self._notify_and_callback(
                user_id=user_id,
                event_data=event_data,
                stream_type=stream_type,
                store_id=store_id
            )

    def _notify_and_callback(self, user_id, event_data, stream_type, store_id):
        logger.debug(
            "Notifying %s of a new event.",
            user_id
        )

        stream_ids = list(self.stored_event_listeners[user_id])
        for stream_id in stream_ids:
            self._notify_and_callback_stream(user_id, stream_id, event_data,
                                             stream_type, store_id)

        if not self.stored_event_listeners[user_id]:
            del self.stored_event_listeners[user_id]

    def _notify_and_callback_stream(self, user_id, stream_id, event_data,
                                    stream_type, store_id):

        event_listener = self.stored_event_listeners[user_id].pop(stream_id)
        return_event_object = {
            k: event_listener[k] for k in ["start", "chunk", "end"]
        }

        # work out the new end token
        token = event_listener["start"]
        end = self._next_token(stream_type, store_id, token)
        return_event_object["end"] = end

        # add the event to the chunk
        chunk = event_listener["chunk"]
        chunk.append(event_data)

        # callback the defer. We know this can't have been resolved before as
        # we always remove the event_listener from the map before resolving.
        event_listener["defer"].callback(return_event_object)

    def _next_token(self, stream_type, store_id, current_token):
        stream_handler = self.hs.get_handlers().event_stream_handler
        return stream_handler.get_event_stream_token(
            stream_type,
            store_id,
            current_token
        )

    def store_events_for(self, user_id=None, stream_id=None, from_tok=None):
        """Store all incoming events for this user. This should be paired with
        get_events_for to return chunked data.

        Args:
            user_id (str): The user to monitor incoming events for.
            stream (object): The stream that is receiving events
            from_tok (str): The token to monitor incoming events from.
        """
        event_listener = {
            "start": from_tok,
            "chunk": [],
            "end": from_tok,
            "defer": defer.Deferred(),
        }

        if user_id not in self.stored_event_listeners:
            self.stored_event_listeners[user_id] = {stream_id: event_listener}
        else:
            self.stored_event_listeners[user_id][stream_id] = event_listener

    def purge_events_for(self, user_id=None, stream_id=None):
        """Purges any stored events for this user.

        Args:
            user_id (str): The user to purge stored events for.
        """
        try:
            del self.stored_event_listeners[user_id][stream_id]
            if not self.stored_event_listeners[user_id]:
                del self.stored_event_listeners[user_id]
        except KeyError:
            pass

    def get_events_for(self, user_id=None, stream_id=None, timeout=0):
        """Retrieve stored events for this user, waiting if necessary.

        It is advisable to wrap this call in a maybeDeferred.

        Args:
            user_id (str): The user to get events for.
            timeout (int): The time in seconds to wait before giving up.
        Returns:
            A Deferred or a dict containing the chunk data, depending on if
            there was data to return yet. The Deferred callback may be None if
            there were no events before the timeout expired.
        """
        logger.debug("%s is listening for events.", user_id)

        if len(self.stored_event_listeners[user_id][stream_id]["chunk"]) > 0:
            logger.debug("%s returning existing chunk.", user_id)
            return self.stored_event_listeners[user_id][stream_id]

        reactor.callLater(
            (timeout / 1000.0), self._timeout, user_id, stream_id
        )
        return self.stored_event_listeners[user_id][stream_id]["defer"]

    def _timeout(self, user_id, stream_id):
        try:
            # We remove the event_listener from the map so that we can't
            # resolve the deferred twice.
            event_listeners = self.stored_event_listeners[user_id]
            event_listener = event_listeners.pop(stream_id)
            event_listener["defer"].callback(None)
            logger.debug("%s event listening timed out.", user_id)
        except KeyError:
            pass
