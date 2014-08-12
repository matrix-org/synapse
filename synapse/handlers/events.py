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
from twisted.internet import defer

from ._base import BaseHandler
from synapse.api.streams.event import (
    EventStream, MessagesStreamData, RoomMemberStreamData, FeedbackStreamData,
    RoomDataStreamData
)
from synapse.handlers.presence import PresenceStreamData


class EventStreamHandler(BaseHandler):

    stream_data_classes = [
        MessagesStreamData,
        RoomMemberStreamData,
        FeedbackStreamData,
        RoomDataStreamData,
        PresenceStreamData,
    ]

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

    def get_event_stream_token(self, stream_type, store_id, start_token):
        """Return the next token after this event.

        Args:
            stream_type (str): The StreamData.EVENT_TYPE
            store_id (int): The new storage ID assigned from the data store.
            start_token (str): The token the user started with.
        Returns:
            str: The end token.
        """
        for i, stream_cls in enumerate(EventStreamHandler.stream_data_classes):
            if stream_cls.EVENT_TYPE == stream_type:
                # this is the stream for this event, so replace this part of
                # the token
                store_ids = start_token.split(EventStream.SEPARATOR)
                store_ids[i] = str(store_id)
                return EventStream.SEPARATOR.join(store_ids)
        raise RuntimeError("Didn't find a stream type %s" % stream_type)

    @defer.inlineCallbacks
    def get_stream(self, auth_user_id, pagin_config, timeout=0):
        """Gets events as an event stream for this user.

        This function looks for interesting *events* for this user. This is
        different from the notifier, which looks for interested *users* who may
        want to know about a single event.

        Args:
            auth_user_id (str): The user requesting their event stream.
            pagin_config (synapse.api.streams.PaginationConfig): The config to
            use when obtaining the stream.
            timeout (int): The max time to wait for an incoming event in ms.
        Returns:
            A pagination stream API dict
        """
        auth_user = self.hs.parse_userid(auth_user_id)

        stream_id = object()

        try:
            if auth_user not in self._streams_per_user:
                self._streams_per_user[auth_user] = 0
                if auth_user in self._stop_timer_per_user:
                    self.clock.cancel_call_later(
                        self._stop_timer_per_user.pop(auth_user))
                else:
                    self.distributor.fire(
                        "started_user_eventstream", auth_user
                    )
            self._streams_per_user[auth_user] += 1

            # construct an event stream with the correct data ordering
            stream_data_list = []
            for stream_class in EventStreamHandler.stream_data_classes:
                stream_data_list.append(stream_class(self.hs))
            event_stream = EventStream(auth_user_id, stream_data_list)

            # fix unknown tokens to known tokens
            pagin_config = yield event_stream.fix_tokens(pagin_config)

            # register interest in receiving new events
            self.notifier.store_events_for(user_id=auth_user_id,
                                           stream_id=stream_id,
                                           from_tok=pagin_config.from_tok)

            # see if we can grab a chunk now
            data_chunk = yield event_stream.get_chunk(config=pagin_config)

            # if there are previous events, return those. If not, wait on the
            # new events for 'timeout' seconds.
            if len(data_chunk["chunk"]) == 0 and timeout != 0:
                results = yield defer.maybeDeferred(
                    self.notifier.get_events_for,
                    user_id=auth_user_id,
                    stream_id=stream_id,
                    timeout=timeout
                )
                if results:
                    defer.returnValue(results)

            defer.returnValue(data_chunk)
        finally:
            # cleanup
            self.notifier.purge_events_for(user_id=auth_user_id,
                                           stream_id=stream_id)

            self._streams_per_user[auth_user] -= 1
            if not self._streams_per_user[auth_user]:
                del self._streams_per_user[auth_user]

                # 10 seconds of grace to allow the client to reconnect again
                #   before we think they're gone
                def _later():
                    self.distributor.fire(
                        "stopped_user_eventstream", auth_user
                    )
                    del self._stop_timer_per_user[auth_user]

                self._stop_timer_per_user[auth_user] = (
                    self.clock.call_later(5, _later)
                )
