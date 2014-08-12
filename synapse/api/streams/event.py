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
"""This module contains classes for streaming from the event stream: /events.
"""
from twisted.internet import defer

from synapse.api.errors import EventStreamError
from synapse.api.events.room import (
    RoomMemberEvent, MessageEvent, FeedbackEvent, RoomTopicEvent
)
from synapse.api.streams import PaginationStream, StreamData

import logging

logger = logging.getLogger(__name__)


class MessagesStreamData(StreamData):
    EVENT_TYPE = MessageEvent.TYPE

    def __init__(self, hs, room_id=None, feedback=False):
        super(MessagesStreamData, self).__init__(hs)
        self.room_id = room_id
        self.with_feedback = feedback

    @defer.inlineCallbacks
    def get_rows(self, user_id, from_key, to_key, limit):
        (data, latest_ver) = yield self.store.get_message_stream(
            user_id=user_id,
            from_key=from_key,
            to_key=to_key,
            limit=limit,
            room_id=self.room_id,
            with_feedback=self.with_feedback
        )
        defer.returnValue((data, latest_ver))

    @defer.inlineCallbacks
    def max_token(self):
        val = yield self.store.get_max_message_id()
        defer.returnValue(val)


class RoomMemberStreamData(StreamData):
    EVENT_TYPE = RoomMemberEvent.TYPE

    @defer.inlineCallbacks
    def get_rows(self, user_id, from_key, to_key, limit):
        (data, latest_ver) = yield self.store.get_room_member_stream(
            user_id=user_id,
            from_key=from_key,
            to_key=to_key
        )

        defer.returnValue((data, latest_ver))

    @defer.inlineCallbacks
    def max_token(self):
        val = yield self.store.get_max_room_member_id()
        defer.returnValue(val)


class FeedbackStreamData(StreamData):
    EVENT_TYPE = FeedbackEvent.TYPE

    def __init__(self, hs, room_id=None):
        super(FeedbackStreamData, self).__init__(hs)
        self.room_id = room_id

    @defer.inlineCallbacks
    def get_rows(self, user_id, from_key, to_key, limit):
        (data, latest_ver) = yield self.store.get_feedback_stream(
            user_id=user_id,
            from_key=from_key,
            to_key=to_key,
            limit=limit,
            room_id=self.room_id
        )
        defer.returnValue((data, latest_ver))

    @defer.inlineCallbacks
    def max_token(self):
        val = yield self.store.get_max_feedback_id()
        defer.returnValue(val)


class RoomDataStreamData(StreamData):
    EVENT_TYPE = RoomTopicEvent.TYPE  # TODO need multiple event types

    def __init__(self, hs, room_id=None):
        super(RoomDataStreamData, self).__init__(hs)
        self.room_id = room_id

    @defer.inlineCallbacks
    def get_rows(self, user_id, from_key, to_key, limit):
        (data, latest_ver) = yield self.store.get_room_data_stream(
            user_id=user_id,
            from_key=from_key,
            to_key=to_key,
            limit=limit,
            room_id=self.room_id
        )
        defer.returnValue((data, latest_ver))

    @defer.inlineCallbacks
    def max_token(self):
        val = yield self.store.get_max_room_data_id()
        defer.returnValue(val)


class EventStream(PaginationStream):

    SEPARATOR = '_'

    def __init__(self, user_id, stream_data_list):
        super(EventStream, self).__init__()
        self.user_id = user_id
        self.stream_data = stream_data_list

    @defer.inlineCallbacks
    def fix_tokens(self, pagination_config):
        pagination_config.from_tok = yield self.fix_token(
            pagination_config.from_tok)
        pagination_config.to_tok = yield self.fix_token(
            pagination_config.to_tok)
        defer.returnValue(pagination_config)

    @defer.inlineCallbacks
    def fix_token(self, token):
        """Fixes unknown values in a token to known values.

        Args:
            token (str): The token to fix up.
        Returns:
            The fixed-up token, which may == token.
        """
        # replace TOK_START and TOK_END with 0_0_0 or -1_-1_-1 depending.
        replacements = [
            (PaginationStream.TOK_START, "0"),
            (PaginationStream.TOK_END, "-1")
        ]
        for magic_token, key in replacements:
            if magic_token == token:
                token = EventStream.SEPARATOR.join(
                    [key] * len(self.stream_data)
                )

        # replace -1 values with an actual pkey
        token_segments = self._split_token(token)
        for i, tok in enumerate(token_segments):
            if tok == -1:
                # add 1 to the max token because results are EXCLUSIVE from the
                # latest version.
                token_segments[i] = 1 + (yield self.stream_data[i].max_token())
        defer.returnValue(EventStream.SEPARATOR.join(
            str(x) for x in token_segments
        ))

    @defer.inlineCallbacks
    def get_chunk(self, config=None):
        # no support for limit on >1 streams, makes no sense.
        if config.limit and len(self.stream_data) > 1:
            raise EventStreamError(
                400, "Limit not supported on multiplexed streams."
            )

        (chunk_data, next_tok) = yield self._get_chunk_data(config.from_tok,
                                                            config.to_tok,
                                                            config.limit)

        defer.returnValue({
            "chunk": chunk_data,
            "start": config.from_tok,
            "end": next_tok
        })

    @defer.inlineCallbacks
    def _get_chunk_data(self, from_tok, to_tok, limit):
        """ Get event data between the two tokens.

        Tokens are SEPARATOR separated values representing pkey values of
        certain tables, and the position determines the StreamData invoked
        according to the STREAM_DATA list.

        The magic value '-1' can be used to get the latest value.

        Args:
            from_tok - The token to start from.
            to_tok - The token to end at. Must have values > from_tok or be -1.
        Returns:
            A list of event data.
        Raises:
            EventStreamError if something went wrong.
        """
        # sanity check
        if (from_tok.count(EventStream.SEPARATOR) !=
                to_tok.count(EventStream.SEPARATOR) or
                (from_tok.count(EventStream.SEPARATOR) + 1) !=
                len(self.stream_data)):
            raise EventStreamError(400, "Token lengths don't match.")

        chunk = []
        next_ver = []
        for i, (from_pkey, to_pkey) in enumerate(zip(
            self._split_token(from_tok),
            self._split_token(to_tok)
        )):
            if from_pkey == to_pkey:
                # tokens are the same, we have nothing to do.
                next_ver.append(str(to_pkey))
                continue

            (event_chunk, max_pkey) = yield self.stream_data[i].get_rows(
                self.user_id, from_pkey, to_pkey, limit
            )

            chunk += event_chunk
            next_ver.append(str(max_pkey))

        defer.returnValue((chunk, EventStream.SEPARATOR.join(next_ver)))

    def _split_token(self, token):
        """Splits the given token into a list of pkeys.

        Args:
            token (str): The token with SEPARATOR values.
        Returns:
            A list of ints.
        """
        segments = token.split(EventStream.SEPARATOR)
        try:
            int_segments = [int(x) for x in segments]
        except ValueError:
            raise EventStreamError(400, "Bad token: %s" % token)
        return int_segments
