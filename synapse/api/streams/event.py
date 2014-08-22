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
from synapse.api.events import SynapseEvent
from synapse.api.events.room import (
    RoomMemberEvent, MessageEvent, FeedbackEvent, RoomTopicEvent
)
from synapse.api.streams import PaginationStream, StreamData

import logging

logger = logging.getLogger(__name__)


class EventsStreamData(StreamData):
    EVENT_TYPE = "EventsStream"

    def __init__(self, hs, room_id=None, feedback=False):
        super(EventsStreamData, self).__init__(hs)
        self.room_id = room_id
        self.with_feedback = feedback

    @defer.inlineCallbacks
    def get_rows(self, user_id, from_key, to_key, limit, direction):
        data, latest_ver = yield self.store.get_room_events(
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
        val = yield self.store.get_room_events_max_id()
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

        if (
            not pagination_config.to_tok
            and pagination_config.direction == 'f'
        ):
            pagination_config.to_tok = yield self.get_current_max_token()

        logger.debug("pagination_config: %s", pagination_config)

        defer.returnValue(pagination_config)

    @defer.inlineCallbacks
    def fix_token(self, token):
        """Fixes unknown values in a token to known values.

        Args:
            token (str): The token to fix up.
        Returns:
            The fixed-up token, which may == token.
        """
        if token == PaginationStream.TOK_END:
            new_token = yield self.get_current_max_token()

            logger.debug("fix_token: From %s to %s", token, new_token)

            token = new_token

        defer.returnValue(token)

    @defer.inlineCallbacks
    def get_current_max_token(self):
        new_token_parts = []
        for s in self.stream_data:
            mx = yield s.max_token()
            new_token_parts.append(str(mx))

        new_token = EventStream.SEPARATOR.join(new_token_parts)

        logger.debug("get_current_max_token: %s", new_token)

        defer.returnValue(new_token)

    @defer.inlineCallbacks
    def get_chunk(self, config):
        # no support for limit on >1 streams, makes no sense.
        if config.limit and len(self.stream_data) > 1:
            raise EventStreamError(
                400, "Limit not supported on multiplexed streams."
            )

        chunk_data, next_tok = yield self._get_chunk_data(
            config.from_tok,
            config.to_tok,
            config.limit,
            config.direction,
        )

        defer.returnValue({
            "chunk": chunk_data,
            "start": config.from_tok,
            "end": next_tok
        })

    @defer.inlineCallbacks
    def _get_chunk_data(self, from_tok, to_tok, limit, direction):
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
        if to_tok is not None:
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
                self.user_id, from_pkey, to_pkey, limit, direction,
            )

            chunk.extend([
                e.get_dict() if isinstance(e, SynapseEvent) else e
                for e in event_chunk
            ])
            next_ver.append(str(max_pkey))

        defer.returnValue((chunk, EventStream.SEPARATOR.join(next_ver)))

    def _split_token(self, token):
        """Splits the given token into a list of pkeys.

        Args:
            token (str): The token with SEPARATOR values.
        Returns:
            A list of ints.
        """
        if token:
            segments = token.split(EventStream.SEPARATOR)
        else:
            segments = [None] * len(self.stream_data)
        return segments
