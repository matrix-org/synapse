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

from synapse.api.constants import Membership
from synapse.api.events.room import RoomTopicEvent
from synapse.api.errors import RoomError
from synapse.streams.config import PaginationConfig
from ._base import BaseRoomHandler

import logging

logger = logging.getLogger(__name__)



class MessageHandler(BaseRoomHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.clock = hs.get_clock()
        self.event_factory = hs.get_event_factory()

    @defer.inlineCallbacks
    def get_message(self, msg_id=None, room_id=None, sender_id=None,
                    user_id=None):
        """ Retrieve a message.

        Args:
            msg_id (str): The message ID to obtain.
            room_id (str): The room where the message resides.
            sender_id (str): The user ID of the user who sent the message.
            user_id (str): The user ID of the user making this request.
        Returns:
            The message, or None if no message exists.
        Raises:
            SynapseError if something went wrong.
        """
        yield self.auth.check_joined_room(room_id, user_id)

        # Pull out the message from the db
#        msg = yield self.store.get_message(
#            room_id=room_id,
#            msg_id=msg_id,
#            user_id=sender_id
#        )

        # TODO (erikj): Once we work out the correct c-s api we need to think on how to do this.

        defer.returnValue(None)

    @defer.inlineCallbacks
    def send_message(self, event=None, suppress_auth=False, stamp_event=True):
        """ Send a message.

        Args:
            event : The message event to store.
            suppress_auth (bool) : True to suppress auth for this message. This
            is primarily so the home server can inject messages into rooms at
            will.
            stamp_event (bool) : True to stamp event content with server keys.
        Raises:
            SynapseError if something went wrong.
        """
        # TODO(paul): Why does 'event' not have a 'user' object?
        user = self.hs.parse_userid(event.user_id)
        assert(user.is_mine)

        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        if not suppress_auth:
            yield self.auth.check(event, snapshot, raises=True)

        yield self._on_new_room_event(event, snapshot)

        self.hs.get_handlers().presence_handler.bump_presence_active_time(
            user
        )

    @defer.inlineCallbacks
    def get_messages(self, user_id=None, room_id=None, pagin_config=None,
                     feedback=False):
        """Get messages in a room.

        Args:
            user_id (str): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config rules to apply, if any.
            feedback (bool): True to get compressed feedback with the messages
        Returns:
            dict: Pagination API results
        """
        yield self.auth.check_joined_room(room_id, user_id)

        data_source = self.hs.get_event_sources().sources["room"]

        if not pagin_config.from_token:
            pagin_config.from_token = yield self.hs.get_event_sources().get_current_token()

        user = self.hs.parse_userid(user_id)

        events, next_token = yield data_source.get_pagination_rows(
            user, pagin_config, room_id
        )

        chunk = {
            "chunk": [e.get_dict() for e in events],
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        defer.returnValue(chunk)

    @defer.inlineCallbacks
    def store_room_data(self, event=None, stamp_event=True):
        """ Stores data for a room.

        Args:
            event : The room path event
            stamp_event (bool) : True to stamp event content with server keys.
        Raises:
            SynapseError if something went wrong.
        """

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        yield self.auth.check(event, snapshot, raises=True)

        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        yield self.state_handler.handle_new_event(event, snapshot)

        yield self._on_new_room_event(event, snapshot)

    @defer.inlineCallbacks
    def get_room_data(self, user_id=None, room_id=None,
                      event_type=None, state_key="",
                      public_room_rules=[],
                      private_room_rules=["join"]):
        """ Get data from a room.

        Args:
            event : The room path event
            public_room_rules : A list of membership states the user can be in,
            in order to read this data IN A PUBLIC ROOM. An empty list means
            'any state'.
            private_room_rules : A list of membership states the user can be
            in, in order to read this data IN A PRIVATE ROOM. An empty list
            means 'any state'.
        Returns:
            The path data content.
        Raises:
            SynapseError if something went wrong.
        """
        if event_type == RoomTopicEvent.TYPE:
            # anyone invited/joined can read the topic
            private_room_rules = ["invite", "join"]

        # does this room exist
        room = yield self.store.get_room(room_id)
        if not room:
            raise RoomError(403, "Room does not exist.")

        # does this user exist in this room
        member = yield self.store.get_room_member(
            room_id=room_id,
            user_id="" if not user_id else user_id)

        member_state = member.membership if member else None

        if room.is_public and public_room_rules:
            # make sure the user meets public room rules
            if member_state not in public_room_rules:
                raise RoomError(403, "Member does not meet public room rules.")
        elif not room.is_public and private_room_rules:
            # make sure the user meets private room rules
            if member_state not in private_room_rules:
                raise RoomError(
                    403, "Member does not meet private room rules.")

        data = yield self.store.get_current_state(
            room_id, event_type, state_key
        )
        defer.returnValue(data)

    @defer.inlineCallbacks
    def get_feedback(self, event_id):
        # yield self.auth.check_joined_room(room_id, user_id)

        # Pull out the feedback from the db
        fb = yield self.store.get_feedback(event_id)

        if fb:
            defer.returnValue(fb)
        defer.returnValue(None)

    @defer.inlineCallbacks
    def send_feedback(self, event, stamp_event=True):
        if stamp_event:
            event.content["hsob_ts"] = int(self.clock.time_msec())

        snapshot = yield self.store.snapshot_room(event.room_id, event.user_id)

        yield self.auth.check(event, snapshot, raises=True)

        # store message in db
        yield self._on_new_room_event(event, snapshot)

    @defer.inlineCallbacks
    def snapshot_all_rooms(self, user_id=None, pagin_config=None,
                           feedback=False):
        """Retrieve a snapshot of all rooms the user is invited or has joined.

        This snapshot may include messages for all rooms where the user is
        joined, depending on the pagination config.

        Args:
            user_id (str): The ID of the user making the request.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config used to determine how many messages *PER ROOM* to return.
            feedback (bool): True to get feedback along with these messages.
        Returns:
            A list of dicts with "room_id" and "membership" keys for all rooms
            the user is currently invited or joined in on. Rooms where the user
            is joined on, may return a "messages" key with messages, depending
            on the specified PaginationConfig.
        """
        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=user_id,
            membership_list=[Membership.INVITE, Membership.JOIN]
        )

        user = self.hs.parse_userid(user_id)

        rooms_ret = []

        now_token = yield self.hs.get_event_sources().get_current_token()

        presence_stream = self.hs.get_event_sources().sources["presence"]
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user, pagination_config, None
        )

        limit = pagin_config.limit
        if not limit:
            limit = 10

        for event in room_list:
            d = {
                "room_id": event.room_id,
                "membership": event.membership,
            }

            if event.membership == Membership.INVITE:
                d["inviter"] = event.user_id

            rooms_ret.append(d)

            if event.membership != Membership.JOIN:
                continue
            try:
                messages, token = yield self.store.get_recent_events_for_room(
                    event.room_id,
                    limit=limit,
                    end_token=now_token.room_key,
                )

                start_token = now_token.copy_and_replace("room_key", token[0])
                end_token = now_token.copy_and_replace("room_key", token[1])

                d["messages"] = {
                    "chunk": [m.get_dict() for m in messages],
                    "start": start_token.to_string(),
                    "end": end_token.to_string(),
                }

                current_state = yield self.store.get_current_state(
                    event.room_id
                )
                d["state"] = [c.get_dict() for c in current_state]
            except:
                logger.exception("Failed to get snapshot")

        ret = {
            "rooms": rooms_ret,
            "presence": presence,
            "end": now_token.to_string()
        }

        defer.returnValue(ret)


