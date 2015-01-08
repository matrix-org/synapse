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

from synapse.api.constants import EventTypes, Membership
from synapse.api.errors import RoomError
from synapse.streams.config import PaginationConfig
from synapse.events.validator import EventValidator
from synapse.util.logcontext import PreserveLoggingContext

from ._base import BaseHandler

import logging

logger = logging.getLogger(__name__)


class MessageHandler(BaseHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.clock = hs.get_clock()
        self.validator = EventValidator()

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

        # TODO (erikj): Once we work out the correct c-s api we need to think
        # on how to do this.

        defer.returnValue(None)

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
            pagin_config.from_token = (
                yield self.hs.get_event_sources().get_current_token()
            )

        user = self.hs.parse_userid(user_id)

        events, next_key = yield data_source.get_pagination_rows(
            user, pagin_config.get_source_config("room"), room_id
        )

        next_token = pagin_config.from_token.copy_and_replace(
            "room_key", next_key
        )

        chunk = {
            "chunk": [self.hs.serialize_event(e) for e in events],
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        defer.returnValue(chunk)

    @defer.inlineCallbacks
    def create_and_send_event(self, event_dict, ratelimit=True):
        """ Given a dict from a client, create and handle a new event.

        Creates an FrozenEvent object, filling out auth_events, prev_events,
        etc.

        Adds display names to Join membership events.

        Persists and notifies local clients and federation.

        Args:
            event_dict (dict): An entire event
        """
        builder = self.event_builder_factory.new(event_dict)

        self.validator.validate_new(builder)

        if ratelimit:
            self.ratelimit(builder.user_id)
        # TODO(paul): Why does 'event' not have a 'user' object?
        user = self.hs.parse_userid(builder.user_id)
        assert self.hs.is_mine(user), "User must be our own: %s" % (user,)

        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            if membership == Membership.JOIN:
                joinee = self.hs.parse_userid(builder.state_key)
                # If event doesn't include a display name, add one.
                yield self.distributor.fire(
                    "collect_presencelike_data",
                    joinee,
                    builder.content
                )

        event, context = yield self._create_new_client_event(
            builder=builder,
        )

        if event.type == EventTypes.Member:
            member_handler = self.hs.get_handlers().room_member_handler
            yield member_handler.change_membership(event, context)
        else:
            yield self.handle_new_client_event(
                event=event,
                context=context,
            )

        if event.type == EventTypes.Message:
            presence = self.hs.get_handlers().presence_handler
            with PreserveLoggingContext():
                presence.bump_presence_active_time(user)

        defer.returnValue(event)

    @defer.inlineCallbacks
    def get_room_data(self, user_id=None, room_id=None,
                      event_type=None, state_key=""):
        """ Get data from a room.

        Args:
            event : The room path event
        Returns:
            The path data content.
        Raises:
            SynapseError if something went wrong.
        """
        have_joined = yield self.auth.check_joined_room(room_id, user_id)
        if not have_joined:
            raise RoomError(403, "User not in room.")

        data = yield self.state_handler.get_current_state(
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
    def get_state_events(self, user_id, room_id):
        """Retrieve all state events for a given room.

        Args:
            user_id(str): The user requesting state events.
            room_id(str): The room ID to get all state events from.
        Returns:
            A list of dicts representing state events. [{}, {}, {}]
        """
        yield self.auth.check_joined_room(room_id, user_id)

        # TODO: This is duplicating logic from snapshot_all_rooms
        current_state = yield self.state_handler.get_current_state(room_id)
        defer.returnValue([self.hs.serialize_event(c) for c in current_state])

    @defer.inlineCallbacks
    def snapshot_all_rooms(self, user_id=None, pagin_config=None,
                           feedback=False, as_client_event=True):
        """Retrieve a snapshot of all rooms the user is invited or has joined.

        This snapshot may include messages for all rooms where the user is
        joined, depending on the pagination config.

        Args:
            user_id (str): The ID of the user making the request.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config used to determine how many messages *PER ROOM* to return.
            feedback (bool): True to get feedback along with these messages.
            as_client_event (bool): True to get events in client-server format.
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
            user, pagination_config.get_source_config("presence"), None
        )

        public_rooms = yield self.store.get_rooms(is_public=True)
        public_room_ids = [r["room_id"] for r in public_rooms]

        limit = pagin_config.limit
        if limit is None:
            limit = 10

        for event in room_list:
            d = {
                "room_id": event.room_id,
                "membership": event.membership,
                "visibility": (
                    "public" if event.room_id in public_room_ids
                    else "private"
                ),
            }

            if event.membership == Membership.INVITE:
                d["inviter"] = event.sender

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
                    "chunk": [
                        self.hs.serialize_event(m, as_client_event)
                        for m in messages
                    ],
                    "start": start_token.to_string(),
                    "end": end_token.to_string(),
                }

                current_state = yield self.state_handler.get_current_state(
                    event.room_id
                )
                d["state"] = [
                    self.hs.serialize_event(c) for c in current_state
                ]
            except:
                logger.exception("Failed to get snapshot")

        ret = {
            "rooms": rooms_ret,
            "presence": presence,
            "end": now_token.to_string()
        }

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def room_initial_sync(self, user_id, room_id, pagin_config=None,
                          feedback=False):
        yield self.auth.check_joined_room(room_id, user_id)

        # TODO(paul): I wish I was called with user objects not user_id
        #   strings...
        auth_user = self.hs.parse_userid(user_id)

        # TODO: These concurrently
        state_tuples = yield self.state_handler.get_current_state(room_id)
        state = [self.hs.serialize_event(x) for x in state_tuples]

        member_event = (yield self.store.get_room_member(
            user_id=user_id,
            room_id=room_id
        ))

        now_token = yield self.hs.get_event_sources().get_current_token()

        limit = pagin_config.limit if pagin_config else None
        if limit is None:
            limit = 10

        messages, token = yield self.store.get_recent_events_for_room(
            room_id,
            limit=limit,
            end_token=now_token.room_key,
        )

        start_token = now_token.copy_and_replace("room_key", token[0])
        end_token = now_token.copy_and_replace("room_key", token[1])

        room_members = yield self.store.get_room_members(room_id)

        presence_handler = self.hs.get_handlers().presence_handler
        presence = []
        for m in room_members:
            try:
                member_presence = yield presence_handler.get_state(
                    target_user=self.hs.parse_userid(m.user_id),
                    auth_user=auth_user,
                    as_event=True,
                )
                presence.append(member_presence)
            except Exception:
                logger.exception(
                    "Failed to get member presence of %r", m.user_id
                )

        defer.returnValue({
            "membership": member_event.membership,
            "room_id": room_id,
            "messages": {
                "chunk": [self.hs.serialize_event(m) for m in messages],
                "start": start_token.to_string(),
                "end": end_token.to_string(),
            },
            "state": state,
            "presence": presence
        })
