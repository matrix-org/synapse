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
from synapse.api.errors import SynapseError, AuthError, Codes
from synapse.streams.config import PaginationConfig
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.util import unwrapFirstError
from synapse.util.logcontext import PreserveLoggingContext
from synapse.types import UserID, RoomStreamToken, StreamToken

from ._base import BaseHandler

import logging

logger = logging.getLogger(__name__)


class MessageHandler(BaseHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.state = hs.get_state_handler()
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
                     as_client_event=True, is_guest=False):
        """Get messages in a room.

        Args:
            user_id (str): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
                config rules to apply, if any.
            as_client_event (bool): True to get events in client-server format.
            is_guest (bool): Whether the requesting user is a guest (as opposed
                to a fully registered user).
        Returns:
            dict: Pagination API results
        """
        data_source = self.hs.get_event_sources().sources["room"]

        if pagin_config.from_token:
            room_token = pagin_config.from_token.room_key
        else:
            pagin_config.from_token = (
                yield self.hs.get_event_sources().get_current_token(
                    direction='b'
                )
            )
            room_token = pagin_config.from_token.room_key

        room_token = RoomStreamToken.parse(room_token)
        if room_token.topological is None:
            raise SynapseError(400, "Invalid token")

        pagin_config.from_token = pagin_config.from_token.copy_and_replace(
            "room_key", str(room_token)
        )

        source_config = pagin_config.get_source_config("room")

        if not is_guest:
            member_event = yield self.auth.check_user_was_in_room(room_id, user_id)
            if member_event.membership == Membership.LEAVE:
                # If they have left the room then clamp the token to be before
                # they left the room.
                # If they're a guest, we'll just 403 them if they're asking for
                # events they can't see.
                leave_token = yield self.store.get_topological_token_for_event(
                    member_event.event_id
                )
                leave_token = RoomStreamToken.parse(leave_token)
                if leave_token.topological < room_token.topological:
                    source_config.from_key = str(leave_token)

                if source_config.direction == "f":
                    if source_config.to_key is None:
                        source_config.to_key = str(leave_token)
                    else:
                        to_token = RoomStreamToken.parse(source_config.to_key)
                        if leave_token.topological < to_token.topological:
                            source_config.to_key = str(leave_token)

        yield self.hs.get_handlers().federation_handler.maybe_backfill(
            room_id, room_token.topological
        )

        user = UserID.from_string(user_id)

        events, next_key = yield data_source.get_pagination_rows(
            user, source_config, room_id
        )

        next_token = pagin_config.from_token.copy_and_replace(
            "room_key", next_key
        )

        if not events:
            defer.returnValue({
                "chunk": [],
                "start": pagin_config.from_token.to_string(),
                "end": next_token.to_string(),
            })

        events = yield self._filter_events_for_client(user_id, events, is_guest=is_guest)

        time_now = self.clock.time_msec()

        chunk = {
            "chunk": [
                serialize_event(e, time_now, as_client_event)
                for e in events
            ],
            "start": pagin_config.from_token.to_string(),
            "end": next_token.to_string(),
        }

        defer.returnValue(chunk)

    @defer.inlineCallbacks
    def create_and_send_event(self, event_dict, ratelimit=True,
                              token_id=None, txn_id=None, is_guest=False):
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
        user = UserID.from_string(builder.user_id)
        assert self.hs.is_mine(user), "User must be our own: %s" % (user,)

        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            if membership == Membership.JOIN:
                joinee = UserID.from_string(builder.state_key)
                # If event doesn't include a display name, add one.
                yield self.distributor.fire(
                    "collect_presencelike_data",
                    joinee,
                    builder.content
                )

        if token_id is not None:
            builder.internal_metadata.token_id = token_id

        if txn_id is not None:
            builder.internal_metadata.txn_id = txn_id

        event, context = yield self._create_new_client_event(
            builder=builder,
        )

        if event.type == EventTypes.Member:
            member_handler = self.hs.get_handlers().room_member_handler
            yield member_handler.change_membership(event, context, is_guest=is_guest)
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
                      event_type=None, state_key="", is_guest=False):
        """ Get data from a room.

        Args:
            event : The room path event
        Returns:
            The path data content.
        Raises:
            SynapseError if something went wrong.
        """
        membership, membership_event_id = yield self._check_in_room_or_world_readable(
            room_id, user_id, is_guest
        )

        if membership == Membership.JOIN:
            data = yield self.state_handler.get_current_state(
                room_id, event_type, state_key
            )
        elif membership == Membership.LEAVE:
            key = (event_type, state_key)
            room_state = yield self.store.get_state_for_events(
                [membership_event_id], [key]
            )
            data = room_state[membership_event_id].get(key)

        defer.returnValue(data)

    @defer.inlineCallbacks
    def _check_in_room_or_world_readable(self, room_id, user_id, is_guest):
        try:
            # check_user_was_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            member_event = yield self.auth.check_user_was_in_room(room_id, user_id)
            defer.returnValue((member_event.membership, member_event.event_id))
            return
        except AuthError, auth_error:
            visibility = yield self.state_handler.get_current_state(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility and
                visibility.content["history_visibility"] == "world_readable"
            ):
                defer.returnValue((Membership.JOIN, None))
                return
            if not is_guest:
                raise auth_error
            raise AuthError(
                403, "Guest access not allowed", errcode=Codes.GUEST_ACCESS_FORBIDDEN
            )

    @defer.inlineCallbacks
    def get_state_events(self, user_id, room_id, is_guest=False):
        """Retrieve all state events for a given room. If the user is
        joined to the room then return the current state. If the user has
        left the room return the state events from when they left.

        Args:
            user_id(str): The user requesting state events.
            room_id(str): The room ID to get all state events from.
        Returns:
            A list of dicts representing state events. [{}, {}, {}]
        """
        membership, membership_event_id = yield self._check_in_room_or_world_readable(
            room_id, user_id, is_guest
        )

        if membership == Membership.JOIN:
            room_state = yield self.state_handler.get_current_state(room_id)
        elif membership == Membership.LEAVE:
            room_state = yield self.store.get_state_for_events(
                [membership_event_id], None
            )
            room_state = room_state[membership_event_id]

        now = self.clock.time_msec()
        defer.returnValue(
            [serialize_event(c, now) for c in room_state.values()]
        )

    @defer.inlineCallbacks
    def snapshot_all_rooms(self, user_id=None, pagin_config=None,
                           as_client_event=True, include_archived=False):
        """Retrieve a snapshot of all rooms the user is invited or has joined.

        This snapshot may include messages for all rooms where the user is
        joined, depending on the pagination config.

        Args:
            user_id (str): The ID of the user making the request.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
            config used to determine how many messages *PER ROOM* to return.
            as_client_event (bool): True to get events in client-server format.
            include_archived (bool): True to get rooms that the user has left
        Returns:
            A list of dicts with "room_id" and "membership" keys for all rooms
            the user is currently invited or joined in on. Rooms where the user
            is joined on, may return a "messages" key with messages, depending
            on the specified PaginationConfig.
        """
        memberships = [Membership.INVITE, Membership.JOIN]
        if include_archived:
            memberships.append(Membership.LEAVE)

        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=user_id, membership_list=memberships
        )

        user = UserID.from_string(user_id)

        rooms_ret = []

        now_token = yield self.hs.get_event_sources().get_current_token()

        presence_stream = self.hs.get_event_sources().sources["presence"]
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user, pagination_config.get_source_config("presence"), None
        )

        receipt_stream = self.hs.get_event_sources().sources["receipt"]
        receipt, _ = yield receipt_stream.get_pagination_rows(
            user, pagination_config.get_source_config("receipt"), None
        )

        tags_by_room = yield self.store.get_tags_for_user(user_id)

        public_room_ids = yield self.store.get_public_room_ids()

        limit = pagin_config.limit
        if limit is None:
            limit = 10

        @defer.inlineCallbacks
        def handle_room(event):
            d = {
                "room_id": event.room_id,
                "membership": event.membership,
                "visibility": (
                    "public" if event.room_id in public_room_ids
                    else "private"
                ),
            }

            if event.membership == Membership.INVITE:
                time_now = self.clock.time_msec()
                d["inviter"] = event.sender

                invite_event = yield self.store.get_event(event.event_id)
                d["invite"] = serialize_event(invite_event, time_now, as_client_event)

            rooms_ret.append(d)

            if event.membership not in (Membership.JOIN, Membership.LEAVE):
                return

            try:
                if event.membership == Membership.JOIN:
                    room_end_token = now_token.room_key
                    deferred_room_state = self.state_handler.get_current_state(
                        event.room_id
                    )
                elif event.membership == Membership.LEAVE:
                    room_end_token = "s%d" % (event.stream_ordering,)
                    deferred_room_state = self.store.get_state_for_events(
                        [event.event_id], None
                    )
                    deferred_room_state.addCallback(
                        lambda states: states[event.event_id]
                    )

                (messages, token), current_state = yield defer.gatherResults(
                    [
                        self.store.get_recent_events_for_room(
                            event.room_id,
                            limit=limit,
                            end_token=room_end_token,
                        ),
                        deferred_room_state,
                    ]
                ).addErrback(unwrapFirstError)

                messages = yield self._filter_events_for_client(
                    user_id, messages
                )

                start_token = now_token.copy_and_replace("room_key", token[0])
                end_token = now_token.copy_and_replace("room_key", token[1])
                time_now = self.clock.time_msec()

                d["messages"] = {
                    "chunk": [
                        serialize_event(m, time_now, as_client_event)
                        for m in messages
                    ],
                    "start": start_token.to_string(),
                    "end": end_token.to_string(),
                }

                d["state"] = [
                    serialize_event(c, time_now, as_client_event)
                    for c in current_state.values()
                ]

                private_user_data = []
                tags = tags_by_room.get(event.room_id)
                if tags:
                    private_user_data.append({
                        "type": "m.tag",
                        "content": {"tags": tags},
                    })
                d["private_user_data"] = private_user_data
            except:
                logger.exception("Failed to get snapshot")

        # Only do N rooms at once
        n = 5
        d_list = [handle_room(e) for e in room_list]
        for i in range(0, len(d_list), n):
            yield defer.gatherResults(
                d_list[i:i + n],
                consumeErrors=True
            ).addErrback(unwrapFirstError)

        ret = {
            "rooms": rooms_ret,
            "presence": presence,
            "receipts": receipt,
            "end": now_token.to_string(),
        }

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def room_initial_sync(self, user_id, room_id, pagin_config=None, is_guest=False):
        """Capture the a snapshot of a room. If user is currently a member of
        the room this will be what is currently in the room. If the user left
        the room this will be what was in the room when they left.

        Args:
            user_id(str): The user to get a snapshot for.
            room_id(str): The room to get a snapshot of.
            pagin_config(synapse.streams.config.PaginationConfig):
                The pagination config used to determine how many messages to
                return.
        Raises:
            AuthError if the user wasn't in the room.
        Returns:
            A JSON serialisable dict with the snapshot of the room.
        """

        membership, member_event_id = yield self._check_in_room_or_world_readable(
            room_id,
            user_id,
            is_guest
        )

        if membership == Membership.JOIN:
            result = yield self._room_initial_sync_joined(
                user_id, room_id, pagin_config, membership, is_guest
            )
        elif membership == Membership.LEAVE:
            result = yield self._room_initial_sync_parted(
                user_id, room_id, pagin_config, membership, member_event_id, is_guest
            )

        private_user_data = []
        tags = yield self.store.get_tags_for_room(user_id, room_id)
        if tags:
            private_user_data.append({
                "type": "m.tag",
                "content": {"tags": tags},
            })
        result["private_user_data"] = private_user_data

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _room_initial_sync_parted(self, user_id, room_id, pagin_config,
                                  membership, member_event_id, is_guest):
        room_state = yield self.store.get_state_for_events(
            [member_event_id], None
        )

        room_state = room_state[member_event_id]

        limit = pagin_config.limit if pagin_config else None
        if limit is None:
            limit = 10

        stream_token = yield self.store.get_stream_token_for_event(
            member_event_id
        )

        messages, token = yield self.store.get_recent_events_for_room(
            room_id,
            limit=limit,
            end_token=stream_token
        )

        messages = yield self._filter_events_for_client(
            user_id, messages, is_guest=is_guest
        )

        start_token = StreamToken(token[0], 0, 0, 0, 0)
        end_token = StreamToken(token[1], 0, 0, 0, 0)

        time_now = self.clock.time_msec()

        defer.returnValue({
            "membership": membership,
            "room_id": room_id,
            "messages": {
                "chunk": [serialize_event(m, time_now) for m in messages],
                "start": start_token.to_string(),
                "end": end_token.to_string(),
            },
            "state": [serialize_event(s, time_now) for s in room_state.values()],
            "presence": [],
            "receipts": [],
        })

    @defer.inlineCallbacks
    def _room_initial_sync_joined(self, user_id, room_id, pagin_config,
                                  membership, is_guest):
        current_state = yield self.state.get_current_state(
            room_id=room_id,
        )

        # TODO(paul): I wish I was called with user objects not user_id
        #   strings...
        auth_user = UserID.from_string(user_id)

        # TODO: These concurrently
        time_now = self.clock.time_msec()
        state = [
            serialize_event(x, time_now)
            for x in current_state.values()
        ]

        now_token = yield self.hs.get_event_sources().get_current_token()

        limit = pagin_config.limit if pagin_config else None
        if limit is None:
            limit = 10

        room_members = [
            m for m in current_state.values()
            if m.type == EventTypes.Member
            and m.content["membership"] == Membership.JOIN
        ]

        presence_handler = self.hs.get_handlers().presence_handler

        @defer.inlineCallbacks
        def get_presence():
            states = {}
            if not is_guest:
                states = yield presence_handler.get_states(
                    target_users=[UserID.from_string(m.user_id) for m in room_members],
                    auth_user=auth_user,
                    as_event=True,
                    check_auth=False,
                )

            defer.returnValue(states.values())

        receipts_handler = self.hs.get_handlers().receipts_handler

        presence, receipts, (messages, token) = yield defer.gatherResults(
            [
                get_presence(),
                receipts_handler.get_receipts_for_room(room_id, now_token.receipt_key),
                self.store.get_recent_events_for_room(
                    room_id,
                    limit=limit,
                    end_token=now_token.room_key,
                )
            ],
            consumeErrors=True,
        ).addErrback(unwrapFirstError)

        messages = yield self._filter_events_for_client(
            user_id, messages, is_guest=is_guest, require_all_visible_for_guests=False
        )

        start_token = now_token.copy_and_replace("room_key", token[0])
        end_token = now_token.copy_and_replace("room_key", token[1])

        time_now = self.clock.time_msec()

        ret = {
            "room_id": room_id,
            "messages": {
                "chunk": [serialize_event(m, time_now) for m in messages],
                "start": start_token.to_string(),
                "end": end_token.to_string(),
            },
            "state": state,
            "presence": presence,
            "receipts": receipts,
        }
        if not is_guest:
            ret["membership"] = membership

        defer.returnValue(ret)
