# -*- coding: utf-8 -*-
# Copyright 2014 - 2016 OpenMarket Ltd
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
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.push.action_generator import ActionGenerator
from synapse.streams.config import PaginationConfig
from synapse.types import (
    UserID, RoomAlias, RoomStreamToken, StreamToken, get_domain_from_id
)
from synapse.util import unwrapFirstError
from synapse.util.async import concurrently_execute, run_on_reactor, ReadWriteLock
from synapse.util.caches.snapshot_cache import SnapshotCache
from synapse.util.logcontext import preserve_fn
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

from canonicaljson import encode_canonical_json

import logging

logger = logging.getLogger(__name__)


class MessageHandler(BaseHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.validator = EventValidator()
        self.snapshot_cache = SnapshotCache()

        self.pagination_lock = ReadWriteLock()

    @defer.inlineCallbacks
    def purge_history(self, room_id, event_id):
        event = yield self.store.get_event(event_id)

        if event.room_id != room_id:
            raise SynapseError(400, "Event is for wrong room.")

        depth = event.depth

        with (yield self.pagination_lock.write(room_id)):
            yield self.store.delete_old_state(room_id, depth)

    @defer.inlineCallbacks
    def get_messages(self, requester, room_id=None, pagin_config=None,
                     as_client_event=True, event_filter=None):
        """Get messages in a room.

        Args:
            requester (Requester): The user requesting messages.
            room_id (str): The room they want messages from.
            pagin_config (synapse.api.streams.PaginationConfig): The pagination
                config rules to apply, if any.
            as_client_event (bool): True to get events in client-server format.
            event_filter (Filter): Filter to apply to results or None
        Returns:
            dict: Pagination API results
        """
        user_id = requester.user.to_string()

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

        pagin_config.from_token = pagin_config.from_token.copy_and_replace(
            "room_key", str(room_token)
        )

        source_config = pagin_config.get_source_config("room")

        with (yield self.pagination_lock.read(room_id)):
            membership, member_event_id = yield self._check_in_room_or_world_readable(
                room_id, user_id
            )

            if source_config.direction == 'b':
                # if we're going backwards, we might need to backfill. This
                # requires that we have a topo token.
                if room_token.topological:
                    max_topo = room_token.topological
                else:
                    max_topo = yield self.store.get_max_topological_token(
                        room_id, room_token.stream
                    )

                if membership == Membership.LEAVE:
                    # If they have left the room then clamp the token to be before
                    # they left the room, to save the effort of loading from the
                    # database.
                    leave_token = yield self.store.get_topological_token_for_event(
                        member_event_id
                    )
                    leave_token = RoomStreamToken.parse(leave_token)
                    if leave_token.topological < max_topo:
                        source_config.from_key = str(leave_token)

                yield self.hs.get_handlers().federation_handler.maybe_backfill(
                    room_id, max_topo
                )

            events, next_key = yield self.store.paginate_room_events(
                room_id=room_id,
                from_key=source_config.from_key,
                to_key=source_config.to_key,
                direction=source_config.direction,
                limit=source_config.limit,
                event_filter=event_filter,
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

        if event_filter:
            events = event_filter.filter(events)

        events = yield filter_events_for_client(
            self.store,
            user_id,
            events,
            is_peeking=(member_event_id is None),
        )

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
    def create_event(self, event_dict, token_id=None, txn_id=None, prev_event_ids=None):
        """
        Given a dict from a client, create a new event.

        Creates an FrozenEvent object, filling out auth_events, prev_events,
        etc.

        Adds display names to Join membership events.

        Args:
            event_dict (dict): An entire event
            token_id (str)
            txn_id (str)
            prev_event_ids (list): The prev event ids to use when creating the event

        Returns:
            Tuple of created event (FrozenEvent), Context
        """
        builder = self.event_builder_factory.new(event_dict)

        self.validator.validate_new(builder)

        if builder.type == EventTypes.Member:
            membership = builder.content.get("membership", None)
            target = UserID.from_string(builder.state_key)

            if membership in {Membership.JOIN, Membership.INVITE}:
                # If event doesn't include a display name, add one.
                profile = self.hs.get_handlers().profile_handler
                content = builder.content

                try:
                    content["displayname"] = yield profile.get_displayname(target)
                    content["avatar_url"] = yield profile.get_avatar_url(target)
                except Exception as e:
                    logger.info(
                        "Failed to get profile information for %r: %s",
                        target, e
                    )

        if token_id is not None:
            builder.internal_metadata.token_id = token_id

        if txn_id is not None:
            builder.internal_metadata.txn_id = txn_id

        event, context = yield self._create_new_client_event(
            builder=builder,
            prev_event_ids=prev_event_ids,
        )
        defer.returnValue((event, context))

    @defer.inlineCallbacks
    def send_nonmember_event(self, requester, event, context, ratelimit=True):
        """
        Persists and notifies local clients and federation of an event.

        Args:
            event (FrozenEvent) the event to send.
            context (Context) the context of the event.
            ratelimit (bool): Whether to rate limit this send.
            is_guest (bool): Whether the sender is a guest.
        """
        if event.type == EventTypes.Member:
            raise SynapseError(
                500,
                "Tried to send member event through non-member codepath"
            )

        user = UserID.from_string(event.sender)

        assert self.hs.is_mine(user), "User must be our own: %s" % (user,)

        if event.is_state():
            prev_state = self.deduplicate_state_event(event, context)
            if prev_state is not None:
                defer.returnValue(prev_state)

        yield self.handle_new_client_event(
            requester=requester,
            event=event,
            context=context,
            ratelimit=ratelimit,
        )

        if event.type == EventTypes.Message:
            presence = self.hs.get_presence_handler()
            yield presence.bump_presence_active_time(user)

    def deduplicate_state_event(self, event, context):
        """
        Checks whether event is in the latest resolved state in context.

        If so, returns the version of the event in context.
        Otherwise, returns None.
        """
        prev_event = context.current_state.get((event.type, event.state_key))
        if prev_event and event.user_id == prev_event.user_id:
            prev_content = encode_canonical_json(prev_event.content)
            next_content = encode_canonical_json(event.content)
            if prev_content == next_content:
                return prev_event
        return None

    @defer.inlineCallbacks
    def create_and_send_nonmember_event(
        self,
        requester,
        event_dict,
        ratelimit=True,
        txn_id=None
    ):
        """
        Creates an event, then sends it.

        See self.create_event and self.send_nonmember_event.
        """
        event, context = yield self.create_event(
            event_dict,
            token_id=requester.access_token_id,
            txn_id=txn_id
        )
        yield self.send_nonmember_event(
            requester,
            event,
            context,
            ratelimit=ratelimit,
        )
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
            room_id, user_id
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
    def _check_in_room_or_world_readable(self, room_id, user_id):
        try:
            # check_user_was_in_room will return the most recent membership
            # event for the user if:
            #  * The user is a non-guest user, and was ever in the room
            #  * The user is a guest user, and has joined the room
            # else it will throw.
            member_event = yield self.auth.check_user_was_in_room(room_id, user_id)
            defer.returnValue((member_event.membership, member_event.event_id))
            return
        except AuthError:
            visibility = yield self.state_handler.get_current_state(
                room_id, EventTypes.RoomHistoryVisibility, ""
            )
            if (
                visibility and
                visibility.content["history_visibility"] == "world_readable"
            ):
                defer.returnValue((Membership.JOIN, None))
                return
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
            room_id, user_id
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
        key = (
            user_id,
            pagin_config.from_token,
            pagin_config.to_token,
            pagin_config.direction,
            pagin_config.limit,
            as_client_event,
            include_archived,
        )
        now_ms = self.clock.time_msec()
        result = self.snapshot_cache.get(now_ms, key)
        if result is not None:
            return result

        return self.snapshot_cache.set(now_ms, key, self._snapshot_all_rooms(
            user_id, pagin_config, as_client_event, include_archived
        ))

    @defer.inlineCallbacks
    def _snapshot_all_rooms(self, user_id=None, pagin_config=None,
                            as_client_event=True, include_archived=False):

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

        account_data, account_data_by_room = (
            yield self.store.get_account_data_for_user(user_id)
        )

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

                messages = yield filter_events_for_client(
                    self.store, user_id, messages
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

                account_data_events = []
                tags = tags_by_room.get(event.room_id)
                if tags:
                    account_data_events.append({
                        "type": "m.tag",
                        "content": {"tags": tags},
                    })

                account_data = account_data_by_room.get(event.room_id, {})
                for account_data_type, content in account_data.items():
                    account_data_events.append({
                        "type": account_data_type,
                        "content": content,
                    })

                d["account_data"] = account_data_events
            except:
                logger.exception("Failed to get snapshot")

        yield concurrently_execute(handle_room, room_list, 10)

        account_data_events = []
        for account_data_type, content in account_data.items():
            account_data_events.append({
                "type": account_data_type,
                "content": content,
            })

        ret = {
            "rooms": rooms_ret,
            "presence": presence,
            "account_data": account_data_events,
            "receipts": receipt,
            "end": now_token.to_string(),
        }

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def room_initial_sync(self, requester, room_id, pagin_config=None):
        """Capture the a snapshot of a room. If user is currently a member of
        the room this will be what is currently in the room. If the user left
        the room this will be what was in the room when they left.

        Args:
            requester(Requester): The user to get a snapshot for.
            room_id(str): The room to get a snapshot of.
            pagin_config(synapse.streams.config.PaginationConfig):
                The pagination config used to determine how many messages to
                return.
        Raises:
            AuthError if the user wasn't in the room.
        Returns:
            A JSON serialisable dict with the snapshot of the room.
        """

        user_id = requester.user.to_string()

        membership, member_event_id = yield self._check_in_room_or_world_readable(
            room_id, user_id,
        )
        is_peeking = member_event_id is None

        if membership == Membership.JOIN:
            result = yield self._room_initial_sync_joined(
                user_id, room_id, pagin_config, membership, is_peeking
            )
        elif membership == Membership.LEAVE:
            result = yield self._room_initial_sync_parted(
                user_id, room_id, pagin_config, membership, member_event_id, is_peeking
            )

        account_data_events = []
        tags = yield self.store.get_tags_for_room(user_id, room_id)
        if tags:
            account_data_events.append({
                "type": "m.tag",
                "content": {"tags": tags},
            })

        account_data = yield self.store.get_account_data_for_room(user_id, room_id)
        for account_data_type, content in account_data.items():
            account_data_events.append({
                "type": account_data_type,
                "content": content,
            })

        result["account_data"] = account_data_events

        defer.returnValue(result)

    @defer.inlineCallbacks
    def _room_initial_sync_parted(self, user_id, room_id, pagin_config,
                                  membership, member_event_id, is_peeking):
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

        messages = yield filter_events_for_client(
            self.store, user_id, messages, is_peeking=is_peeking
        )

        start_token = StreamToken.START.copy_and_replace("room_key", token[0])
        end_token = StreamToken.START.copy_and_replace("room_key", token[1])

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
                                  membership, is_peeking):
        current_state = yield self.state.get_current_state(
            room_id=room_id,
        )

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

        presence_handler = self.hs.get_presence_handler()

        @defer.inlineCallbacks
        def get_presence():
            states = yield presence_handler.get_states(
                [m.user_id for m in room_members],
                as_event=True,
            )

            defer.returnValue(states)

        @defer.inlineCallbacks
        def get_receipts():
            receipts_handler = self.hs.get_handlers().receipts_handler
            receipts = yield receipts_handler.get_receipts_for_room(
                room_id,
                now_token.receipt_key
            )
            defer.returnValue(receipts)

        presence, receipts, (messages, token) = yield defer.gatherResults(
            [
                get_presence(),
                get_receipts(),
                self.store.get_recent_events_for_room(
                    room_id,
                    limit=limit,
                    end_token=now_token.room_key,
                )
            ],
            consumeErrors=True,
        ).addErrback(unwrapFirstError)

        messages = yield filter_events_for_client(
            self.store, user_id, messages, is_peeking=is_peeking,
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
        if not is_peeking:
            ret["membership"] = membership

        defer.returnValue(ret)

    @defer.inlineCallbacks
    def _create_new_client_event(self, builder, prev_event_ids=None):
        if prev_event_ids:
            prev_events = yield self.store.add_event_hashes(prev_event_ids)
            prev_max_depth = yield self.store.get_max_depth_of_events(prev_event_ids)
            depth = prev_max_depth + 1
        else:
            latest_ret = yield self.store.get_latest_event_ids_and_hashes_in_room(
                builder.room_id,
            )

            if latest_ret:
                depth = max([d for _, _, d in latest_ret]) + 1
            else:
                depth = 1

            prev_events = [
                (event_id, prev_hashes)
                for event_id, prev_hashes, _ in latest_ret
            ]

        builder.prev_events = prev_events
        builder.depth = depth

        state_handler = self.state_handler

        context = yield state_handler.compute_event_context(builder)

        if builder.is_state():
            builder.prev_state = yield self.store.add_event_hashes(
                context.prev_state_events
            )

        yield self.auth.add_auth_events(builder, context)

        signing_key = self.hs.config.signing_key[0]
        add_hashes_and_signatures(
            builder, self.server_name, signing_key
        )

        event = builder.build()

        logger.debug(
            "Created event %s with current state: %s",
            event.event_id, context.current_state,
        )

        defer.returnValue(
            (event, context,)
        )

    @defer.inlineCallbacks
    def handle_new_client_event(
        self,
        requester,
        event,
        context,
        ratelimit=True,
        extra_users=[]
    ):
        # We now need to go and hit out to wherever we need to hit out to.

        if ratelimit:
            self.ratelimit(requester)

        try:
            self.auth.check(event, auth_events=context.current_state)
        except AuthError as err:
            logger.warn("Denying new event %r because %s", event, err)
            raise err

        yield self.maybe_kick_guest_users(event, context.current_state.values())

        if event.type == EventTypes.CanonicalAlias:
            # Check the alias is acually valid (at this time at least)
            room_alias_str = event.content.get("alias", None)
            if room_alias_str:
                room_alias = RoomAlias.from_string(room_alias_str)
                directory_handler = self.hs.get_handlers().directory_handler
                mapping = yield directory_handler.get_association(room_alias)

                if mapping["room_id"] != event.room_id:
                    raise SynapseError(
                        400,
                        "Room alias %s does not point to the room" % (
                            room_alias_str,
                        )
                    )

        federation_handler = self.hs.get_handlers().federation_handler

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.INVITE:
                def is_inviter_member_event(e):
                    return (
                        e.type == EventTypes.Member and
                        e.sender == event.sender
                    )

                event.unsigned["invite_room_state"] = [
                    {
                        "type": e.type,
                        "state_key": e.state_key,
                        "content": e.content,
                        "sender": e.sender,
                    }
                    for k, e in context.current_state.items()
                    if e.type in self.hs.config.room_invite_state_types
                    or is_inviter_member_event(e)
                ]

                invitee = UserID.from_string(event.state_key)
                if not self.hs.is_mine(invitee):
                    # TODO: Can we add signature from remote server in a nicer
                    # way? If we have been invited by a remote server, we need
                    # to get them to sign the event.

                    returned_invite = yield federation_handler.send_invite(
                        invitee.domain,
                        event,
                    )

                    event.unsigned.pop("room_state", None)

                    # TODO: Make sure the signatures actually are correct.
                    event.signatures.update(
                        returned_invite.signatures
                    )

        if event.type == EventTypes.Redaction:
            if self.auth.check_redaction(event, auth_events=context.current_state):
                original_event = yield self.store.get_event(
                    event.redacts,
                    check_redacted=False,
                    get_prev_content=False,
                    allow_rejected=False,
                    allow_none=False
                )
                if event.user_id != original_event.user_id:
                    raise AuthError(
                        403,
                        "You don't have permission to redact events"
                    )

        if event.type == EventTypes.Create and context.current_state:
            raise AuthError(
                403,
                "Changing the room create event is forbidden",
            )

        action_generator = ActionGenerator(self.hs)
        yield action_generator.handle_push_actions_for_event(
            event, context
        )

        (event_stream_id, max_stream_id) = yield self.store.persist_event(
            event, context=context
        )

        # this intentionally does not yield: we don't care about the result
        # and don't need to wait for it.
        preserve_fn(self.hs.get_pusherpool().on_new_notifications)(
            event_stream_id, max_stream_id
        )

        destinations = set()
        for k, s in context.current_state.items():
            try:
                if k[0] == EventTypes.Member:
                    if s.content["membership"] == Membership.JOIN:
                        destinations.add(get_domain_from_id(s.state_key))
            except SynapseError:
                logger.warn(
                    "Failed to get destination from event %s", s.event_id
                )

        @defer.inlineCallbacks
        def _notify():
            yield run_on_reactor()
            self.notifier.on_new_room_event(
                event, event_stream_id, max_stream_id,
                extra_users=extra_users
            )

        preserve_fn(_notify)()

        # If invite, remove room_state from unsigned before sending.
        event.unsigned.pop("invite_room_state", None)

        federation_handler.handle_new_event(
            event, destinations=destinations,
        )
