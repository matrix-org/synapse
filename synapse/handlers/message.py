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
from synapse.api.errors import AuthError, Codes, SynapseError, LimitExceededError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.events.utils import serialize_event
from synapse.events.validator import EventValidator
from synapse.push.action_generator import ActionGenerator
from synapse.types import (
    UserID, RoomAlias, RoomStreamToken,
)
from synapse.util.async import run_on_reactor, ReadWriteLock, Limiter
from synapse.util.logcontext import preserve_fn
from synapse.util.metrics import measure_func
from synapse.visibility import filter_events_for_client

from ._base import BaseHandler

from canonicaljson import encode_canonical_json

import logging
import random

logger = logging.getLogger(__name__)


class MessageHandler(BaseHandler):

    def __init__(self, hs):
        super(MessageHandler, self).__init__(hs)
        self.hs = hs
        self.state = hs.get_state_handler()
        self.clock = hs.get_clock()
        self.validator = EventValidator()

        self.pagination_lock = ReadWriteLock()

        # We arbitrarily limit concurrent event creation for a room to 5.
        # This is to stop us from diverging history *too* much.
        self.limiter = Limiter(max_count=5)

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
                yield self.hs.get_event_sources().get_current_token_for_room(
                    room_id=room_id
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

        with (yield self.limiter.queue(builder.room_id)):
            self.validator.validate_new(builder)

            if builder.type == EventTypes.Member:
                membership = builder.content.get("membership", None)
                target = UserID.from_string(builder.state_key)

                if membership in {Membership.JOIN, Membership.INVITE}:
                    # If event doesn't include a display name, add one.
                    profile = self.hs.get_handlers().profile_handler
                    content = builder.content

                    try:
                        if "displayname" not in content:
                            content["displayname"] = yield profile.get_displayname(target)
                        if "avatar_url" not in content:
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

        # We check here if we are currently being rate limited, so that we
        # don't do unnecessary work. We check again just before we actually
        # send the event.
        time_now = self.clock.time()
        allowed, time_allowed = self.ratelimiter.send_message(
            event.sender, time_now,
            msg_rate_hz=self.hs.config.rc_messages_per_second,
            burst_count=self.hs.config.rc_message_burst_count,
            update=False,
        )
        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now)),
            )

        user = UserID.from_string(event.sender)

        assert self.hs.is_mine(user), "User must be our own: %s" % (user,)

        if event.is_state():
            prev_state = yield self.deduplicate_state_event(event, context)
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
            # We don't want to block sending messages on any presence code. This
            # matters as sometimes presence code can take a while.
            preserve_fn(presence.bump_presence_active_time)(user)

    @defer.inlineCallbacks
    def deduplicate_state_event(self, event, context):
        """
        Checks whether event is in the latest resolved state in context.

        If so, returns the version of the event in context.
        Otherwise, returns None.
        """
        prev_event_id = context.prev_state_ids.get((event.type, event.state_key))
        prev_event = yield self.store.get_event(prev_event_id, allow_none=True)
        if not prev_event:
            return

        if prev_event and event.user_id == prev_event.user_id:
            prev_content = encode_canonical_json(prev_event.content)
            next_content = encode_canonical_json(event.content)
            if prev_content == next_content:
                defer.returnValue(prev_event)
        return

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

    @measure_func("_create_new_client_event")
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

            # We want to limit the max number of prev events we point to in our
            # new event
            if len(latest_ret) > 10:
                # Sort by reverse depth, so we point to the most recent.
                latest_ret.sort(key=lambda a: -a[2])
                new_latest_ret = latest_ret[:5]

                # We also randomly point to some of the older events, to make
                # sure that we don't completely ignore the older events.
                if latest_ret[5:]:
                    sample_size = min(5, len(latest_ret[5:]))
                    new_latest_ret.extend(random.sample(latest_ret[5:], sample_size))
                latest_ret = new_latest_ret

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
            "Created event %s with state: %s",
            event.event_id, context.prev_state_ids,
        )

        defer.returnValue(
            (event, context,)
        )

    @measure_func("handle_new_client_event")
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
            yield self.auth.check_from_context(event, context)
        except AuthError as err:
            logger.warn("Denying new event %r because %s", event, err)
            raise err

        yield self.maybe_kick_guest_users(event, context)

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

                state_to_include_ids = [
                    e_id
                    for k, e_id in context.current_state_ids.items()
                    if k[0] in self.hs.config.room_invite_state_types
                    or k[0] == EventTypes.Member and k[1] == event.sender
                ]

                state_to_include = yield self.store.get_events(state_to_include_ids)

                event.unsigned["invite_room_state"] = [
                    {
                        "type": e.type,
                        "state_key": e.state_key,
                        "content": e.content,
                        "sender": e.sender,
                    }
                    for e in state_to_include.values()
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
            auth_events_ids = yield self.auth.compute_auth_events(
                event, context.prev_state_ids, for_verification=True,
            )
            auth_events = yield self.store.get_events(auth_events_ids)
            auth_events = {
                (e.type, e.state_key): e for e in auth_events.values()
            }
            if self.auth.check_redaction(event, auth_events=auth_events):
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

        if event.type == EventTypes.Create and context.prev_state_ids:
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

        @defer.inlineCallbacks
        def _notify():
            yield run_on_reactor()
            yield self.notifier.on_new_room_event(
                event, event_stream_id, max_stream_id,
                extra_users=extra_users
            )

        preserve_fn(_notify)()

        # If invite, remove room_state from unsigned before sending.
        event.unsigned.pop("invite_room_state", None)
