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

from synapse.api.errors import LimitExceededError, SynapseError, AuthError
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.api.constants import Membership, EventTypes
from synapse.types import UserID, RoomAlias, Requester
from synapse.push.action_generator import ActionGenerator

from synapse.util.logcontext import PreserveLoggingContext, preserve_fn

import logging


logger = logging.getLogger(__name__)


VISIBILITY_PRIORITY = (
    "world_readable",
    "shared",
    "invited",
    "joined",
)


MEMBERSHIP_PRIORITY = (
    Membership.JOIN,
    Membership.INVITE,
    Membership.KNOCK,
    Membership.LEAVE,
    Membership.BAN,
)


class BaseHandler(object):
    """
    Common base class for the event handlers.

    Attributes:
        store (synapse.storage.events.StateStore):
        state_handler (synapse.state.StateHandler):
    """

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.ratelimiter = hs.get_ratelimiter()
        self.clock = hs.get_clock()
        self.hs = hs

        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname

        self.event_builder_factory = hs.get_event_builder_factory()

    @defer.inlineCallbacks
    def filter_events_for_clients(self, user_tuples, events, event_id_to_state):
        """ Returns dict of user_id -> list of events that user is allowed to
        see.

        Args:
            user_tuples (str, bool): (user id, is_peeking) for each user to be
                checked. is_peeking should be true if:
                * the user is not currently a member of the room, and:
                * the user has not been a member of the room since the
                given events
            events ([synapse.events.EventBase]): list of events to filter
        """
        forgotten = yield defer.gatherResults([
            self.store.who_forgot_in_room(
                room_id,
            )
            for room_id in frozenset(e.room_id for e in events)
        ], consumeErrors=True)

        # Set of membership event_ids that have been forgotten
        event_id_forgotten = frozenset(
            row["event_id"] for rows in forgotten for row in rows
        )

        def allowed(event, user_id, is_peeking):
            """
            Args:
                event (synapse.events.EventBase): event to check
                user_id (str)
                is_peeking (bool)
            """
            state = event_id_to_state[event.event_id]

            # get the room_visibility at the time of the event.
            visibility_event = state.get((EventTypes.RoomHistoryVisibility, ""), None)
            if visibility_event:
                visibility = visibility_event.content.get("history_visibility", "shared")
            else:
                visibility = "shared"

            if visibility not in VISIBILITY_PRIORITY:
                visibility = "shared"

            # if it was world_readable, it's easy: everyone can read it
            if visibility == "world_readable":
                return True

            # Always allow history visibility events on boundaries. This is done
            # by setting the effective visibility to the least restrictive
            # of the old vs new.
            if event.type == EventTypes.RoomHistoryVisibility:
                prev_content = event.unsigned.get("prev_content", {})
                prev_visibility = prev_content.get("history_visibility", None)

                if prev_visibility not in VISIBILITY_PRIORITY:
                    prev_visibility = "shared"

                new_priority = VISIBILITY_PRIORITY.index(visibility)
                old_priority = VISIBILITY_PRIORITY.index(prev_visibility)
                if old_priority < new_priority:
                    visibility = prev_visibility

            # likewise, if the event is the user's own membership event, use
            # the 'most joined' membership
            membership = None
            if event.type == EventTypes.Member and event.state_key == user_id:
                membership = event.content.get("membership", None)
                if membership not in MEMBERSHIP_PRIORITY:
                    membership = "leave"

                prev_content = event.unsigned.get("prev_content", {})
                prev_membership = prev_content.get("membership", None)
                if prev_membership not in MEMBERSHIP_PRIORITY:
                    prev_membership = "leave"

                new_priority = MEMBERSHIP_PRIORITY.index(membership)
                old_priority = MEMBERSHIP_PRIORITY.index(prev_membership)
                if old_priority < new_priority:
                    membership = prev_membership

            # otherwise, get the user's membership at the time of the event.
            if membership is None:
                membership_event = state.get((EventTypes.Member, user_id), None)
                if membership_event:
                    if membership_event.event_id not in event_id_forgotten:
                        membership = membership_event.membership

            # if the user was a member of the room at the time of the event,
            # they can see it.
            if membership == Membership.JOIN:
                return True

            if visibility == "joined":
                # we weren't a member at the time of the event, so we can't
                # see this event.
                return False

            elif visibility == "invited":
                # user can also see the event if they were *invited* at the time
                # of the event.
                return membership == Membership.INVITE

            else:
                # visibility is shared: user can also see the event if they have
                # become a member since the event
                #
                # XXX: if the user has subsequently joined and then left again,
                # ideally we would share history up to the point they left. But
                # we don't know when they left.
                return not is_peeking

        defer.returnValue({
            user_id: [
                event
                for event in events
                if allowed(event, user_id, is_peeking)
            ]
            for user_id, is_peeking in user_tuples
        })

    @defer.inlineCallbacks
    def _filter_events_for_client(self, user_id, events, is_peeking=False):
        """
        Check which events a user is allowed to see

        Args:
            user_id(str): user id to be checked
            events([synapse.events.EventBase]): list of events to be checked
            is_peeking(bool): should be True if:
              * the user is not currently a member of the room, and:
              * the user has not been a member of the room since the given
                events

        Returns:
            [synapse.events.EventBase]
        """
        types = (
            (EventTypes.RoomHistoryVisibility, ""),
            (EventTypes.Member, user_id),
        )
        event_id_to_state = yield self.store.get_state_for_events(
            frozenset(e.event_id for e in events),
            types=types
        )
        res = yield self.filter_events_for_clients(
            [(user_id, is_peeking)], events, event_id_to_state
        )
        defer.returnValue(res.get(user_id, []))

    def ratelimit(self, requester):
        time_now = self.clock.time()
        allowed, time_allowed = self.ratelimiter.send_message(
            requester.user.to_string(), time_now,
            msg_rate_hz=self.hs.config.rc_messages_per_second,
            burst_count=self.hs.config.rc_message_burst_count,
        )
        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now)),
            )

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

        add_hashes_and_signatures(
            builder, self.server_name, self.signing_key
        )

        event = builder.build()

        logger.debug(
            "Created event %s with current state: %s",
            event.event_id, context.current_state,
        )

        defer.returnValue(
            (event, context,)
        )

    def is_host_in_room(self, current_state):
        room_members = [
            (state_key, event.membership)
            for ((event_type, state_key), event) in current_state.items()
            if event_type == EventTypes.Member
        ]
        if len(room_members) == 0:
            # Have we just created the room, and is this about to be the very
            # first member event?
            create_event = current_state.get(("m.room.create", ""))
            if create_event:
                return True
        for (state_key, membership) in room_members:
            if (
                UserID.from_string(state_key).domain == self.hs.hostname
                and membership == Membership.JOIN
            ):
                return True
        return False

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
            event, context, self
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
                        destinations.add(
                            UserID.from_string(s.state_key).domain
                        )
            except SynapseError:
                logger.warn(
                    "Failed to get destination from event %s", s.event_id
                )

        with PreserveLoggingContext():
            # Don't block waiting on waking up all the listeners.
            self.notifier.on_new_room_event(
                event, event_stream_id, max_stream_id,
                extra_users=extra_users
            )

        # If invite, remove room_state from unsigned before sending.
        event.unsigned.pop("invite_room_state", None)

        federation_handler.handle_new_event(
            event, destinations=destinations,
        )

    @defer.inlineCallbacks
    def maybe_kick_guest_users(self, event, current_state):
        # Technically this function invalidates current_state by changing it.
        # Hopefully this isn't that important to the caller.
        if event.type == EventTypes.GuestAccess:
            guest_access = event.content.get("guest_access", "forbidden")
            if guest_access != "can_join":
                yield self.kick_guest_users(current_state)

    @defer.inlineCallbacks
    def kick_guest_users(self, current_state):
        for member_event in current_state:
            try:
                if member_event.type != EventTypes.Member:
                    continue

                target_user = UserID.from_string(member_event.state_key)
                if not self.hs.is_mine(target_user):
                    continue

                if member_event.content["membership"] not in {
                    Membership.JOIN,
                    Membership.INVITE
                }:
                    continue

                if (
                    "kind" not in member_event.content
                    or member_event.content["kind"] != "guest"
                ):
                    continue

                # We make the user choose to leave, rather than have the
                # event-sender kick them. This is partially because we don't
                # need to worry about power levels, and partially because guest
                # users are a concept which doesn't hugely work over federation,
                # and having homeservers have their own users leave keeps more
                # of that decision-making and control local to the guest-having
                # homeserver.
                requester = Requester(target_user, "", True)
                handler = self.hs.get_handlers().room_member_handler
                yield handler.update_membership(
                    requester,
                    target_user,
                    member_event.room_id,
                    "leave",
                    ratelimit=False,
                )
            except Exception as e:
                logger.warn("Error kicking guest user: %s" % (e,))
