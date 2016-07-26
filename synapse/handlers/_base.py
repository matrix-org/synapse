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

import logging

from twisted.internet import defer

import synapse.types
from synapse.api.constants import Membership, EventTypes
from synapse.api.errors import LimitExceededError
from synapse.types import UserID


logger = logging.getLogger(__name__)


class BaseHandler(object):
    """
    Common base class for the event handlers.

    Attributes:
        store (synapse.storage.DataStore):
        state_handler (synapse.state.StateHandler):
    """

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.ratelimiter = hs.get_ratelimiter()
        self.clock = hs.get_clock()
        self.hs = hs

        self.server_name = hs.hostname

        self.event_builder_factory = hs.get_event_builder_factory()

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
                self.hs.is_mine_id(state_key)
                and membership == Membership.JOIN
            ):
                return True
        return False

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
                requester = synapse.types.create_requester(
                    target_user, is_guest=True)
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
