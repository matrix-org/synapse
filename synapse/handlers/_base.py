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
from synapse.api.constants import EventTypes, Membership
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

    @defer.inlineCallbacks
    def ratelimit(self, requester, update=True):
        """Ratelimits requests.

        Args:
            requester (Requester)
            update (bool): Whether to record that a request is being processed.
                Set to False when doing multiple checks for one request (e.g.
                to check up front if we would reject the request), and set to
                True for the last call for a given request.

        Raises:
            LimitExceededError if the request should be ratelimited
        """
        time_now = self.clock.time()
        user_id = requester.user.to_string()

        # The AS user itself is never rate limited.
        app_service = self.store.get_app_service_by_user_id(user_id)
        if app_service is not None:
            return  # do not ratelimit app service senders

        # Disable rate limiting of users belonging to any AS that is configured
        # not to be rate limited in its registration file (rate_limited: true|false).
        if requester.app_service and not requester.app_service.is_rate_limited():
            return

        # Check if there is a per user override in the DB.
        override = yield self.store.get_ratelimit_for_user(user_id)
        if override:
            # If overriden with a null Hz then ratelimiting has been entirely
            # disabled for the user
            if not override.messages_per_second:
                return

            messages_per_second = override.messages_per_second
            burst_count = override.burst_count
        else:
            messages_per_second = self.hs.config.rc_messages_per_second
            burst_count = self.hs.config.rc_message_burst_count

        allowed, time_allowed = self.ratelimiter.send_message(
            user_id, time_now,
            msg_rate_hz=messages_per_second,
            burst_count=burst_count,
            update=update,
        )
        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now)),
            )

    @defer.inlineCallbacks
    def maybe_kick_guest_users(self, event, context=None):
        # Technically this function invalidates current_state by changing it.
        # Hopefully this isn't that important to the caller.
        if event.type == EventTypes.GuestAccess:
            guest_access = event.content.get("guest_access", "forbidden")
            if guest_access != "can_join":
                if context:
                    current_state_ids = yield context.get_current_state_ids(self.store)
                    current_state = yield self.store.get_events(
                        list(current_state_ids.values())
                    )
                else:
                    current_state = yield self.state_handler.get_current_state(
                        event.room_id
                    )

                current_state = list(current_state.values())

                logger.info("maybe_kick_guest_users %r", current_state)
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
                handler = self.hs.get_room_member_handler()
                yield handler.update_membership(
                    requester,
                    target_user,
                    member_event.room_id,
                    "leave",
                    ratelimit=False,
                )
            except Exception as e:
                logger.warn("Error kicking guest user: %s" % (e,))
