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
from typing import TYPE_CHECKING, Optional

import synapse.state
import synapse.storage
import synapse.types
from synapse.api.constants import EventTypes, Membership
from synapse.api.ratelimiting import Ratelimiter
from synapse.types import UserID

if TYPE_CHECKING:
    from synapse.app.homeserver import HomeServer

logger = logging.getLogger(__name__)


class BaseHandler:
    """
    Common base class for the event handlers.
    """

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()  # type: synapse.storage.DataStore
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.state_handler = hs.get_state_handler()  # type: synapse.state.StateHandler
        self.distributor = hs.get_distributor()
        self.clock = hs.get_clock()
        self.hs = hs

        # The rate_hz and burst_count are overridden on a per-user basis
        self.request_ratelimiter = Ratelimiter(
            clock=self.clock, rate_hz=0, burst_count=0
        )
        self._rc_message = self.hs.config.rc_message

        # Check whether ratelimiting room admin message redaction is enabled
        # by the presence of rate limits in the config
        if self.hs.config.rc_admin_redaction:
            self.admin_redaction_ratelimiter = Ratelimiter(
                clock=self.clock,
                rate_hz=self.hs.config.rc_admin_redaction.per_second,
                burst_count=self.hs.config.rc_admin_redaction.burst_count,
            )  # type: Optional[Ratelimiter]
        else:
            self.admin_redaction_ratelimiter = None

        self.server_name = hs.hostname

        self.event_builder_factory = hs.get_event_builder_factory()

    async def ratelimit(self, requester, update=True, is_admin_redaction=False):
        """Ratelimits requests.

        Args:
            requester (Requester)
            update (bool): Whether to record that a request is being processed.
                Set to False when doing multiple checks for one request (e.g.
                to check up front if we would reject the request), and set to
                True for the last call for a given request.
            is_admin_redaction (bool): Whether this is a room admin/moderator
                redacting an event. If so then we may apply different
                ratelimits depending on config.

        Raises:
            LimitExceededError if the request should be ratelimited
        """
        user_id = requester.user.to_string()

        # The AS user itself is never rate limited.
        app_service = self.store.get_app_service_by_user_id(user_id)
        if app_service is not None:
            return  # do not ratelimit app service senders

        # Disable rate limiting of users belonging to any AS that is configured
        # not to be rate limited in its registration file (rate_limited: true|false).
        if requester.app_service and not requester.app_service.is_rate_limited():
            return

        messages_per_second = self._rc_message.per_second
        burst_count = self._rc_message.burst_count

        # Check if there is a per user override in the DB.
        override = await self.store.get_ratelimit_for_user(user_id)
        if override:
            # If overridden with a null Hz then ratelimiting has been entirely
            # disabled for the user
            if not override.messages_per_second:
                return

            messages_per_second = override.messages_per_second
            burst_count = override.burst_count

        if is_admin_redaction and self.admin_redaction_ratelimiter:
            # If we have separate config for admin redactions, use a separate
            # ratelimiter as to not have user_ids clash
            self.admin_redaction_ratelimiter.ratelimit(user_id, update=update)
        else:
            # Override rate and burst count per-user
            self.request_ratelimiter.ratelimit(
                user_id,
                rate_hz=messages_per_second,
                burst_count=burst_count,
                update=update,
            )

    async def maybe_kick_guest_users(self, event, context=None):
        # Technically this function invalidates current_state by changing it.
        # Hopefully this isn't that important to the caller.
        if event.type == EventTypes.GuestAccess:
            guest_access = event.content.get("guest_access", "forbidden")
            if guest_access != "can_join":
                if context:
                    current_state_ids = await context.get_current_state_ids()
                    current_state_dict = await self.store.get_events(
                        list(current_state_ids.values())
                    )
                    current_state = list(current_state_dict.values())
                else:
                    current_state_map = await self.state_handler.get_current_state(
                        event.room_id
                    )
                    current_state = list(current_state_map.values())

                logger.info("maybe_kick_guest_users %r", current_state)
                await self.kick_guest_users(current_state)

    async def kick_guest_users(self, current_state):
        for member_event in current_state:
            try:
                if member_event.type != EventTypes.Member:
                    continue

                target_user = UserID.from_string(member_event.state_key)
                if not self.hs.is_mine(target_user):
                    continue

                if member_event.content["membership"] not in {
                    Membership.JOIN,
                    Membership.INVITE,
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
                    target_user, is_guest=True, authenticated_entity=self.server_name
                )
                handler = self.hs.get_room_member_handler()
                await handler.update_membership(
                    requester,
                    target_user,
                    member_event.room_id,
                    "leave",
                    ratelimit=False,
                    require_consent=False,
                )
            except Exception as e:
                logger.exception("Error kicking guest user: %s" % (e,))
