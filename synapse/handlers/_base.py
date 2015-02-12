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

from synapse.api.errors import LimitExceededError, SynapseError
from synapse.util.async import run_on_reactor
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.api.constants import Membership, EventTypes
from synapse.types import UserID

import logging


logger = logging.getLogger(__name__)


class BaseHandler(object):

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

    def ratelimit(self, user_id):
        time_now = self.clock.time()
        allowed, time_allowed = self.ratelimiter.send_message(
            user_id, time_now,
            msg_rate_hz=self.hs.config.rc_messages_per_second,
            burst_count=self.hs.config.rc_message_burst_count,
        )
        if not allowed:
            raise LimitExceededError(
                retry_after_ms=int(1000*(time_allowed - time_now)),
            )

    @defer.inlineCallbacks
    def _create_new_client_event(self, builder):
        yield run_on_reactor()

        latest_ret = yield self.store.get_latest_events_in_room(
            builder.room_id,
        )

        if latest_ret:
            depth = max([d for _, _, d in latest_ret]) + 1
        else:
            depth = 1

        prev_events = [(e, h) for e, h, _ in latest_ret]

        builder.prev_events = prev_events
        builder.depth = depth

        state_handler = self.state_handler

        context = yield state_handler.compute_event_context(builder)

        if builder.is_state():
            builder.prev_state = context.prev_state_events

        yield self.auth.add_auth_events(builder, context)

        add_hashes_and_signatures(
            builder, self.server_name, self.signing_key
        )

        event = builder.build()

        logger.debug(
            "Created event %s with auth_events: %s, current state: %s",
            event.event_id, context.auth_events, context.current_state,
        )

        defer.returnValue(
            (event, context,)
        )

    @defer.inlineCallbacks
    def handle_new_client_event(self, event, context, extra_destinations=[],
                                extra_users=[], suppress_auth=False):
        yield run_on_reactor()

        # We now need to go and hit out to wherever we need to hit out to.

        if not suppress_auth:
            self.auth.check(event, auth_events=context.auth_events)

        yield self.store.persist_event(event, context=context)

        federation_handler = self.hs.get_handlers().federation_handler

        if event.type == EventTypes.Member:
            if event.content["membership"] == Membership.INVITE:
                invitee = UserID.from_string(event.state_key)
                if not self.hs.is_mine(invitee):
                    # TODO: Can we add signature from remote server in a nicer
                    # way? If we have been invited by a remote server, we need
                    # to get them to sign the event.
                    returned_invite = yield federation_handler.send_invite(
                        invitee.domain,
                        event,
                    )

                    # TODO: Make sure the signatures actually are correct.
                    event.signatures.update(
                        returned_invite.signatures
                    )

        destinations = set(extra_destinations)
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

        yield self.notifier.on_new_room_event(event, extra_users=extra_users)

        yield federation_handler.handle_new_event(
            event, destinations=destinations,
        )
