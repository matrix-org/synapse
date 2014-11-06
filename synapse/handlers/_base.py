# -*- coding: utf-8 -*-
# Copyright 2014 OpenMarket Ltd
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

from synapse.api.errors import LimitExceededError
from synapse.util.async import run_on_reactor
from synapse.crypto.event_signing import add_hashes_and_signatures
from synapse.api.events.room import (
    RoomCreateEvent, RoomMemberEvent, RoomPowerLevelsEvent, RoomJoinRulesEvent,
)
from synapse.api.constants import Membership, JoinRules
from syutil.base64util import encode_base64

import logging


logger = logging.getLogger(__name__)


class BaseHandler(object):

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.event_factory = hs.get_event_factory()
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.room_lock = hs.get_room_lock_manager()
        self.state_handler = hs.get_state_handler()
        self.distributor = hs.get_distributor()
        self.ratelimiter = hs.get_ratelimiter()
        self.clock = hs.get_clock()
        self.hs = hs

        self.signing_key = hs.config.signing_key[0]
        self.server_name = hs.hostname

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
    def _add_auth(self, event):
        if event.type == RoomCreateEvent.TYPE:
            event.auth_events = []
            return

        auth_events = []

        key = (RoomPowerLevelsEvent.TYPE, "", )
        power_level_event = event.old_state_events.get(key)

        if power_level_event:
            auth_events.append(power_level_event.event_id)

        key = (RoomJoinRulesEvent.TYPE, "", )
        join_rule_event = event.old_state_events.get(key)

        key = (RoomMemberEvent.TYPE, event.user_id, )
        member_event = event.old_state_events.get(key)

        if join_rule_event:
            join_rule = join_rule_event.content.get("join_rule")
            is_public = join_rule == JoinRules.PUBLIC if join_rule else False

            if event.type == RoomMemberEvent.TYPE:
                if event.content["membership"] == Membership.JOIN:
                    if is_public:
                        auth_events.append(join_rule_event.event_id)
                elif member_event:
                    auth_events.append(member_event.event_id)

        if member_event:
            if member_event.content["membership"] == Membership.JOIN:
                auth_events.append(member_event.event_id)

        hashes = yield self.store.get_event_reference_hashes(
            auth_events
        )
        hashes = [
            {
                k: encode_base64(v) for k, v in h.items()
                if k == "sha256"
            }
            for h in hashes
        ]
        event.auth_events = zip(auth_events, hashes)

    @defer.inlineCallbacks
    def _on_new_room_event(self, event, snapshot, extra_destinations=[],
                           extra_users=[], suppress_auth=False):
        yield run_on_reactor()

        snapshot.fill_out_prev_events(event)

        yield self.state_handler.annotate_state_groups(event)

        yield self._add_auth(event)

        logger.debug("Signing event...")

        add_hashes_and_signatures(
            event, self.server_name, self.signing_key
        )

        logger.debug("Signed event.")

        if not suppress_auth:
            logger.debug("Authing...")
            self.auth.check(event, raises=True)
            logger.debug("Authed")
        else:
            logger.debug("Suppressed auth.")

        yield self.store.persist_event(event)

        destinations = set(extra_destinations)
        # Send a PDU to all hosts who have joined the room.
        destinations.update((yield self.store.get_joined_hosts_for_room(
            event.room_id
        )))
        event.destinations = list(destinations)

        self.notifier.on_new_room_event(event, extra_users=extra_users)

        federation_handler = self.hs.get_handlers().federation_handler
        yield federation_handler.handle_new_event(event, snapshot)
