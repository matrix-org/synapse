# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from synapse.api.errors import cs_error, Codes

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

    def ratelimit(self, user_id):
        time_now = self.clock.time()
        allowed, time_allowed = self.ratelimiter.send_message(
            user_id, time_now,
            msg_rate_hz=self.hs.config.rc_messages_per_second,
            burst_count=self.hs.config.rc_messsage_burst_count,
        )
        if not allowed:
            raise cs_error(
                "Limit exceeded",
                Codes.M_LIMIT_EXCEEDED,
                retry_after_ms=1000*(time_allowed - time_now),
            )


class BaseRoomHandler(BaseHandler):

    @defer.inlineCallbacks
    def _on_new_room_event(self, event, snapshot, extra_destinations=[],
                           extra_users=[]):
        snapshot.fill_out_prev_events(event)

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
