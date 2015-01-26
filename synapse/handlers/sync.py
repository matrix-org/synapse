# -*- coding: utf-8 -*-
# Copyright 2015 OpenMarket Ltd
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

from ._base import BaseHandler

from synapse.streams.config import PaginationConfig
from synapse.api.constants import Membership

from twisted.internet import defer

import collections
import logging

logger = logging.getLogger(__name__)


SyncConfig = collections.namedtuple("SyncConfig", [
    "user",
    "device",
    "limit",
    "gap",
    "sort",
    "backfill",
    "filter",
])


RoomSyncResult = collections.namedtuple("RoomSyncResult", [
    "room_id",
    "limited",
    "published",
    "events", # dict of event
    "state",
    "prev_batch",
])


class SyncResult(collections.namedtuple("SyncResult", [
    "next_batch", # Token for the next sync
    "private_user_data", # List of private events for the user.
    "public_user_data", # List of public events for all users.
    "rooms", # RoomSyncResult for each room.
])):
    __slots__ = []

    def __nonzero__(self):
        return self.private_user_data or self.public_user_data or self.rooms


class SyncHandler(BaseHandler):

    def __init__(self, hs):
        super(SyncHandler, self).__init__(hs)
        self.event_sources = hs.get_event_sources()
        self.clock = hs.get_clock()

    def wait_for_sync_for_user(self, sync_config, since_token=None, timeout=0):
        if timeout == 0:
            return self.current_sync_for_user(sync_config, since_token)
        else:
            def current_sync_callback(since_token):
                return self.current_sync_for_user(
                    self, since_token, sync_config
                )
            return self.notifier.wait_for_events(
                sync_config.filter, since_token, current_sync_callback
            )

    def current_sync_for_user(self, sync_config, since_token=None):
        if since_token is None:
            return self.initial_sync(sync_config)
        else:
            return self.incremental_sync(sync_config)

    @defer.inlineCallbacks
    def initial_sync(self, sync_config):
        if sync_config.sort == "timeline,desc":
            # TODO(mjark): Handle going through events in reverse order?.
            # What does "most recent events" mean when applying the limits mean
            # in this case?
            raise NotImplementedError()

        now_token = yield self.event_sources.get_current_token()

        presence_stream = self.event_sources.sources["presence"]
        # TODO (mjark): This looks wrong, shouldn't we be getting the presence
        # UP to the present rather than after the present?
        pagination_config = PaginationConfig(from_token=now_token)
        presence, _ = yield presence_stream.get_pagination_rows(
            user=sync_config.user,
            pagination_config=pagination_config.get_source_config("presence"),
            key=None
        )
        room_list = yield self.store.get_rooms_for_user_where_membership_is(
            user_id=sync_config.user.to_string(),
            membership_list=[Membership.INVITE, Membership.JOIN]
        )

        # TODO (mjark): Does public mean "published"?
        published_rooms = yield self.store.get_rooms(is_public=True)
        published_room_ids = set(r["room_id"] for r in published_rooms)

        rooms = []
        for event in room_list:
            #TODO (mjark): Apply the event filter in sync_config.
            recent_events, token = yield self.store.get_recent_events_for_room(
                event.room_id,
                limit=sync_config.limit,
                end_token=now_token.room_key,
            )
            prev_batch_token = now_token.copy_and_replace("room_key", token[0])
            current_state_events = yield self.state_handler.get_current_state(
                event.room_id
            )

            rooms.append(RoomSyncResult(
                room_id=event.room_id,
                published=event.room_id in published_room_ids,
                events=recent_events,
                prev_batch=prev_batch_token,
                state=current_state_events,
                limited=True,
            ))

        defer.returnValue(SyncResult(
            public_user_data=presence,
            private_user_data=[],
            rooms=rooms,
            next_batch=now_token,
        ))


    @defer.inlineCallbacks
    def incremental_sync(self, sync_config):
        pass
