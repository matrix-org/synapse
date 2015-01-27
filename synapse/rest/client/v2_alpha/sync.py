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

from twisted.internet import defer

from synapse.http.servlet import RestServlet
from synapse.handlers.sync import SyncConfig
from synapse.types import StreamToken
from synapse.events.utils import serialize_event
from ._base import client_v2_pattern

import logging

logger = logging.getLogger(__name__)


class SyncRestServlet(RestServlet):
    """

    GET parameters::
        timeout(int): How long to wait for new events in milliseconds.
        limit(int): Maxiumum number of events per room to return.
        gap(bool): Create gaps the message history if limit is exceeded to
            ensure that the client has the most recent messages. Defaults to
            "true".
        sort(str,str): tuple of sort key (e.g. "timeline") and direction
            (e.g. "asc", "desc"). Defaults to "timeline,asc".
        since(batch_token): Batch token when asking for incremental deltas.
        set_presence(str): What state the device presence should be set to.
            default is "online".
        backfill(bool): Should the HS request message history from other
            servers. This may take a long time making it unsuitable for clients
            expecting a prompt response. Defaults to "true".
        filter(filter_id): A filter to apply to the events returned.
        filter_*: Filter override parameters.

    Response JSON::
        {
            "next_batch": // batch token for the next /sync
            "private_user_data": // private events for this user.
            "public_user_data": // public events for all users including the
                                // public events for this user.
            "rooms": [{ // List of rooms with updates.
                "room_id": // Id of the room being updated
                "limited": // Was the per-room event limit exceeded?
                "published": // Is the room published by our HS?
                "event_map": // Map of EventID -> event JSON.
                "events": { // The recent events in the room if gap is "true"
                            // otherwise the next events in the room.
                    "batch": [] // list of EventIDs in the "event_map".
                    "prev_batch": // back token for getting previous events.
                }
                "state": [] // list of EventIDs updating the current state to
                            // be what it should be at the end of the batch.
            }]
        }
    """

    PATTERN = client_v2_pattern("/sync$")
    ALLOWED_SORT = set(["timeline,asc", "timeline,desc"])
    ALLOWED_PRESENCE = set(["online", "offline", "idle"])

    def __init__(self, hs):
        super(SyncRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self.sync_handler = hs.get_handlers().sync_handler
        self.clock = hs.get_clock()

    @defer.inlineCallbacks
    def on_GET(self, request):
        user = yield self.auth.get_user_by_req(request)

        timeout = self.parse_integer(request, "timeout", default=0)
        limit = self.parse_integer(request, "limit", required=True)
        gap = self.parse_boolean(request, "gap", default=True)
        sort = self.parse_string(
            request, "sort", default="timeline,asc",
            allowed_values=self.ALLOWED_SORT
        )
        since = self.parse_string(request, "since")
        set_presence = self.parse_string(
            request, "set_presence", default="online",
            allowed_values=self.ALLOWED_PRESENCE
        )
        backfill = self.parse_boolean(request, "backfill", default=False)
        filter_id = self.parse_string(request, "filter", default=None)

        logger.info(
            "/sync: user=%r, timeout=%r, limit=%r, gap=%r, sort=%r, since=%r,"
            " set_presence=%r, backfill=%r, filter_id=%r" % (
                user, timeout, limit, gap, sort, since, set_presence,
                backfill, filter_id
            )
        )

        # TODO(mjark): Load filter and apply overrides.
        # filter = self.filters.load_fitler(filter_id_str)
        # filter = filter.apply_overrides(http_request)
        # if filter.matches(event):
        #   # stuff

        sync_config = SyncConfig(
            user=user,
            device="TODO",  # TODO(mjark) Get the device_id from access_token
            gap=gap,
            limit=limit,
            sort=sort,
            backfill=backfill,
            filter="TODO",  # TODO(mjark) Add the filter to the config.
        )

        if since is not None:
            since_token = StreamToken.from_string(since)
        else:
            since_token = None

        sync_result = yield self.sync_handler.wait_for_sync_for_user(
            sync_config, since_token=since_token, timeout=timeout
        )

        time_now = self.clock.time_msec()

        response_content = {
            "public_user_data": self.encode_events(
                sync_result.public_user_data, filter, time_now
            ),
            "private_user_data": self.encode_events(
                sync_result.private_user_data, filter, time_now
            ),
            "rooms": self.encode_rooms(sync_result.rooms, filter, time_now),
            "next_batch": sync_result.next_batch.to_string(),
        }

        defer.returnValue((200, response_content))

    def encode_events(self, events, filter, time_now):
        return [self.encode_event(event, filter, time_now) for event in events]

    @staticmethod
    def encode_event(event, filter, time_now):
        # TODO(mjark): Respect formatting requirements in the filter.
        return serialize_event(event, time_now)

    def encode_rooms(self, rooms, filter, time_now):
        return [self.encode_room(room, filter, time_now) for room in rooms]

    @staticmethod
    def encode_room(room, filter, time_now):
        event_map = {}
        state_event_ids = []
        recent_event_ids = []
        for event in room.state:
            # TODO(mjark): Respect formatting requirements in the filter.
            event_map[event.event_id] = serialize_event(
                event, time_now, strip_ids=True
            )
            state_event_ids.append(event.event_id)

        for event in room.events:
            # TODO(mjark): Respect formatting requirements in the filter.
            event_map[event.event_id] = serialize_event(
                event, time_now, strip_ids=True
            )
            recent_event_ids.append(event.event_id)
        return {
            "room_id": room.room_id,
            "event_map": event_map,
            "events": {
                "batch": recent_event_ids,
                "prev_batch": room.prev_batch.to_string(),
            },
            "state": state_event_ids,
            "limited": room.limited,
            "published": room.published,
        }


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
