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

from synapse.http.servlet import RestServlet
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
        #self.sync_handler = hs.get_handlers().sync_hanlder

    @defer.inlineCallbacks
    def on_GET(self, request):
        user = yield self.auth.get_user_by_req(request)

        timeout = self.parse_integer(request, "timeout", default=0)
        limit = self.parse_integer(request, "limit", default=None)
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
        backfill = self.parse_boolean(request, "backfill", default=True)
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

        # if timeout != 0:
        #   register for updates from the event stream

        #rooms = []

        if gap:
            pass
            # now_stream_token = get_current_stream_token
            # for room_id in get_rooms_for_user(user, filter=filter):
            #   state, events, start, end, limited, published = updates_for_room(
            #       from=since, to=now_stream_token, limit=limit,
            #       anchor_to_start=False
            #   )
            #   rooms[room_id] = (state, events, start, limited, published)
            # next_stream_token = now.
        else:
            pass
            # now_stream_token = get_current_stream_token
            # for room_id in get_rooms_for_user(user, filter=filter)
            #   state, events, start, end, limited, published = updates_for_room(
            #       from=since, to=now_stream_token, limit=limit,
            #       anchor_to_start=False
            #   )
            #   next_stream_token = min(next_stream_token, end)


        response_content = {}

        defer.returnValue((200, response_content))


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
