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

from synapse.http.servlet import (
    RestServlet, parse_string, parse_integer, parse_boolean
)
from synapse.handlers.sync import SyncConfig
from synapse.types import StreamToken
from synapse.events.utils import (
    serialize_event, format_event_for_client_v2_without_event_id,
)
from synapse.api.filtering import FilterCollection
from ._base import client_v2_pattern

import copy
import logging

logger = logging.getLogger(__name__)


class SyncRestServlet(RestServlet):
    """

    GET parameters::
        timeout(int): How long to wait for new events in milliseconds.
        since(batch_token): Batch token when asking for incremental deltas.
        set_presence(str): What state the device presence should be set to.
            default is "online".
        filter(filter_id): A filter to apply to the events returned.

    Response JSON::
        {
          "next_batch": // batch token for the next /sync
          "presence": // presence data for the user.
          "rooms": {
            "joined": { // Joined rooms being updated.
              "${room_id}": { // Id of the room being updated
                "event_map": // Map of EventID -> event JSON.
                "timeline": { // The recent events in the room if gap is "true"
                  "limited": // Was the per-room event limit exceeded?
                             // otherwise the next events in the room.
                  "events": [] // list of EventIDs in the "event_map".
                  "prev_batch": // back token for getting previous events.
                }
                "state": {"events": []} // list of EventIDs updating the
                                        // current state to be what it should
                                        // be at the end of the batch.
                "ephemeral": {"events": []} // list of event objects
              }
            },
            "invited": {}, // Invited rooms being updated.
            "archived": {} // Archived rooms being updated.
          }
        }
    """

    PATTERN = client_v2_pattern("/sync$")
    ALLOWED_PRESENCE = set(["online", "offline"])

    def __init__(self, hs):
        super(SyncRestServlet, self).__init__()
        self.auth = hs.get_auth()
        self.event_stream_handler = hs.get_handlers().event_stream_handler
        self.sync_handler = hs.get_handlers().sync_handler
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()

    @defer.inlineCallbacks
    def on_GET(self, request):
        user, token_id, _ = yield self.auth.get_user_by_req(request)

        timeout = parse_integer(request, "timeout", default=0)
        since = parse_string(request, "since")
        set_presence = parse_string(
            request, "set_presence", default="online",
            allowed_values=self.ALLOWED_PRESENCE
        )
        filter_id = parse_string(request, "filter", default=None)
        full_state = parse_boolean(request, "full_state", default=False)

        logger.info(
            "/sync: user=%r, timeout=%r, since=%r,"
            " set_presence=%r, filter_id=%r" % (
                user, timeout, since, set_presence, filter_id
            )
        )

        try:
            filter = yield self.filtering.get_user_filter(
                user.localpart, filter_id
            )
        except:
            filter = FilterCollection({})

        sync_config = SyncConfig(
            user=user,
            filter=filter,
        )

        if since is not None:
            since_token = StreamToken.from_string(since)
        else:
            since_token = None

        if set_presence == "online":
            yield self.event_stream_handler.started_stream(user)

        try:
            sync_result = yield self.sync_handler.wait_for_sync_for_user(
                sync_config, since_token=since_token, timeout=timeout,
                full_state=full_state
            )
        finally:
            if set_presence == "online":
                self.event_stream_handler.stopped_stream(user)

        time_now = self.clock.time_msec()

        joined = self.encode_joined(
            sync_result.joined, filter, time_now, token_id
        )

        invited = self.encode_invited(
            sync_result.invited, filter, time_now, token_id
        )

        archived = self.encode_archived(
            sync_result.archived, filter, time_now, token_id
        )

        response_content = {
            "presence": self.encode_presence(
                sync_result.presence, filter, time_now
            ),
            "rooms": {
                "joined": joined,
                "invited": invited,
                "archived": archived,
            },
            "next_batch": sync_result.next_batch.to_string(),
        }

        defer.returnValue((200, response_content))

    def encode_presence(self, events, filter, time_now):
        formatted = []
        for event in events:
            event = copy.deepcopy(event)
            event['sender'] = event['content'].pop('user_id')
            formatted.append(event)
        return {"events": filter.filter_presence(formatted)}


    def encode_joined(self, rooms, filter, time_now, token_id):
        """
        Encode the joined rooms in a sync result

        :param list[synapse.handlers.sync.JoinedSyncResult] rooms: list of sync
            results for rooms this user is joined to
        :param FilterCollection filter: filters to apply to the results
        :param int time_now: current time - used as a baseline for age
            calculations
        :param int token_id: ID of the user's auth token - used for namespacing
            of transaction IDs

        :return: the joined rooms list, in our response format
        :rtype: dict[str, dict[str, object]]
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = self.encode_room(
                room, filter, time_now, token_id
            )

        return joined


    def encode_invited(self, rooms, filter, time_now, token_id):
        """
        Encode the invited rooms in a sync result

        :param list[synapse.handlers.sync.InvitedSyncResult] rooms: list of
             sync results for rooms this user is joined to
        :param FilterCollection filter: filters to apply to the results
        :param int time_now: current time - used as a baseline for age
            calculations
        :param int token_id: ID of the user's auth token - used for namespacing
            of transaction IDs

        :return: the invited rooms list, in our response format
        :rtype: dict[str, dict[str, object]]
        """
        invited = {}
        for room in rooms:
            invite = serialize_event(
                room.invite, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_event_id,
            )
            invited_state = invite.get("unsigned", {}).pop("invite_room_state", [])
            invited_state.append(invite)
            invited[room.room_id] = {
                "invite_state": {"events": invited_state}
            }

        return invited

    def encode_archived(self, rooms, filter, time_now, token_id):
        """
        Encode the archived rooms in a sync result

        :param list[synapse.handlers.sync.ArchivedSyncResult] rooms: list of
             sync results for rooms this user is joined to
        :param FilterCollection filter: filters to apply to the results
        :param int time_now: current time - used as a baseline for age
            calculations
        :param int token_id: ID of the user's auth token - used for namespacing
            of transaction IDs

        :return: the invited rooms list, in our response format
        :rtype: dict[str, dict[str, object]]
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = self.encode_room(
                room, filter, time_now, token_id, joined=False
            )

        return joined

    @staticmethod
    def encode_room(room, filter, time_now, token_id, joined=True):
        """
        :param synapse.handlers.sync.JoinedSyncResult|synapse.handlers.sync.ArchivedSyncResult room: sync result for a single room
        :param FilterCollection filter: filters to apply to the results
        :param int time_now: current time - used as a baseline for age
            calculations
        :param int token_id: ID of the user's auth token - used for namespacing
            of transaction IDs
        :param joined: True if the user is joined to this room - will mean
            we handle ephemeral events

        :return: the room, encoded in our response format
        :rtype: dict[str, object]
        """
        event_map = {}
        state_events = filter.filter_room_state(room.state)
        state_event_ids = []
        for event in state_events:
            # TODO(mjark): Respect formatting requirements in the filter.
            event_map[event.event_id] = serialize_event(
                event, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_event_id,
            )
            state_event_ids.append(event.event_id)

        timeline_events = filter.filter_room_timeline(room.timeline.events)
        timeline_event_ids = []
        for event in timeline_events:
            # TODO(mjark): Respect formatting requirements in the filter.
            event_map[event.event_id] = serialize_event(
                event, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_event_id,
            )
            timeline_event_ids.append(event.event_id)

        private_user_data = filter.filter_room_private_user_data(
            room.private_user_data
        )

        result = {
            "event_map": event_map,
            "timeline": {
                "events": timeline_event_ids,
                "prev_batch": room.timeline.prev_batch.to_string(),
                "limited": room.timeline.limited,
            },
            "state": {"events": state_event_ids},
            "private_user_data": {"events": private_user_data},
        }

        if joined:
            ephemeral_events = filter.filter_room_ephemeral(room.ephemeral)
            result["ephemeral"] = {"events": ephemeral_events}

        return result


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
