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
from synapse.events import FrozenEvent
from synapse.events.utils import (
    serialize_event, format_event_for_client_v2_without_room_id,
)
from synapse.api.filtering import FilterCollection
from synapse.api.errors import SynapseError
from ._base import client_v2_patterns

import copy
import logging

import ujson as json

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
            "join": { // Joined rooms being updated.
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
            "invite": {}, // Invited rooms being updated.
            "leave": {} // Archived rooms being updated.
          }
        }
    """

    PATTERNS = client_v2_patterns("/sync$")
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
        user, token_id, is_guest = yield self.auth.get_user_by_req(
            request, allow_guest=True
        )

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

        if filter_id and filter_id.startswith('{'):
            try:
                filter_object = json.loads(filter_id)
            except:
                raise SynapseError(400, "Invalid filter JSON")
            self.filtering._check_valid_filter(filter_object)
            filter = FilterCollection(filter_object)
        else:
            try:
                filter = yield self.filtering.get_user_filter(
                    user.localpart, filter_id
                )
            except:
                filter = FilterCollection({})

        if is_guest and filter.list_rooms() is None:
            raise SynapseError(
                400, "Guest users must provide a list of rooms in the filter"
            )

        sync_config = SyncConfig(
            user=user,
            is_guest=is_guest,
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
            "account_data": self.encode_account_data(
                sync_result.account_data, filter, time_now
            ),
            "presence": self.encode_presence(
                sync_result.presence, filter, time_now
            ),
            "rooms": {
                "join": joined,
                "invite": invited,
                "leave": archived,
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

    def encode_account_data(self, events, filter, time_now):
        return {"events": filter.filter_account_data(events)}

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
                event_format=format_event_for_client_v2_without_room_id,
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
        :param JoinedSyncResult|ArchivedSyncResult room: sync result for a
            single room
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
        def serialize(event):
            # TODO(mjark): Respect formatting requirements in the filter.
            return serialize_event(
                event, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_room_id,
            )

        state_dict = room.state
        timeline_events = filter.filter_room_timeline(room.timeline.events)

        state_dict = SyncRestServlet._rollback_state_for_timeline(
            state_dict, timeline_events)

        state_events = filter.filter_room_state(state_dict.values())

        serialized_state = [serialize(e) for e in state_events]
        serialized_timeline = [serialize(e) for e in timeline_events]

        account_data = filter.filter_room_account_data(
            room.account_data
        )

        result = {
            "timeline": {
                "events": serialized_timeline,
                "prev_batch": room.timeline.prev_batch.to_string(),
                "limited": room.timeline.limited,
            },
            "state": {"events": serialized_state},
            "account_data": {"events": account_data},
        }

        if joined:
            ephemeral_events = filter.filter_room_ephemeral(room.ephemeral)
            result["ephemeral"] = {"events": ephemeral_events}

        return result

    @staticmethod
    def _rollback_state_for_timeline(state, timeline):
        """
        Wind the state dictionary backwards, so that it represents the
        state at the start of the timeline, rather than at the end.

        :param dict[(str, str), synapse.events.EventBase] state: the
            state dictionary. Will be updated to the state before the timeline.
        :param list[synapse.events.EventBase] timeline: the event timeline
        :return: updated state dictionary
        """
        logger.debug("Processing state dict %r; timeline %r", state,
                     [e.get_dict() for e in timeline])

        result = state.copy()

        for timeline_event in reversed(timeline):
            if not timeline_event.is_state():
                continue

            event_key = (timeline_event.type, timeline_event.state_key)

            logger.debug("Considering %s for removal", event_key)

            state_event = result.get(event_key)
            if (state_event is None or
                    state_event.event_id != timeline_event.event_id):
                # the event in the timeline isn't present in the state
                # dictionary.
                #
                # the most likely cause for this is that there was a fork in
                # the event graph, and the state is no longer valid. Really,
                # the event shouldn't be in the timeline. We're going to ignore
                # it for now, however.
                logger.warn("Found state event %r in timeline which doesn't "
                            "match state dictionary", timeline_event)
                continue

            prev_event_id = timeline_event.unsigned.get("replaces_state", None)

            prev_content = timeline_event.unsigned.get('prev_content')
            prev_sender = timeline_event.unsigned.get('prev_sender')
            # Empircally it seems possible for the event to have a
            # "replaces_state" key but not a prev_content or prev_sender
            # markjh conjectures that it could be due to the server not
            # having a copy of that event.
            # If this is the case the we ignore the previous event. This will
            # cause the displayname calculations on the client to be incorrect
            if prev_event_id is None or not prev_content or not prev_sender:
                logger.debug(
                    "Removing %r from the state dict, as it is missing"
                    " prev_content (prev_event_id=%r)",
                    timeline_event.event_id, prev_event_id
                )
                del result[event_key]
            else:
                logger.debug(
                    "Replacing %r with %r in state dict",
                    timeline_event.event_id, prev_event_id
                )
                result[event_key] = FrozenEvent({
                    "type": timeline_event.type,
                    "state_key": timeline_event.state_key,
                    "content": prev_content,
                    "sender": prev_sender,
                    "event_id": prev_event_id,
                    "room_id": timeline_event.room_id,
                })

            logger.debug("New value: %r", result.get(event_key))

        return result


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
