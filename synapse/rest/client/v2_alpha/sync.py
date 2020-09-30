# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

import itertools
import logging

from synapse.api.constants import PresenceState
from synapse.api.errors import Codes, StoreError, SynapseError
from synapse.api.filtering import DEFAULT_FILTER_COLLECTION, FilterCollection
from synapse.events.utils import (
    format_event_for_client_v2_without_room_id,
    format_event_raw,
)
from synapse.handlers.presence import format_user_presence_state
from synapse.handlers.sync import SyncConfig
from synapse.http.servlet import RestServlet, parse_boolean, parse_integer, parse_string
from synapse.types import StreamToken
from synapse.util import json_decoder

from ._base import client_patterns, set_timeline_upper_limit

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

    PATTERNS = client_patterns("/sync$")
    ALLOWED_PRESENCE = {"online", "offline", "unavailable"}

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.sync_handler = hs.get_sync_handler()
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()
        self.presence_handler = hs.get_presence_handler()
        self._server_notices_sender = hs.get_server_notices_sender()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(self, request):
        if b"from" in request.args:
            # /events used to use 'from', but /sync uses 'since'.
            # Lets be helpful and whine if we see a 'from'.
            raise SynapseError(
                400, "'from' is not a valid query parameter. Did you mean 'since'?"
            )

        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        user = requester.user
        device_id = requester.device_id

        timeout = parse_integer(request, "timeout", default=0)
        since = parse_string(request, "since")
        set_presence = parse_string(
            request,
            "set_presence",
            default="online",
            allowed_values=self.ALLOWED_PRESENCE,
        )
        filter_id = parse_string(request, "filter", default=None)
        full_state = parse_boolean(request, "full_state", default=False)

        logger.debug(
            "/sync: user=%r, timeout=%r, since=%r, "
            "set_presence=%r, filter_id=%r, device_id=%r",
            user,
            timeout,
            since,
            set_presence,
            filter_id,
            device_id,
        )

        request_key = (user, timeout, since, filter_id, full_state, device_id)

        if filter_id is None:
            filter_collection = DEFAULT_FILTER_COLLECTION
        elif filter_id.startswith("{"):
            try:
                filter_object = json_decoder.decode(filter_id)
                set_timeline_upper_limit(
                    filter_object, self.hs.config.filter_timeline_limit
                )
            except Exception:
                raise SynapseError(400, "Invalid filter JSON")
            self.filtering.check_valid_filter(filter_object)
            filter_collection = FilterCollection(filter_object)
        else:
            try:
                filter_collection = await self.filtering.get_user_filter(
                    user.localpart, filter_id
                )
            except StoreError as err:
                if err.code != 404:
                    raise
                # fix up the description and errcode to be more useful
                raise SynapseError(400, "No such filter", errcode=Codes.INVALID_PARAM)

        sync_config = SyncConfig(
            user=user,
            filter_collection=filter_collection,
            is_guest=requester.is_guest,
            request_key=request_key,
            device_id=device_id,
        )

        since_token = None
        if since is not None:
            since_token = await StreamToken.from_string(self.store, since)

        # send any outstanding server notices to the user.
        await self._server_notices_sender.on_user_syncing(user.to_string())

        affect_presence = set_presence != PresenceState.OFFLINE

        if affect_presence:
            await self.presence_handler.set_state(
                user, {"presence": set_presence}, True
            )

        context = await self.presence_handler.user_syncing(
            user.to_string(), affect_presence=affect_presence
        )
        with context:
            sync_result = await self.sync_handler.wait_for_sync_for_user(
                sync_config,
                since_token=since_token,
                timeout=timeout,
                full_state=full_state,
            )

        # the client may have disconnected by now; don't bother to serialize the
        # response if so.
        if request._disconnected:
            logger.info("Client has disconnected; not serializing response.")
            return 200, {}

        time_now = self.clock.time_msec()
        response_content = await self.encode_response(
            time_now, sync_result, requester.access_token_id, filter_collection
        )

        logger.debug("Event formatting complete")
        return 200, response_content

    async def encode_response(self, time_now, sync_result, access_token_id, filter):
        logger.debug("Formatting events in sync response")
        if filter.event_format == "client":
            event_formatter = format_event_for_client_v2_without_room_id
        elif filter.event_format == "federation":
            event_formatter = format_event_raw
        else:
            raise Exception("Unknown event format %s" % (filter.event_format,))

        joined = await self.encode_joined(
            sync_result.joined,
            time_now,
            access_token_id,
            filter.event_fields,
            event_formatter,
        )

        invited = await self.encode_invited(
            sync_result.invited, time_now, access_token_id, event_formatter
        )

        archived = await self.encode_archived(
            sync_result.archived,
            time_now,
            access_token_id,
            filter.event_fields,
            event_formatter,
        )

        logger.debug("building sync response dict")
        return {
            "account_data": {"events": sync_result.account_data},
            "to_device": {"events": sync_result.to_device},
            "device_lists": {
                "changed": list(sync_result.device_lists.changed),
                "left": list(sync_result.device_lists.left),
            },
            "presence": SyncRestServlet.encode_presence(sync_result.presence, time_now),
            "rooms": {"join": joined, "invite": invited, "leave": archived},
            "groups": {
                "join": sync_result.groups.join,
                "invite": sync_result.groups.invite,
                "leave": sync_result.groups.leave,
            },
            "device_one_time_keys_count": sync_result.device_one_time_keys_count,
            "next_batch": await sync_result.next_batch.to_string(self.store),
        }

    @staticmethod
    def encode_presence(events, time_now):
        return {
            "events": [
                {
                    "type": "m.presence",
                    "sender": event.user_id,
                    "content": format_user_presence_state(
                        event, time_now, include_user_id=False
                    ),
                }
                for event in events
            ]
        }

    async def encode_joined(
        self, rooms, time_now, token_id, event_fields, event_formatter
    ):
        """
        Encode the joined rooms in a sync result

        Args:
            rooms(list[synapse.handlers.sync.JoinedSyncResult]): list of sync
                results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
                of transaction IDs
            event_fields(list<str>): List of event fields to include. If empty,
                all fields will be returned.
            event_formatter (func[dict]): function to convert from federation format
                to client format
        Returns:
            dict[str, dict[str, object]]: the joined rooms list, in our
                response format
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = await self.encode_room(
                room,
                time_now,
                token_id,
                joined=True,
                only_fields=event_fields,
                event_formatter=event_formatter,
            )

        return joined

    async def encode_invited(self, rooms, time_now, token_id, event_formatter):
        """
        Encode the invited rooms in a sync result

        Args:
            rooms(list[synapse.handlers.sync.InvitedSyncResult]): list of
                sync results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
                of transaction IDs
            event_formatter (func[dict]): function to convert from federation format
                to client format

        Returns:
            dict[str, dict[str, object]]: the invited rooms list, in our
                response format
        """
        invited = {}
        for room in rooms:
            invite = await self._event_serializer.serialize_event(
                room.invite,
                time_now,
                token_id=token_id,
                event_format=event_formatter,
                is_invite=True,
            )
            unsigned = dict(invite.get("unsigned", {}))
            invite["unsigned"] = unsigned
            invited_state = list(unsigned.pop("invite_room_state", []))
            invited_state.append(invite)
            invited[room.room_id] = {"invite_state": {"events": invited_state}}

        return invited

    async def encode_archived(
        self, rooms, time_now, token_id, event_fields, event_formatter
    ):
        """
        Encode the archived rooms in a sync result

        Args:
            rooms (list[synapse.handlers.sync.ArchivedSyncResult]): list of
                sync results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
                of transaction IDs
            event_fields(list<str>): List of event fields to include. If empty,
                all fields will be returned.
            event_formatter (func[dict]): function to convert from federation format
                to client format
        Returns:
            dict[str, dict[str, object]]: The invited rooms list, in our
                response format
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = await self.encode_room(
                room,
                time_now,
                token_id,
                joined=False,
                only_fields=event_fields,
                event_formatter=event_formatter,
            )

        return joined

    async def encode_room(
        self, room, time_now, token_id, joined, only_fields, event_formatter
    ):
        """
        Args:
            room (JoinedSyncResult|ArchivedSyncResult): sync result for a
                single room
            time_now (int): current time - used as a baseline for age
                calculations
            token_id (int): ID of the user's auth token - used for namespacing
                of transaction IDs
            joined (bool): True if the user is joined to this room - will mean
                we handle ephemeral events
            only_fields(list<str>): Optional. The list of event fields to include.
            event_formatter (func[dict]): function to convert from federation format
                to client format
        Returns:
            dict[str, object]: the room, encoded in our response format
        """

        def serialize(events):
            return self._event_serializer.serialize_events(
                events,
                time_now=time_now,
                # We don't bundle "live" events, as otherwise clients
                # will end up double counting annotations.
                bundle_aggregations=False,
                token_id=token_id,
                event_format=event_formatter,
                only_event_fields=only_fields,
            )

        state_dict = room.state
        timeline_events = room.timeline.events

        state_events = state_dict.values()

        for event in itertools.chain(state_events, timeline_events):
            # We've had bug reports that events were coming down under the
            # wrong room.
            if event.room_id != room.room_id:
                logger.warning(
                    "Event %r is under room %r instead of %r",
                    event.event_id,
                    room.room_id,
                    event.room_id,
                )

        serialized_state = await serialize(state_events)
        serialized_timeline = await serialize(timeline_events)

        account_data = room.account_data

        result = {
            "timeline": {
                "events": serialized_timeline,
                "prev_batch": await room.timeline.prev_batch.to_string(self.store),
                "limited": room.timeline.limited,
            },
            "state": {"events": serialized_state},
            "account_data": {"events": account_data},
        }

        if joined:
            ephemeral_events = room.ephemeral
            result["ephemeral"] = {"events": ephemeral_events}
            result["unread_notifications"] = room.unread_notifications
            result["summary"] = room.summary
            result["org.matrix.msc2654.unread_count"] = room.unread_count

        return result


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
