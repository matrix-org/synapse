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

from twisted.internet import defer

from synapse.http.servlet import (
    RestServlet, parse_string, parse_integer, parse_boolean,
    parse_json_object_from_request,
)
from synapse.handlers.sync import (
    SyncConfig, SyncPaginationConfig, SYNC_PAGINATION_TAGS_IGNORE, SyncExtras,
    DEFAULT_SYNC_EXTRAS,
)
from synapse.types import SyncNextBatchToken
from synapse.events.utils import (
    serialize_event, format_event_for_client_v2_without_room_id,
)
from synapse.api.filtering import FilterCollection, DEFAULT_FILTER_COLLECTION
from synapse.api.errors import SynapseError
from synapse.api.constants import PresenceState
from ._base import client_v2_patterns

import copy
import itertools
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
        self.sync_handler = hs.get_sync_handler()
        self.clock = hs.get_clock()
        self.filtering = hs.get_filtering()
        self.presence_handler = hs.get_presence_handler()

    @defer.inlineCallbacks
    def on_POST(self, request):
        requester = yield self.auth.get_user_by_req(
            request, allow_guest=True
        )
        user = requester.user

        body = parse_json_object_from_request(request)

        timeout = body.get("timeout", 0)

        since = body.get("since", None)

        extras = body.get("extras", {})
        extras = SyncExtras(
            paginate=extras.get("paginate", {}),
            peek=extras.get("peek", {}),
        )

        if "from" in body:
            # /events used to use 'from', but /sync uses 'since'.
            # Lets be helpful and whine if we see a 'from'.
            raise SynapseError(
                400, "'from' is not a valid parameter. Did you mean 'since'?"
            )

        set_presence = body.get("set_presence", "online")
        if set_presence not in self.ALLOWED_PRESENCE:
            message = "Parameter 'set_presence' must be one of [%s]" % (
                ", ".join(repr(v) for v in self.ALLOWED_PRESENCE)
            )
            raise SynapseError(400, message)

        full_state = body.get("full_state", False)

        filter_id = body.get("filter_id", None)
        filter_dict = body.get("filter", None)
        pagination_config = body.get("pagination_config", None)

        if filter_dict is not None and filter_id is not None:
            raise SynapseError(
                400,
                "Can only specify one of `filter` and `filter_id` paramters"
            )

        if filter_id:
            filter_collection = yield self.filtering.get_user_filter(
                user.localpart, filter_id
            )
            filter_key = filter_id
        elif filter_dict:
            self.filtering.check_valid_filter(filter_dict)
            filter_collection = FilterCollection(filter_dict)
            filter_key = json.dumps(filter_dict)
        else:
            filter_collection = DEFAULT_FILTER_COLLECTION
            filter_key = None

        request_key = (user, timeout, since, filter_key, full_state)

        sync_config = SyncConfig(
            user=user,
            filter_collection=filter_collection,
            is_guest=requester.is_guest,
            request_key=request_key,
            pagination_config=SyncPaginationConfig(
                order=pagination_config["order"],
                limit=pagination_config["limit"],
                tags=pagination_config.get("tags", SYNC_PAGINATION_TAGS_IGNORE),
            ) if pagination_config else None,
        )

        if since is not None:
            batch_token = SyncNextBatchToken.from_string(since)
        else:
            batch_token = None

        sync_result = yield self._handle_sync(
            requester=requester,
            sync_config=sync_config,
            batch_token=batch_token,
            set_presence=set_presence,
            full_state=full_state,
            timeout=timeout,
            extras=extras,
        )

        defer.returnValue(sync_result)

    @defer.inlineCallbacks
    def on_GET(self, request):
        if "from" in request.args:
            # /events used to use 'from', but /sync uses 'since'.
            # Lets be helpful and whine if we see a 'from'.
            raise SynapseError(
                400, "'from' is not a valid query parameter. Did you mean 'since'?"
            )

        requester = yield self.auth.get_user_by_req(
            request, allow_guest=True
        )
        user = requester.user

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

        request_key = (user, timeout, since, filter_id, full_state)

        if filter_id:
            if filter_id.startswith('{'):
                try:
                    filter_object = json.loads(filter_id)
                except:
                    raise SynapseError(400, "Invalid filter JSON")
                self.filtering.check_valid_filter(filter_object)
                filter = FilterCollection(filter_object)
            else:
                filter = yield self.filtering.get_user_filter(
                    user.localpart, filter_id
                )
        else:
            filter = DEFAULT_FILTER_COLLECTION

        sync_config = SyncConfig(
            user=user,
            filter_collection=filter,
            is_guest=requester.is_guest,
            request_key=request_key,
            pagination_config=None,
        )

        if since is not None:
            batch_token = SyncNextBatchToken.from_string(since)
        else:
            batch_token = None

        sync_result = yield self._handle_sync(
            requester=requester,
            sync_config=sync_config,
            batch_token=batch_token,
            set_presence=set_presence,
            full_state=full_state,
            timeout=timeout,
        )

        defer.returnValue(sync_result)

    @defer.inlineCallbacks
    def _handle_sync(self, requester, sync_config, batch_token, set_presence,
                     full_state, timeout, extras=DEFAULT_SYNC_EXTRAS):
        affect_presence = set_presence != PresenceState.OFFLINE

        user = sync_config.user

        if affect_presence:
            yield self.presence_handler.set_state(user, {"presence": set_presence})

        context = yield self.presence_handler.user_syncing(
            user.to_string(), affect_presence=affect_presence,
        )
        with context:
            sync_result = yield self.sync_handler.wait_for_sync_for_user(
                sync_config, batch_token=batch_token, timeout=timeout,
                full_state=full_state, extras=extras,
            )

        time_now = self.clock.time_msec()

        joined = self.encode_joined(
            sync_result.joined, time_now, requester.access_token_id
        )

        invited = self.encode_invited(
            sync_result.invited, time_now, requester.access_token_id
        )

        archived = self.encode_archived(
            sync_result.archived, time_now, requester.access_token_id
        )

        response_content = {
            "account_data": {"events": sync_result.account_data},
            "presence": self.encode_presence(
                sync_result.presence, time_now
            ),
            "rooms": {
                "join": joined,
                "invite": invited,
                "leave": archived,
            },
            "next_batch": sync_result.next_batch.to_string(),
        }

        if sync_result.errors:
            response_content["rooms"]["errors"] = self.encode_errors(sync_result.errors)

        if sync_result.pagination_info:
            response_content["pagination_info"] = sync_result.pagination_info

        defer.returnValue((200, response_content))

    def encode_presence(self, events, time_now):
        formatted = []
        for event in events:
            event = copy.deepcopy(event)
            event['sender'] = event['content'].pop('user_id')
            formatted.append(event)
        return {"events": formatted}

    def encode_errors(self, errors):
        return {
            e.room_id: {
                "errcode": e.errcode,
                "error": e.error
            }
            for e in errors
        }

    def encode_joined(self, rooms, time_now, token_id):
        """
        Encode the joined rooms in a sync result

        Args:
            rooms(list[synapse.handlers.sync.JoinedSyncResult]): list of sync
                results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
                of transaction IDs

        Returns:
            dict[str, dict[str, object]]: the joined rooms list, in our
                response format
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = self.encode_room(
                room, time_now, token_id
            )
            joined[room.room_id]["synced"] = room.synced

        return joined

    def encode_invited(self, rooms, time_now, token_id):
        """
        Encode the invited rooms in a sync result

        Args:
            rooms(list[synapse.handlers.sync.InvitedSyncResult]): list of
                sync results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
            of transaction IDs

        Returns:
            dict[str, dict[str, object]]: the invited rooms list, in our
                response format
        """
        invited = {}
        for room in rooms:
            invite = serialize_event(
                room.invite, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_room_id,
            )
            unsigned = dict(invite.get("unsigned", {}))
            invite["unsigned"] = unsigned
            invited_state = list(unsigned.pop("invite_room_state", []))
            invited_state.append(invite)
            invited[room.room_id] = {
                "invite_state": {"events": invited_state}
            }

        return invited

    def encode_archived(self, rooms, time_now, token_id):
        """
        Encode the archived rooms in a sync result

        Args:
            rooms (list[synapse.handlers.sync.ArchivedSyncResult]): list of
                sync results for rooms this user is joined to
            time_now(int): current time - used as a baseline for age
                calculations
            token_id(int): ID of the user's auth token - used for namespacing
                of transaction IDs

        Returns:
            dict[str, dict[str, object]]: The invited rooms list, in our
                response format
        """
        joined = {}
        for room in rooms:
            joined[room.room_id] = self.encode_room(
                room, time_now, token_id, joined=False
            )

        return joined

    @staticmethod
    def encode_room(room, time_now, token_id, joined=True):
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

        Returns:
            dict[str, object]: the room, encoded in our response format
        """
        def serialize(event):
            # TODO(mjark): Respect formatting requirements in the filter.
            return serialize_event(
                event, time_now, token_id=token_id,
                event_format=format_event_for_client_v2_without_room_id,
            )

        state_dict = room.state
        timeline_events = room.timeline.events

        state_events = state_dict.values()

        for event in itertools.chain(state_events, timeline_events):
            # We've had bug reports that events were coming down under the
            # wrong room.
            if event.room_id != room.room_id:
                logger.warn(
                    "Event %r is under room %r instead of %r",
                    event.event_id, room.room_id, event.room_id,
                )

        serialized_state = [serialize(e) for e in state_events]
        serialized_timeline = [serialize(e) for e in timeline_events]

        account_data = room.account_data

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
            ephemeral_events = room.ephemeral
            result["ephemeral"] = {"events": ephemeral_events}
            result["unread_notifications"] = room.unread_notifications

        return result


def register_servlets(hs, http_server):
    SyncRestServlet(hs).register(http_server)
