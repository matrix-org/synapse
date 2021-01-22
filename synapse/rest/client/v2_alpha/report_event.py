# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import logging
from http import HTTPStatus

from synapse.api.auth import Auth
from synapse.api.constants import EventTypes
from synapse.api.errors import AuthError, Codes, SynapseError
from synapse.federation.federation_client import FederationClient
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.server import HomeServer
from synapse.server_notices.server_notices_manager import ServerNoticesManager
from synapse.state import StateHandler
from synapse.storage import DataStore, Storage
from synapse.types import UserID
from synapse.visibility import filter_events_for_client

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ReportEventRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/report/(?P<event_id>[^/]*)$")

    hs: HomeServer
    auth: Auth
    federation_client: FederationClient
    snm: ServerNoticesManager
    state: StateHandler
    storage: Storage
    store: DataStore

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()


        self.clock = hs.get_clock()
        self.federation_client = hs.get_federation_client()
        self.snm = hs.get_server_notices_manager()
        self.state = hs.get_state_handler()
        self.store = hs.get_datastore()
        self.storage = hs.get_storage()

    async def on_POST(self, request, room_id, event_id):
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user.to_string()

        body = parse_json_object_from_request(request)
        assert_params_in_dict(body, ("reason", "score"))

        if not isinstance(body["reason"], str):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'reason' must be a string",
                Codes.BAD_JSON,
            )
        if not isinstance(body["score"], int):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'score' must be an integer",
                Codes.BAD_JSON,
            )

        target = body.get("org.matrix.msc2938.target", "homeserver-admins")

        if target == "room-moderators":
            # Report event to room moderators.
            # This branch has further safety checks (e.g. can the user actually see the event?)
            return await self._target_room_moderators(room_id=room_id, event_id=event_id, user_id=user_id, reason=body["reason"], score=body["score"])
        elif target == "homeserver-admins":
            return await self._target_homeserver_admin(room_id=room_id, event_id=event_id, user_id=user_id, reason=body["reason"], content=body)
        else:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Optional param 'target' must be one of ['homeserver-admins', 'room-moderators']",
                Codes.BAD_JSON,
            )

    async def _target_homeserver_admin(self, room_id, event_id, user_id, reason, content):
        # Store event report for later investigation by the homeserver admin.
        await self.store.add_event_report(
            room_id=room_id,
            event_id=event_id,
            user_id=user_id,
            reason=reason,
            content=content,
            received_ts=self.clock.time_msec(),
        )

        return 200, {}

    async def _target_room_moderators(self, room_id, event_id, user_id, reason, score):
        # We're dispatching the abuse report to room moderators.
        # First, let's make sure that we should.

        # A little sanity check on the event itself.
        event = await self.store.get_event(event_id)
        if event.room_id != room_id:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "No such event in this room",
                Codes.NOT_FOUND
            )

        # Now make sure that the user was able to witness the event.
        events = await filter_events_for_client(
            self.storage,
            user_id,
            [event],
            is_peeking=True
        )
        if len(events) == 0:
            raise SynapseError(
                HTTPStatus.FORBIDDEN,
                "User cannot witness this event",
                Codes.FORBIDDEN
            )

        # Find the moderators
        power_level_event = await self.state.get_current_state(
            room_id, EventTypes.PowerLevels, ""
        )
        ban_level = power_level_event.content.get("ban", 50)
        kick_level = power_level_event.content.get("kick", 50)
        moderator_level = max(ban_level, kick_level)

        # map: homeserver:str -> [user_id]
        room = await self.store.get_room_with_stats(room_id)
        # FIXME: What do we do if `room is None`?

        moderators_by_hs = {}
        for member_id in room["joined_members"]:
            level = power_level_event.content.get("users", {}).get(member_id)
            if not level:
                level = power_level_event.content.get("users_default", 0)
            if level >= moderator_level:
                hs = UserID.from_string(user_id).domain
                moderators_on_hs = moderators_by_hs.get(hs, [])
                moderators_on_hs.append(member_id)


        # Dispatch report
        for (hs, moderators) in moderators_by_hs.items():
            if hs == self.hs.domain:
                # Dispatch report immediately as a server notice.
                for member_id in moderators:
                    await self.snm.send_notice(
                        user_id=member_id,
                        type=EventTypes.Message,
                        event_content= {
                            "body": "User has reported content",
                            "msgtype": "m.server_notice.content_report",
                            "roomId": room_id,
                            "eventId": event_id,
                            "userId": user_id,
                            "score": score,
                            "reason": reason
                        }
                    )
            else:
                # Dispatch report to remote homeserver.
                # FIXME: Dispatch report to remote moderators.
                pass



def register_servlets(hs, http_server):
    ReportEventRestServlet(hs).register(http_server)
