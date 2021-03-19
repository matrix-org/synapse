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
from typing import Dict, List, Optional

from synapse.api.auth import Auth
from synapse.api.constants import EventTypes
from synapse.api.errors import Codes, SynapseError
from synapse.federation.sender import FederationSender
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.server import HomeServer
from synapse.server_notices.server_notices_manager import ServerNoticesManager
from synapse.state import StateHandler
from synapse.storage import DataStore, Storage
from synapse.types import EventID, JsonDict, RoomID, UserID, get_domain_from_id
from synapse.visibility import filter_events_for_client

from ._base import client_patterns

logger = logging.getLogger(__name__)


class ReportEventRestServlet(RestServlet):
    PATTERNS = client_patterns("/rooms/(?P<room_id>[^/]*)/report/(?P<event_id>[^/]*)$")

    hs: HomeServer
    auth: Auth
    federation_sender: Optional[FederationSender]
    server_notices: ServerNoticesManager
    state: StateHandler
    storage: Storage
    store: DataStore

    def __init__(self, hs):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()

        self.federation_sender = None
        if hs.should_send_federation():
            self.federation_sender = hs.get_federation_sender()
            hs.get_federation_registry().register_edu_handler(
                "org.matrix.m.content_report", self.on_receive_report_through_federation
            )
        self.clock = hs.get_clock()
        self.federation_client = hs.get_federation_client()
        self.server_notices = hs.get_server_notices_manager()
        self.state = hs.get_state_handler()
        self.store = hs.get_datastore()
        self.storage = hs.get_storage()

    async def on_POST(self, request, room_id, event_id):
        requester = await self.auth.get_user_by_req(request)
        user_id = requester.user
        room_id = RoomID.from_string(room_id)
        event_id = EventID.from_string(event_id)

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
            return await self._report_to_room_moderators(
                room_id=room_id,
                event_id=event_id,
                user_id=user_id,
                reason=body["reason"],
                score=body["score"],
            )
        elif target == "homeserver-admins":
            return await self._report_to_homeserver_admin(
                room_id=room_id,
                event_id=event_id,
                user_id=user_id,
                reason=body["reason"],
                content=body,
            )
        else:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Optional param 'target' must be one of ['homeserver-admins', 'room-moderators']",
                Codes.BAD_JSON,
            )

    async def _report_to_homeserver_admin(
        self,
        room_id: RoomID,
        event_id: EventID,
        user_id: UserID,
        reason: str,
        content: JsonDict,
    ):
        """
        Report an event to the homeserver admin.
        This is typically meant to be used to report an entire room, e.g. for harboring illegal activities.

        - room_id The room in which the event took place.
        - event_id The event to report. We do not check whether the event took place in that room.
        - user_id The user who reported the event. We do not check whether the user can actually witness the event.
        - reason The human-readable reason provided by the user.
        - content A JSON dictionary `{reason: String?, score: Number?}`.

        To receive the report, the homeserver admin will need to call the admin `event_reports` API.
        """
        # Store event report for later investigation by the homeserver admin.
        await self.store.add_event_report(
            room_id=room_id.to_string(),
            event_id=event_id.to_string(),
            user_id=user_id.to_string(),
            reason=reason,
            content=content,
            received_ts=self.clock.time_msec(),
        )

        return 200, {}

    async def _report_to_room_moderators(
        self,
        room_id: RoomID,
        event_id: EventID,
        user_id: UserID,
        reason: str,
        score: Optional[int],
    ):
        """
        Report an event to the moderators of the room.
        This is typically meant to be used to report a single event, e.g. for spamming, trolling or disregarding room rules.

        - room_id The room in which the event took place.
        - event_id The event to report. We do not check whether the event took place in that room.
        - user_id The user who reported the event. We do not check whether the user can actually witness the event.
        - reason The human-readable reason provided by the user.
        - score Optionally, a "badness" score where -100 is "really bad" and 0 is "acceptable".


        We define "moderator" as any member who has the powerlevel to kick and ban users.

        Moderators will receive the reports through server notifications.
        """
        # We're dispatching the abuse report to room moderators.
        # First, let's make sure that we should.

        # A little sanity check on the event itself.
        event = await self.store.get_event(
            event_id="$%s" % event_id.localpart, check_room_id=None
        )
        if event.room_id != room_id.to_string():
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "No such event in this room", Codes.NOT_FOUND
            )

        # Now make sure that the user was able to witness the event.
        events = await filter_events_for_client(
            self.storage, user_id.to_string(), [event], is_peeking=True
        )
        if len(events) == 0:
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "User cannot witness this event",
                Codes.FORBIDDEN,
            )

        moderators = await self.get_moderators(room_id)

        event_content = {
            "body": "User has reported content",
            "msgtype": "org.matrix.m.server_notice.content_report",
            "roomId": room_id.to_string(),
            "eventId": event_id.to_string(),
            "userId": user_id.to_string(),
            "score": score,
            "reason": reason,
        }

        # domain => list of users
        moderators_by_hs: Dict[str, List[str]] = {}
        for moderator in await self.get_moderators(room_id):
            hs = user_id.domain
            moderators_on_hs = moderators_by_hs.get(hs, None)
            if moderators_on_hs is None:
                moderators_on_hs = []
                moderators_by_hs[hs] = moderators_on_hs
            moderators_on_hs.append(moderator)

        # Dispatch report
        for (hs, moderators) in moderators_by_hs.items():
            if self.hs.hostname == hs:
                # Dispatch report immediately as a server notice.
                if self.server_notices.is_enabled():
                    for member_id in moderators:
                        await self.server_notices.send_notice(
                            user_id=member_id,
                            type=EventTypes.Message,
                            event_content=event_content,
                        )
            elif self.federation_sender:
                # Dispatch report to remote homeserver.
                #
                # We could make this a PDU and make efforts to keep this transactional,
                # but we figure that the main role of these messages is to inform moderators
                # who are available *right now*.
                await self.federation_sender.build_and_send_edu(
                    destination=hs,
                    edu_type="org.matrix.m.content_report",
                    content=event_content,
                )
        if self.server_notices.is_enabled():
            return 200, {}
        else:
            return 200, {"warning": "server notices are disabled"}

    async def get_moderators(self, room_id: RoomID) -> List[str]:
        moderators = []
        room_id_str = room_id.to_string()
        power_level_event = await self.state.get_current_state(
            room_id_str, EventTypes.PowerLevels, ""
        )
        if power_level_event is None:
            # Odd. Perhaps there are no moderators.
            raise SynapseError(
                HTTPStatus.NOT_FOUND,
                "This room doesn't seem to have moderators",
                Codes.FORBIDDEN,
            )

        ban_level = power_level_event.content.get("ban", 50)
        kick_level = power_level_event.content.get("kick", 50)
        moderator_level = max(ban_level, kick_level)

        for [member_id, level] in power_level_event.content["users"].items():
            if level >= moderator_level:
                moderators.append(member_id)

        return moderators

    async def on_receive_report_through_federation(
        self, origin: str, edu_content: JsonDict
    ) -> None:
        room_id = edu_content.pop("room_id")
        event_id = edu_content.pop("event_id")
        user_id = edu_content.pop("user_id")
        score = edu_content.pop("score")
        reason = edu_content.pop("reason")

        # Before proceeding, run a few reasonable checks.
        # Note that if the remote homeserver is malicious, there is only so much
        # we can do to detect false reports.

        # - Is the alledged sender a member of the homeserver?
        if get_domain_from_id(user_id) != origin:
            logger.warning(
                "Received invalid event report edu: user is %s but domain %s"
                % (user_id, origin)
            )
            return

        # - Did we actually participate in this event?
        event = None
        try:
            event = await self.store.get_event(event_id.to_string())
        except Exception:
            pass
        if event is None:
            logger.warning(
                "Received invalid event report edu: no such event %s" % event_id
            )
            return

        # - Did the event take place in the alledged room?
        if event.room_id != room_id:
            logger.warning(
                "Received invalid event report edu: room is %s but event's room is %s"
                % (room_id, event.room_id)
            )
            return

        # - Could the alledged sender witness this event?
        # FIXME: TODO

        # Rebuild the event, to ensure that we're not accidentally
        # propagating additional malicious fields.
        event_content = {
            "body": "User has reported content",
            "msgtype": "org.matrix.m.server_notice.content_report",
            "roomId": room_id,
            "eventId": event_id,
            "userId": user_id,
            "score": score,
            "reason": reason,
        }

        # Alright, we are satisfied. Let's dispatch to moderators.
        all_moderators = await self.get_moderators(room_id)
        for user_id in all_moderators:
            if self.hs.is_mine(user_id):
                await self.server_notices.send_notice(
                    user_id=user_id.to_string(),
                    type=EventTypes.Message,
                    event_content=event_content,
                )


def register_servlets(hs, http_server):
    ReportEventRestServlet(hs).register(http_server)
