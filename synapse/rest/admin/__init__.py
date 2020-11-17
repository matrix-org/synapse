# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2018-2019 New Vector Ltd
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
import platform

import synapse
from synapse.api.errors import Codes, NotFoundError, SynapseError
from synapse.http.server import JsonResource
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.rest.admin._base import (
    admin_patterns,
    assert_requester_is_admin,
    historical_admin_path_patterns,
)
from synapse.rest.admin.devices import (
    DeleteDevicesRestServlet,
    DeviceRestServlet,
    DevicesRestServlet,
)
from synapse.rest.admin.event_reports import (
    EventReportDetailRestServlet,
    EventReportsRestServlet,
)
from synapse.rest.admin.groups import DeleteGroupAdminRestServlet
from synapse.rest.admin.media import ListMediaInRoom, register_servlets_for_media_repo
from synapse.rest.admin.purge_room_servlet import PurgeRoomServlet
from synapse.rest.admin.rooms import (
    DeleteRoomRestServlet,
    JoinRoomAliasServlet,
    ListRoomRestServlet,
    RoomMembersRestServlet,
    RoomRestServlet,
    ShutdownRoomRestServlet,
)
from synapse.rest.admin.server_notice_servlet import SendServerNoticeServlet
from synapse.rest.admin.statistics import UserMediaStatisticsRestServlet
from synapse.rest.admin.users import (
    AccountValidityRenewServlet,
    DeactivateAccountRestServlet,
    PushersRestServlet,
    ResetPasswordRestServlet,
    SearchUsersRestServlet,
    UserAdminServlet,
    UserMediaRestServlet,
    UserMembershipRestServlet,
    UserRegisterServlet,
    UserRestServletV2,
    UsersRestServlet,
    UsersRestServletV2,
    UserTokenRestServlet,
    WhoisRestServlet,
)
from synapse.types import RoomStreamToken
from synapse.util.versionstring import get_version_string

logger = logging.getLogger(__name__)


class VersionServlet(RestServlet):
    PATTERNS = admin_patterns("/server_version$")

    def __init__(self, hs):
        self.res = {
            "server_version": get_version_string(synapse),
            "python_version": platform.python_version(),
        }

    def on_GET(self, request):
        return 200, self.res


class PurgeHistoryRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns(
        "/purge_history/(?P<room_id>[^/]*)(/(?P<event_id>[^/]+))?"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        self.pagination_handler = hs.get_pagination_handler()
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()

    async def on_POST(self, request, room_id, event_id):
        await assert_requester_is_admin(self.auth, request)

        body = parse_json_object_from_request(request, allow_empty_body=True)

        delete_local_events = bool(body.get("delete_local_events", False))

        # establish the topological ordering we should keep events from. The
        # user can provide an event_id in the URL or the request body, or can
        # provide a timestamp in the request body.
        if event_id is None:
            event_id = body.get("purge_up_to_event_id")

        if event_id is not None:
            event = await self.store.get_event(event_id)

            if event.room_id != room_id:
                raise SynapseError(400, "Event is for wrong room.")

            room_token = RoomStreamToken(
                event.depth, event.internal_metadata.stream_ordering
            )
            token = await room_token.to_string(self.store)

            logger.info("[purge] purging up to token %s (event_id %s)", token, event_id)
        elif "purge_up_to_ts" in body:
            ts = body["purge_up_to_ts"]
            if not isinstance(ts, int):
                raise SynapseError(
                    400, "purge_up_to_ts must be an int", errcode=Codes.BAD_JSON
                )

            stream_ordering = await self.store.find_first_stream_ordering_after_ts(ts)

            r = await self.store.get_room_event_before_stream_ordering(
                room_id, stream_ordering
            )
            if not r:
                logger.warning(
                    "[purge] purging events not possible: No event found "
                    "(received_ts %i => stream_ordering %i)",
                    ts,
                    stream_ordering,
                )
                raise SynapseError(
                    404, "there is no event to be purged", errcode=Codes.NOT_FOUND
                )
            (stream, topo, _event_id) = r
            token = "t%d-%d" % (topo, stream)
            logger.info(
                "[purge] purging up to token %s (received_ts %i => "
                "stream_ordering %i)",
                token,
                ts,
                stream_ordering,
            )
        else:
            raise SynapseError(
                400,
                "must specify purge_up_to_event_id or purge_up_to_ts",
                errcode=Codes.BAD_JSON,
            )

        purge_id = self.pagination_handler.start_purge_history(
            room_id, token, delete_local_events=delete_local_events
        )

        return 200, {"purge_id": purge_id}


class PurgeHistoryStatusRestServlet(RestServlet):
    PATTERNS = historical_admin_path_patterns(
        "/purge_history_status/(?P<purge_id>[^/]+)"
    )

    def __init__(self, hs):
        """

        Args:
            hs (synapse.server.HomeServer)
        """
        self.pagination_handler = hs.get_pagination_handler()
        self.auth = hs.get_auth()

    async def on_GET(self, request, purge_id):
        await assert_requester_is_admin(self.auth, request)

        purge_status = self.pagination_handler.get_purge_status(purge_id)
        if purge_status is None:
            raise NotFoundError("purge id '%s' not found" % purge_id)

        return 200, purge_status.asdict()


########################################################################################
#
# please don't add more servlets here: this file is already long and unwieldy. Put
# them in separate files within the 'admin' package.
#
########################################################################################


class AdminRestResource(JsonResource):
    """The REST resource which gets mounted at /_synapse/admin"""

    def __init__(self, hs):
        JsonResource.__init__(self, hs, canonical_json=False)
        register_servlets(hs, self)


def register_servlets(hs, http_server):
    """
    Register all the admin servlets.
    """
    register_servlets_for_client_rest_resource(hs, http_server)
    ListRoomRestServlet(hs).register(http_server)
    RoomRestServlet(hs).register(http_server)
    RoomMembersRestServlet(hs).register(http_server)
    DeleteRoomRestServlet(hs).register(http_server)
    JoinRoomAliasServlet(hs).register(http_server)
    PurgeRoomServlet(hs).register(http_server)
    SendServerNoticeServlet(hs).register(http_server)
    VersionServlet(hs).register(http_server)
    UserAdminServlet(hs).register(http_server)
    UserMediaRestServlet(hs).register(http_server)
    UserMembershipRestServlet(hs).register(http_server)
    UserTokenRestServlet(hs).register(http_server)
    UserRestServletV2(hs).register(http_server)
    UsersRestServletV2(hs).register(http_server)
    DeviceRestServlet(hs).register(http_server)
    DevicesRestServlet(hs).register(http_server)
    DeleteDevicesRestServlet(hs).register(http_server)
    UserMediaStatisticsRestServlet(hs).register(http_server)
    EventReportDetailRestServlet(hs).register(http_server)
    EventReportsRestServlet(hs).register(http_server)
    PushersRestServlet(hs).register(http_server)


def register_servlets_for_client_rest_resource(hs, http_server):
    """Register only the servlets which need to be exposed on /_matrix/client/xxx"""
    WhoisRestServlet(hs).register(http_server)
    PurgeHistoryStatusRestServlet(hs).register(http_server)
    DeactivateAccountRestServlet(hs).register(http_server)
    PurgeHistoryRestServlet(hs).register(http_server)
    UsersRestServlet(hs).register(http_server)
    ResetPasswordRestServlet(hs).register(http_server)
    SearchUsersRestServlet(hs).register(http_server)
    ShutdownRoomRestServlet(hs).register(http_server)
    UserRegisterServlet(hs).register(http_server)
    DeleteGroupAdminRestServlet(hs).register(http_server)
    AccountValidityRenewServlet(hs).register(http_server)

    # Load the media repo ones if we're using them. Otherwise load the servlets which
    # don't need a media repo (typically readonly admin APIs).
    if hs.config.can_load_media_repo:
        register_servlets_for_media_repo(hs, http_server)
    else:
        ListMediaInRoom(hs).register(http_server)

    # don't add more things here: new servlets should only be exposed on
    # /_synapse/admin so should not go here. Instead register them in AdminRestResource.
