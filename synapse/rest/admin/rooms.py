# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from typing import List, Optional

from synapse.api.constants import EventTypes, JoinRules
from synapse.api.errors import Codes, NotFoundError, SynapseError
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.rest.admin._base import (
    admin_patterns,
    assert_requester_is_admin,
    assert_user_is_admin,
    historical_admin_path_patterns,
)
from synapse.storage.databases.main.room import RoomSortOrder
from synapse.types import RoomAlias, RoomID, UserID, create_requester

logger = logging.getLogger(__name__)


class ShutdownRoomRestServlet(RestServlet):
    """Shuts down a room by removing all local users from the room and blocking
    all future invites and joins to the room. Any local aliases will be repointed
    to a new room created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    """

    PATTERNS = historical_admin_path_patterns("/shutdown_room/(?P<room_id>[^/]+)")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_shutdown_handler = hs.get_room_shutdown_handler()

    async def on_POST(self, request, room_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        content = parse_json_object_from_request(request)
        assert_params_in_dict(content, ["new_room_user_id"])

        ret = await self.room_shutdown_handler.shutdown_room(
            room_id=room_id,
            new_room_user_id=content["new_room_user_id"],
            new_room_name=content.get("room_name"),
            message=content.get("message"),
            requester_user_id=requester.user.to_string(),
            block=True,
        )

        return (200, ret)


class DeleteRoomRestServlet(RestServlet):
    """Delete a room from server. It is a combination and improvement of
    shut down and purge room.
    Shuts down a room by removing all local users from the room.
    Blocking all future invites and joins to the room is optional.
    If desired any local aliases will be repointed to a new room
    created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    It will remove all trace of a room from the database.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)/delete$")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_shutdown_handler = hs.get_room_shutdown_handler()
        self.pagination_handler = hs.get_pagination_handler()

    async def on_POST(self, request, room_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        content = parse_json_object_from_request(request)

        block = content.get("block", False)
        if not isinstance(block, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'block' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        purge = content.get("purge", True)
        if not isinstance(purge, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'purge' must be a boolean, if given",
                Codes.BAD_JSON,
            )

        ret = await self.room_shutdown_handler.shutdown_room(
            room_id=room_id,
            new_room_user_id=content.get("new_room_user_id"),
            new_room_name=content.get("room_name"),
            message=content.get("message"),
            requester_user_id=requester.user.to_string(),
            block=block,
        )

        # Purge room
        if purge:
            await self.pagination_handler.purge_room(room_id)

        return (200, ret)


class ListRoomRestServlet(RestServlet):
    """
    List all rooms that are known to the homeserver. Results are returned
    in a dictionary containing room information. Supports pagination.
    """

    PATTERNS = admin_patterns("/rooms$")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        # Extract query parameters
        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)
        order_by = parse_string(request, "order_by", default=RoomSortOrder.NAME.value)
        if order_by not in (
            RoomSortOrder.ALPHABETICAL.value,
            RoomSortOrder.SIZE.value,
            RoomSortOrder.NAME.value,
            RoomSortOrder.CANONICAL_ALIAS.value,
            RoomSortOrder.JOINED_MEMBERS.value,
            RoomSortOrder.JOINED_LOCAL_MEMBERS.value,
            RoomSortOrder.VERSION.value,
            RoomSortOrder.CREATOR.value,
            RoomSortOrder.ENCRYPTION.value,
            RoomSortOrder.FEDERATABLE.value,
            RoomSortOrder.PUBLIC.value,
            RoomSortOrder.JOIN_RULES.value,
            RoomSortOrder.GUEST_ACCESS.value,
            RoomSortOrder.HISTORY_VISIBILITY.value,
            RoomSortOrder.STATE_EVENTS.value,
        ):
            raise SynapseError(
                400,
                "Unknown value for order_by: %s" % (order_by,),
                errcode=Codes.INVALID_PARAM,
            )

        search_term = parse_string(request, "search_term")
        if search_term == "":
            raise SynapseError(
                400,
                "search_term cannot be an empty string",
                errcode=Codes.INVALID_PARAM,
            )

        direction = parse_string(request, "dir", default="f")
        if direction not in ("f", "b"):
            raise SynapseError(
                400, "Unknown direction: %s" % (direction,), errcode=Codes.INVALID_PARAM
            )

        reverse_order = True if direction == "b" else False

        # Return list of rooms according to parameters
        rooms, total_rooms = await self.store.get_rooms_paginate(
            start, limit, order_by, reverse_order, search_term
        )
        response = {
            # next_token should be opaque, so return a value the client can parse
            "offset": start,
            "rooms": rooms,
            "total_rooms": total_rooms,
        }

        # Are there more rooms to paginate through after this?
        if (start + limit) < total_rooms:
            # There are. Calculate where the query should start from next time
            # to get the next part of the list
            response["next_batch"] = start + limit

        # Is it possible to paginate backwards? Check if we currently have an
        # offset
        if start > 0:
            if start > limit:
                # Going back one iteration won't take us to the start.
                # Calculate new offset
                response["prev_batch"] = start - limit
            else:
                response["prev_batch"] = 0

        return 200, response


class RoomRestServlet(RestServlet):
    """Get room details.

    TODO: Add on_POST to allow room creation without joining the room
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)$")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(self, request, room_id):
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room_with_stats(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        return 200, ret


class RoomMembersRestServlet(RestServlet):
    """
    Get members list of a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)/members")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(self, request, room_id):
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        members = await self.store.get_users_in_room(room_id)
        ret = {"members": members, "total": len(members)}

        return 200, ret


class JoinRoomAliasServlet(RestServlet):

    PATTERNS = admin_patterns("/join/(?P<room_identifier>[^/]*)")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_member_handler = hs.get_room_member_handler()
        self.admin_handler = hs.get_admin_handler()
        self.state_handler = hs.get_state_handler()

    async def on_POST(self, request, room_identifier):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        content = parse_json_object_from_request(request)

        assert_params_in_dict(content, ["user_id"])
        target_user = UserID.from_string(content["user_id"])

        if not self.hs.is_mine(target_user):
            raise SynapseError(400, "This endpoint can only be used with local users")

        if not await self.admin_handler.get_user(target_user):
            raise NotFoundError("User not found")

        if RoomID.is_valid(room_identifier):
            room_id = room_identifier
            try:
                remote_room_hosts = [
                    x.decode("ascii") for x in request.args[b"server_name"]
                ]  # type: Optional[List[str]]
            except Exception:
                remote_room_hosts = None
        elif RoomAlias.is_valid(room_identifier):
            handler = self.room_member_handler
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, remote_room_hosts = await handler.lookup_room_alias(room_alias)
            room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        fake_requester = create_requester(
            target_user, authenticated_entity=requester.authenticated_entity
        )

        # send invite if room has "JoinRules.INVITE"
        room_state = await self.state_handler.get_current_state(room_id)
        join_rules_event = room_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            if not (join_rules_event.content.get("join_rule") == JoinRules.PUBLIC):
                # update_membership with an action of "invite" can raise a
                # ShadowBanError. This is not handled since it is assumed that
                # an admin isn't going to call this API with a shadow-banned user.
                await self.room_member_handler.update_membership(
                    requester=requester,
                    target=fake_requester.user,
                    room_id=room_id,
                    action="invite",
                    remote_room_hosts=remote_room_hosts,
                    ratelimit=False,
                )

        await self.room_member_handler.update_membership(
            requester=fake_requester,
            target=fake_requester.user,
            room_id=room_id,
            action="join",
            remote_room_hosts=remote_room_hosts,
            ratelimit=False,
        )

        return 200, {"room_id": room_id}
