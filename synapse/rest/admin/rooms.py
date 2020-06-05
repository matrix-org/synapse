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
from typing import List, Optional

from synapse.api.constants import EventTypes, JoinRules, Membership
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
from synapse.storage.data_stores.main.room import RoomSortOrder
from synapse.types import RoomAlias, RoomID, UserID, create_requester
from synapse.util.async_helpers import maybe_awaitable

logger = logging.getLogger(__name__)


class ShutdownRoomRestServlet(RestServlet):
    """Shuts down a room by removing all local users from the room and blocking
    all future invites and joins to the room. Any local aliases will be repointed
    to a new room created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    """

    PATTERNS = historical_admin_path_patterns("/shutdown_room/(?P<room_id>[^/]+)")

    DEFAULT_MESSAGE = (
        "Sharing illegal content on this server is not permitted and rooms in"
        " violation will be blocked."
    )

    def __init__(self, hs):
        self.hs = hs
        self.store = hs.get_datastore()
        self.state = hs.get_state_handler()
        self._room_creation_handler = hs.get_room_creation_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.room_member_handler = hs.get_room_member_handler()
        self.auth = hs.get_auth()
        self._replication = hs.get_replication_data_handler()

    async def on_POST(self, request, room_id):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        content = parse_json_object_from_request(request)
        assert_params_in_dict(content, ["new_room_user_id"])
        new_room_user_id = content["new_room_user_id"]

        room_creator_requester = create_requester(new_room_user_id)

        message = content.get("message", self.DEFAULT_MESSAGE)
        room_name = content.get("room_name", "Content Violation Notification")

        info, stream_id = await self._room_creation_handler.create_room(
            room_creator_requester,
            config={
                "preset": "public_chat",
                "name": room_name,
                "power_level_content_override": {"users_default": -10},
            },
            ratelimit=False,
        )
        new_room_id = info["room_id"]

        requester_user_id = requester.user.to_string()

        logger.info(
            "Shutting down room %r, joining to new room: %r", room_id, new_room_id
        )

        # This will work even if the room is already blocked, but that is
        # desirable in case the first attempt at blocking the room failed below.
        await self.store.block_room(room_id, requester_user_id)

        # We now wait for the create room to come back in via replication so
        # that we can assume that all the joins/invites have propogated before
        # we try and auto join below.
        #
        # TODO: Currently the events stream is written to from master
        await self._replication.wait_for_stream_position(
            self.hs.config.worker.writers.events, "events", stream_id
        )

        users = await self.state.get_current_users_in_room(room_id)
        kicked_users = []
        failed_to_kick_users = []
        for user_id in users:
            if not self.hs.is_mine_id(user_id):
                continue

            logger.info("Kicking %r from %r...", user_id, room_id)

            try:
                target_requester = create_requester(user_id)
                _, stream_id = await self.room_member_handler.update_membership(
                    requester=target_requester,
                    target=target_requester.user,
                    room_id=room_id,
                    action=Membership.LEAVE,
                    content={},
                    ratelimit=False,
                    require_consent=False,
                )

                # Wait for leave to come in over replication before trying to forget.
                await self._replication.wait_for_stream_position(
                    self.hs.config.worker.writers.events, "events", stream_id
                )

                await self.room_member_handler.forget(target_requester.user, room_id)

                await self.room_member_handler.update_membership(
                    requester=target_requester,
                    target=target_requester.user,
                    room_id=new_room_id,
                    action=Membership.JOIN,
                    content={},
                    ratelimit=False,
                    require_consent=False,
                )

                kicked_users.append(user_id)
            except Exception:
                logger.exception(
                    "Failed to leave old room and join new room for %r", user_id
                )
                failed_to_kick_users.append(user_id)

        await self.event_creation_handler.create_and_send_nonmember_event(
            room_creator_requester,
            {
                "type": "m.room.message",
                "content": {"body": message, "msgtype": "m.text"},
                "room_id": new_room_id,
                "sender": new_room_user_id,
            },
            ratelimit=False,
        )

        aliases_for_room = await maybe_awaitable(
            self.store.get_aliases_for_room(room_id)
        )

        await self.store.update_aliases_for_room(
            room_id, new_room_id, requester_user_id
        )

        return (
            200,
            {
                "kicked_users": kicked_users,
                "failed_to_kick_users": failed_to_kick_users,
                "local_aliases": aliases_for_room,
                "new_room_id": new_room_id,
            },
        )


class ListRoomRestServlet(RestServlet):
    """
    List all rooms that are known to the homeserver. Results are returned
    in a dictionary containing room information. Supports pagination.
    """

    PATTERNS = admin_patterns("/rooms$")

    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_handlers().admin_handler

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


class JoinRoomAliasServlet(RestServlet):

    PATTERNS = admin_patterns("/join/(?P<room_identifier>[^/]*)")

    def __init__(self, hs):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_member_handler = hs.get_room_member_handler()
        self.admin_handler = hs.get_handlers().admin_handler
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

        fake_requester = create_requester(target_user)

        # send invite if room has "JoinRules.INVITE"
        room_state = await self.state_handler.get_current_state(room_id)
        join_rules_event = room_state.get((EventTypes.JoinRules, ""))
        if join_rules_event:
            if not (join_rules_event.content.get("join_rule") == JoinRules.PUBLIC):
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
