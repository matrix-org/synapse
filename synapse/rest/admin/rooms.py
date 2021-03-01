# -*- coding: utf-8 -*-
# Copyright 2019-2021 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, List, Optional, Tuple
from urllib import parse as urlparse

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.api.filtering import Filter
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_integer,
    parse_json_object_from_request,
    parse_string,
)
from synapse.http.site import SynapseRequest
from synapse.rest.admin._base import (
    admin_patterns,
    assert_requester_is_admin,
    assert_user_is_admin,
)
from synapse.storage.databases.main.room import RoomSortOrder
from synapse.types import JsonDict, RoomAlias, RoomID, UserID, create_requester
from synapse.util import json_decoder

if TYPE_CHECKING:
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class ShutdownRoomRestServlet(RestServlet):
    """Shuts down a room by removing all local users from the room and blocking
    all future invites and joins to the room. Any local aliases will be repointed
    to a new room created by `new_room_user_id` and kicked users will be auto
    joined to the new room.
    """

    PATTERNS = admin_patterns("/shutdown_room/(?P<room_id>[^/]+)")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_shutdown_handler = hs.get_room_shutdown_handler()

    async def on_POST(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
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
    """Delete a room from server.

    It is a combination and improvement of shutdown and purge room.

    Shuts down a room by removing all local users from the room.
    Blocking all future invites and joins to the room is optional.

    If desired any local aliases will be repointed to a new room
    created by `new_room_user_id` and kicked users will be auto-
    joined to the new room.

    If 'purge' is true, it will remove all traces of a room from the database.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)/delete$")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_shutdown_handler = hs.get_room_shutdown_handler()
        self.pagination_handler = hs.get_pagination_handler()

    async def on_POST(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
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

        force_purge = content.get("force_purge", False)
        if not isinstance(force_purge, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'force_purge' must be a boolean, if given",
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
            await self.pagination_handler.purge_room(room_id, force=force_purge)

        return (200, ret)


class ListRoomRestServlet(RestServlet):
    """
    List all rooms that are known to the homeserver. Results are returned
    in a dictionary containing room information. Supports pagination.
    """

    PATTERNS = admin_patterns("/rooms$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
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

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room_with_stats(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        members = await self.store.get_users_in_room(room_id)
        ret["joined_local_devices"] = await self.store.count_devices_by_users(members)

        return (200, ret)


class RoomMembersRestServlet(RestServlet):
    """
    Get members list of a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)/members")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        members = await self.store.get_users_in_room(room_id)
        ret = {"members": members, "total": len(members)}

        return 200, ret


class RoomStateRestServlet(RestServlet):
    """
    Get full state within a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]+)/state")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        ret = await self.store.get_room(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        event_ids = await self.store.get_current_state_ids(room_id)
        events = await self.store.get_events(event_ids.values())
        now = self.clock.time_msec()
        room_state = await self._event_serializer.serialize_events(
            events.values(),
            now,
            # We don't bother bundling aggregations in when asked for state
            # events, as clients won't use them.
            bundle_aggregations=False,
        )
        ret = {"state": room_state}

        return 200, ret


class JoinRoomAliasServlet(RestServlet):

    PATTERNS = admin_patterns("/join/(?P<room_identifier>[^/]*)")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_member_handler = hs.get_room_member_handler()
        self.admin_handler = hs.get_admin_handler()
        self.state_handler = hs.get_state_handler()

    async def on_POST(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
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


class MakeRoomAdminRestServlet(RestServlet):
    """Allows a server admin to get power in a room if a local user has power in
    a room. Will also invite the user if they're not in the room and it's a
    private room. Can specify another user (rather than the admin user) to be
    granted power, e.g.:

        POST/_synapse/admin/v1/rooms/<room_id_or_alias>/make_room_admin
        {
            "user_id": "@foo:example.com"
        }
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_identifier>[^/]*)/make_room_admin")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_member_handler = hs.get_room_member_handler()
        self.event_creation_handler = hs.get_event_creation_handler()
        self.state_handler = hs.get_state_handler()
        self.is_mine_id = hs.is_mine_id

    async def on_POST(self, request, room_identifier):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)
        content = parse_json_object_from_request(request, allow_empty_body=True)

        # Resolve to a room ID, if necessary.
        if RoomID.is_valid(room_identifier):
            room_id = room_identifier
        elif RoomAlias.is_valid(room_identifier):
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, _ = await self.room_member_handler.lookup_room_alias(room_alias)
            room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )

        # Which user to grant room admin rights to.
        user_to_add = content.get("user_id", requester.user.to_string())

        # Figure out which local users currently have power in the room, if any.
        room_state = await self.state_handler.get_current_state(room_id)
        if not room_state:
            raise SynapseError(400, "Server not in room")

        create_event = room_state[(EventTypes.Create, "")]
        power_levels = room_state.get((EventTypes.PowerLevels, ""))

        if power_levels is not None:
            # We pick the local user with the highest power.
            user_power = power_levels.content.get("users", {})
            admin_users = [
                user_id for user_id in user_power if self.is_mine_id(user_id)
            ]
            admin_users.sort(key=lambda user: user_power[user])

            if not admin_users:
                raise SynapseError(400, "No local admin user in room")

            admin_user_id = None

            for admin_user in reversed(admin_users):
                if room_state.get((EventTypes.Member, admin_user)):
                    admin_user_id = admin_user
                    break

            if not admin_user_id:
                raise SynapseError(
                    400,
                    "No local admin user in room",
                )

            pl_content = power_levels.content
        else:
            # If there is no power level events then the creator has rights.
            pl_content = {}
            admin_user_id = create_event.sender
            if not self.is_mine_id(admin_user_id):
                raise SynapseError(
                    400,
                    "No local admin user in room",
                )

        # Grant the user power equal to the room admin by attempting to send an
        # updated power level event.
        new_pl_content = dict(pl_content)
        new_pl_content["users"] = dict(pl_content.get("users", {}))
        new_pl_content["users"][user_to_add] = new_pl_content["users"][admin_user_id]

        fake_requester = create_requester(
            admin_user_id,
            authenticated_entity=requester.authenticated_entity,
        )

        try:
            await self.event_creation_handler.create_and_send_nonmember_event(
                fake_requester,
                event_dict={
                    "content": new_pl_content,
                    "sender": admin_user_id,
                    "type": EventTypes.PowerLevels,
                    "state_key": "",
                    "room_id": room_id,
                },
            )
        except AuthError:
            # The admin user we found turned out not to have enough power.
            raise SynapseError(
                400, "No local admin user in room with power to update power levels."
            )

        # Now we check if the user we're granting admin rights to is already in
        # the room. If not and it's not a public room we invite them.
        member_event = room_state.get((EventTypes.Member, user_to_add))
        is_joined = False
        if member_event:
            is_joined = member_event.content["membership"] in (
                Membership.JOIN,
                Membership.INVITE,
            )

        if is_joined:
            return 200, {}

        join_rules = room_state.get((EventTypes.JoinRules, ""))
        is_public = False
        if join_rules:
            is_public = join_rules.content.get("join_rule") == JoinRules.PUBLIC

        if is_public:
            return 200, {}

        await self.room_member_handler.update_membership(
            fake_requester,
            target=UserID.from_string(user_to_add),
            room_id=room_id,
            action=Membership.INVITE,
        )

        return 200, {}


class ForwardExtremitiesRestServlet(RestServlet):
    """Allows a server admin to get or clear forward extremities.

    Clearing does not require restarting the server.

        Clear forward extremities:
        DELETE /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities

        Get forward_extremities:
        GET /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_identifier>[^/]*)/forward_extremities")

    def __init__(self, hs: "HomeServer"):
        self.hs = hs
        self.auth = hs.get_auth()
        self.room_member_handler = hs.get_room_member_handler()
        self.store = hs.get_datastore()

    async def resolve_room_id(self, room_identifier: str) -> str:
        """Resolve to a room ID, if necessary."""
        if RoomID.is_valid(room_identifier):
            resolved_room_id = room_identifier
        elif RoomAlias.is_valid(room_identifier):
            room_alias = RoomAlias.from_string(room_identifier)
            room_id, _ = await self.room_member_handler.lookup_room_alias(room_alias)
            resolved_room_id = room_id.to_string()
        else:
            raise SynapseError(
                400, "%s was not legal room ID or room alias" % (room_identifier,)
            )
        if not resolved_room_id:
            raise SynapseError(
                400, "Unknown room ID or room alias %s" % room_identifier
            )
        return resolved_room_id

    async def on_DELETE(self, request, room_identifier):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        room_id = await self.resolve_room_id(room_identifier)

        deleted_count = await self.store.delete_forward_extremities_for_room(room_id)
        return 200, {"deleted": deleted_count}

    async def on_GET(self, request, room_identifier):
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester.user)

        room_id = await self.resolve_room_id(room_identifier)

        extremities = await self.store.get_forward_extremities_for_room(room_id)
        return 200, {"count": len(extremities), "results": extremities}


class RoomEventContextServlet(RestServlet):
    """
    Provide the context for an event.
    This API is designed to be used when system administrators wish to look at
    an abuse report and understand what happened during and immediately prior
    to this event.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/context/(?P<event_id>[^/]*)$")

    def __init__(self, hs):
        super().__init__()
        self.clock = hs.get_clock()
        self.room_context_handler = hs.get_room_context_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self.auth = hs.get_auth()

    async def on_GET(self, request, room_id, event_id):
        requester = await self.auth.get_user_by_req(request, allow_guest=False)
        await assert_user_is_admin(self.auth, requester.user)

        limit = parse_integer(request, "limit", default=10)

        # picking the API shape for symmetry with /messages
        filter_str = parse_string(request, b"filter", encoding="utf-8")
        if filter_str:
            filter_json = urlparse.unquote(filter_str)
            event_filter = Filter(
                json_decoder.decode(filter_json)
            )  # type: Optional[Filter]
        else:
            event_filter = None

        results = await self.room_context_handler.get_event_context(
            requester,
            room_id,
            event_id,
            limit,
            event_filter,
            use_admin_priviledge=True,
        )

        if not results:
            raise SynapseError(404, "Event not found.", errcode=Codes.NOT_FOUND)

        time_now = self.clock.time_msec()
        results["events_before"] = await self._event_serializer.serialize_events(
            results["events_before"], time_now
        )
        results["event"] = await self._event_serializer.serialize_event(
            results["event"], time_now
        )
        results["events_after"] = await self._event_serializer.serialize_events(
            results["events_after"], time_now
        )
        results["state"] = await self._event_serializer.serialize_events(
            results["state"], time_now
        )

        return 200, results
