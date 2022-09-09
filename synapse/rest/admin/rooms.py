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
from typing import TYPE_CHECKING, List, Optional, Tuple, cast
from urllib import parse as urlparse

from synapse.api.constants import EventTypes, JoinRules, Membership
from synapse.api.errors import AuthError, Codes, NotFoundError, SynapseError
from synapse.api.filtering import Filter
from synapse.http.servlet import (
    ResolveRoomIdMixin,
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
from synapse.storage.state import StateFilter
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict, RoomID, UserID, create_requester
from synapse.util import json_decoder

if TYPE_CHECKING:
    from synapse.api.auth import Auth
    from synapse.handlers.pagination import PaginationHandler
    from synapse.handlers.room import RoomShutdownHandler
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RoomRestV2Servlet(RestServlet):
    """Delete a room from server asynchronously with a background task.

    It is a combination and improvement of shutdown and purge room.

    Shuts down a room by removing all local users from the room.
    Blocking all future invites and joins to the room is optional.

    If desired any local aliases will be repointed to a new room
    created by `new_room_user_id` and kicked users will be auto-
    joined to the new room.

    If 'purge' is true, it will remove all traces of a room from the database.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)$", "v2")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main
        self._pagination_handler = hs.get_pagination_handler()
        self._third_party_rules = hs.get_third_party_event_rules()

    async def on_DELETE(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:

        requester = await self._auth.get_user_by_req(request)
        await assert_user_is_admin(self._auth, requester)

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

        if not RoomID.is_valid(room_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "%s is not a legal room ID" % (room_id,)
            )

        # Check this here, as otherwise we'll only fail after the background job has been started.
        if not await self._third_party_rules.check_can_shutdown_room(
            requester.user.to_string(), room_id
        ):
            raise SynapseError(
                403, "Shutdown of this room is forbidden", Codes.FORBIDDEN
            )

        delete_id = self._pagination_handler.start_shutdown_and_purge_room(
            room_id=room_id,
            new_room_user_id=content.get("new_room_user_id"),
            new_room_name=content.get("room_name"),
            message=content.get("message"),
            requester_user_id=requester.user.to_string(),
            block=block,
            purge=purge,
            force_purge=force_purge,
        )

        return HTTPStatus.OK, {"delete_id": delete_id}


class DeleteRoomStatusByRoomIdRestServlet(RestServlet):
    """Get the status of the delete room background task."""

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/delete_status$", "v2")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._pagination_handler = hs.get_pagination_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:

        await assert_requester_is_admin(self._auth, request)

        if not RoomID.is_valid(room_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "%s is not a legal room ID" % (room_id,)
            )

        delete_ids = self._pagination_handler.get_delete_ids_by_room(room_id)
        if delete_ids is None:
            raise NotFoundError("No delete task for room_id '%s' found" % room_id)

        response = []
        for delete_id in delete_ids:
            delete = self._pagination_handler.get_delete_status(delete_id)
            if delete:
                response += [
                    {
                        "delete_id": delete_id,
                        **delete.asdict(),
                    }
                ]
        return HTTPStatus.OK, {"results": cast(JsonDict, response)}


class DeleteRoomStatusByDeleteIdRestServlet(RestServlet):
    """Get the status of the delete room background task."""

    PATTERNS = admin_patterns("/rooms/delete_status/(?P<delete_id>[^/]*)$", "v2")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._pagination_handler = hs.get_pagination_handler()

    async def on_GET(
        self, request: SynapseRequest, delete_id: str
    ) -> Tuple[int, JsonDict]:

        await assert_requester_is_admin(self._auth, request)

        delete_status = self._pagination_handler.get_delete_status(delete_id)
        if delete_status is None:
            raise NotFoundError("delete id '%s' not found" % delete_id)

        return HTTPStatus.OK, cast(JsonDict, delete_status.asdict())


class ListRoomRestServlet(RestServlet):
    """
    List all rooms that are known to the homeserver. Results are returned
    in a dictionary containing room information. Supports pagination.
    """

    PATTERNS = admin_patterns("/rooms$")

    def __init__(self, hs: "HomeServer"):
        self.store = hs.get_datastores().main
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        # Extract query parameters
        start = parse_integer(request, "from", default=0)
        limit = parse_integer(request, "limit", default=100)
        order_by = parse_string(
            request,
            "order_by",
            default=RoomSortOrder.NAME.value,
            allowed_values=[sort_order.value for sort_order in RoomSortOrder],
        )

        search_term = parse_string(request, "search_term", encoding="utf-8")
        if search_term == "":
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "search_term cannot be an empty string",
                errcode=Codes.INVALID_PARAM,
            )

        direction = parse_string(request, "dir", default="f")
        if direction not in ("f", "b"):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Unknown direction: %s" % (direction,),
                errcode=Codes.INVALID_PARAM,
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

        return HTTPStatus.OK, response


class RoomRestServlet(RestServlet):
    """Manage a room.

    On GET : Get details of a room.

    On DELETE : Delete a room from server.

    It is a combination and improvement of shutdown and purge room.

    Shuts down a room by removing all local users from the room.
    Blocking all future invites and joins to the room is optional.

    If desired any local aliases will be repointed to a new room
    created by `new_room_user_id` and kicked users will be auto-
    joined to the new room.

    If 'purge' is true, it will remove all traces of a room from the database.

    TODO: Add on_POST to allow room creation without joining the room
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self.room_shutdown_handler = hs.get_room_shutdown_handler()
        self.pagination_handler = hs.get_pagination_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room_with_stats(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        members = await self.store.get_users_in_room(room_id)
        ret["joined_local_devices"] = await self.store.count_devices_by_users(members)
        ret["forgotten"] = await self.store.is_locally_forgotten_room(room_id)

        return HTTPStatus.OK, ret

    async def on_DELETE(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        return await self._delete_room(
            request,
            room_id,
            self.auth,
            self.room_shutdown_handler,
            self.pagination_handler,
        )

    async def _delete_room(
        self,
        request: SynapseRequest,
        room_id: str,
        auth: "Auth",
        room_shutdown_handler: "RoomShutdownHandler",
        pagination_handler: "PaginationHandler",
    ) -> Tuple[int, JsonDict]:
        requester = await auth.get_user_by_req(request)
        await assert_user_is_admin(auth, requester)

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

        ret = await room_shutdown_handler.shutdown_room(
            room_id=room_id,
            new_room_user_id=content.get("new_room_user_id"),
            new_room_name=content.get("room_name"),
            message=content.get("message"),
            requester_user_id=requester.user.to_string(),
            block=block,
        )

        # Purge room
        if purge:
            try:
                await pagination_handler.purge_room(room_id, force=force_purge)
            except NotFoundError:
                if block:
                    # We can block unknown rooms with this endpoint, in which case
                    # a failed purge is expected.
                    pass
                else:
                    # But otherwise, we expect this purge to have succeeded.
                    raise

        # Cast safety: cast away the knowledge that this is a TypedDict.
        # See https://github.com/python/mypy/issues/4976#issuecomment-579883622
        # for some discussion on why this is necessary. Either way,
        # `ret` is an opaque dictionary blob as far as the rest of the app cares.
        return HTTPStatus.OK, cast(JsonDict, ret)


class RoomMembersRestServlet(RestServlet):
    """
    Get members list of a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/members$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        members = await self.store.get_users_in_room(room_id)
        ret = {"members": members, "total": len(members)}

        return HTTPStatus.OK, ret


class RoomStateRestServlet(RestServlet):
    """
    Get full state within a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/state$")

    def __init__(self, hs: "HomeServer"):
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.clock = hs.get_clock()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        ret = await self.store.get_room(room_id)
        if not ret:
            raise NotFoundError("Room not found")

        event_ids = await self._storage_controllers.state.get_current_state_ids(room_id)
        events = await self.store.get_events(event_ids.values())
        now = self.clock.time_msec()
        room_state = self._event_serializer.serialize_events(events.values(), now)
        ret = {"state": room_state}

        return HTTPStatus.OK, ret


class JoinRoomAliasServlet(ResolveRoomIdMixin, RestServlet):

    PATTERNS = admin_patterns("/join/(?P<room_identifier>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.auth = hs.get_auth()
        self.admin_handler = hs.get_admin_handler()
        self.store = hs.get_datastores().main
        self._storage_controllers = hs.get_storage_controllers()
        self.is_mine = hs.is_mine

    async def on_POST(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
        # This will always be set by the time Twisted calls us.
        assert request.args is not None

        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)

        content = parse_json_object_from_request(request)

        assert_params_in_dict(content, ["user_id"])
        target_user = UserID.from_string(content["user_id"])

        if not self.is_mine(target_user):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "This endpoint can only be used with local users",
            )

        if not await self.admin_handler.get_user(target_user):
            raise NotFoundError("User not found")

        # Get the room ID from the identifier.
        try:
            remote_room_hosts: Optional[List[str]] = [
                x.decode("ascii") for x in request.args[b"server_name"]
            ]
        except Exception:
            remote_room_hosts = None
        room_id, remote_room_hosts = await self.resolve_room_id(
            room_identifier, remote_room_hosts
        )

        fake_requester = create_requester(
            target_user, authenticated_entity=requester.authenticated_entity
        )

        # send invite if room has "JoinRules.INVITE"
        join_rules_event = (
            await self._storage_controllers.state.get_current_state_event(
                room_id, EventTypes.JoinRules, ""
            )
        )
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

        return HTTPStatus.OK, {"room_id": room_id}


class MakeRoomAdminRestServlet(ResolveRoomIdMixin, RestServlet):
    """Allows a server admin to get power in a room if a local user has power in
    a room. Will also invite the user if they're not in the room and it's a
    private room. Can specify another user (rather than the admin user) to be
    granted power, e.g.:

        POST/_synapse/admin/v1/rooms/<room_id_or_alias>/make_room_admin
        {
            "user_id": "@foo:example.com"
        }
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_identifier>[^/]*)/make_room_admin$")

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self._state_storage_controller = hs.get_storage_controllers().state
        self.event_creation_handler = hs.get_event_creation_handler()
        self.state_handler = hs.get_state_handler()
        self.is_mine_id = hs.is_mine_id

    async def on_POST(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        await assert_user_is_admin(self.auth, requester)
        content = parse_json_object_from_request(request, allow_empty_body=True)

        room_id, _ = await self.resolve_room_id(room_identifier)

        # Which user to grant room admin rights to.
        user_to_add = content.get("user_id", requester.user.to_string())

        # Figure out which local users currently have power in the room, if any.
        filtered_room_state = await self._state_storage_controller.get_current_state(
            room_id,
            StateFilter.from_types(
                [
                    (EventTypes.Create, ""),
                    (EventTypes.PowerLevels, ""),
                    (EventTypes.JoinRules, ""),
                    (EventTypes.Member, user_to_add),
                ]
            ),
        )
        if not filtered_room_state:
            raise SynapseError(HTTPStatus.BAD_REQUEST, "Server not in room")

        create_event = filtered_room_state[(EventTypes.Create, "")]
        power_levels = filtered_room_state.get((EventTypes.PowerLevels, ""))

        if power_levels is not None:
            # We pick the local user with the highest power.
            user_power = power_levels.content.get("users", {})
            admin_users = [
                user_id for user_id in user_power if self.is_mine_id(user_id)
            ]
            admin_users.sort(key=lambda user: user_power[user])

            if not admin_users:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST, "No local admin user in room"
                )

            admin_user_id = None

            for admin_user in reversed(admin_users):
                (
                    current_membership_type,
                    _,
                ) = await self.store.get_local_current_membership_for_user_in_room(
                    admin_user, room_id
                )
                if current_membership_type == "join":
                    admin_user_id = admin_user
                    break

            if not admin_user_id:
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
                    "No local admin user in room",
                )

            pl_content = power_levels.content
        else:
            # If there is no power level events then the creator has rights.
            pl_content = {}
            admin_user_id = create_event.sender
            if not self.is_mine_id(admin_user_id):
                raise SynapseError(
                    HTTPStatus.BAD_REQUEST,
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
                HTTPStatus.BAD_REQUEST,
                "No local admin user in room with power to update power levels.",
            )

        # Now we check if the user we're granting admin rights to is already in
        # the room. If not and it's not a public room we invite them.
        member_event = filtered_room_state.get((EventTypes.Member, user_to_add))
        is_joined = False
        if member_event:
            is_joined = member_event.content["membership"] in (
                Membership.JOIN,
                Membership.INVITE,
            )

        if is_joined:
            return HTTPStatus.OK, {}

        join_rules = filtered_room_state.get((EventTypes.JoinRules, ""))
        is_public = False
        if join_rules:
            is_public = join_rules.content.get("join_rule") == JoinRules.PUBLIC

        if is_public:
            return HTTPStatus.OK, {}

        await self.room_member_handler.update_membership(
            fake_requester,
            target=UserID.from_string(user_to_add),
            room_id=room_id,
            action=Membership.INVITE,
        )

        return HTTPStatus.OK, {}


class ForwardExtremitiesRestServlet(ResolveRoomIdMixin, RestServlet):
    """Allows a server admin to get or clear forward extremities.

    Clearing does not require restarting the server.

        Clear forward extremities:
        DELETE /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities

        Get forward_extremities:
        GET /_synapse/admin/v1/rooms/<room_id_or_alias>/forward_extremities
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_identifier>[^/]*)/forward_extremities$")

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_DELETE(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        room_id, _ = await self.resolve_room_id(room_identifier)

        deleted_count = await self.store.delete_forward_extremities_for_room(room_id)
        return HTTPStatus.OK, {"deleted": deleted_count}

    async def on_GET(
        self, request: SynapseRequest, room_identifier: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self.auth, request)

        room_id, _ = await self.resolve_room_id(room_identifier)

        extremities = await self.store.get_forward_extremities_for_room(room_id)
        return HTTPStatus.OK, {"count": len(extremities), "results": extremities}


class RoomEventContextServlet(RestServlet):
    """
    Provide the context for an event.
    This API is designed to be used when system administrators wish to look at
    an abuse report and understand what happened during and immediately prior
    to this event.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/context/(?P<event_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._hs = hs
        self.clock = hs.get_clock()
        self.room_context_handler = hs.get_room_context_handler()
        self._event_serializer = hs.get_event_client_serializer()
        self.auth = hs.get_auth()

    async def on_GET(
        self, request: SynapseRequest, room_id: str, event_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=False)
        await assert_user_is_admin(self.auth, requester)

        limit = parse_integer(request, "limit", default=10)

        # picking the API shape for symmetry with /messages
        filter_str = parse_string(request, "filter", encoding="utf-8")
        if filter_str:
            filter_json = urlparse.unquote(filter_str)
            event_filter: Optional[Filter] = Filter(
                self._hs, json_decoder.decode(filter_json)
            )
        else:
            event_filter = None

        event_context = await self.room_context_handler.get_event_context(
            requester,
            room_id,
            event_id,
            limit,
            event_filter,
            use_admin_priviledge=True,
        )

        if not event_context:
            raise SynapseError(
                HTTPStatus.NOT_FOUND, "Event not found.", errcode=Codes.NOT_FOUND
            )

        time_now = self.clock.time_msec()
        results = {
            "events_before": self._event_serializer.serialize_events(
                event_context.events_before,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "event": self._event_serializer.serialize_event(
                event_context.event,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "events_after": self._event_serializer.serialize_events(
                event_context.events_after,
                time_now,
                bundle_aggregations=event_context.aggregations,
            ),
            "state": self._event_serializer.serialize_events(
                event_context.state, time_now
            ),
            "start": event_context.start,
            "end": event_context.end,
        }

        return HTTPStatus.OK, results


class BlockRoomRestServlet(RestServlet):
    """
    Manage blocking of rooms.
    On PUT: Add or remove a room from blocking list.
    On GET: Get blocking status of room and user who has blocked this room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/block$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        await assert_requester_is_admin(self._auth, request)

        if not RoomID.is_valid(room_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "%s is not a legal room ID" % (room_id,)
            )

        blocked_by = await self._store.room_is_blocked_by(room_id)
        # Test `not None` if `user_id` is an empty string
        # if someone add manually an entry in database
        if blocked_by is not None:
            response = {"block": True, "user_id": blocked_by}
        else:
            response = {"block": False}

        return HTTPStatus.OK, response

    async def on_PUT(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        await assert_user_is_admin(self._auth, requester)

        content = parse_json_object_from_request(request)

        if not RoomID.is_valid(room_id):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST, "%s is not a legal room ID" % (room_id,)
            )

        assert_params_in_dict(content, ["block"])
        block = content.get("block")
        if not isinstance(block, bool):
            raise SynapseError(
                HTTPStatus.BAD_REQUEST,
                "Param 'block' must be a boolean.",
                Codes.BAD_JSON,
            )

        if block:
            await self._store.block_room(room_id, requester.user.to_string())
        else:
            await self._store.unblock_room(room_id)

        return HTTPStatus.OK, {"block": block}


class RoomMessagesRestServlet(RestServlet):
    """
    Get messages list of a room.
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/messages$")

    def __init__(self, hs: "HomeServer"):
        self._hs = hs
        self._clock = hs.get_clock()
        self._pagination_handler = hs.get_pagination_handler()
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        await assert_user_is_admin(self._auth, requester)

        pagination_config = await PaginationConfig.from_request(
            self._store, request, default_limit=10
        )
        # Twisted will have processed the args by now.
        assert request.args is not None
        as_client_event = b"raw" not in request.args
        filter_str = parse_string(request, "filter", encoding="utf-8")
        if filter_str:
            filter_json = urlparse.unquote(filter_str)
            event_filter: Optional[Filter] = Filter(
                self._hs, json_decoder.decode(filter_json)
            )
            if (
                event_filter
                and event_filter.filter_json.get("event_format", "client")
                == "federation"
            ):
                as_client_event = False
        else:
            event_filter = None

        msgs = await self._pagination_handler.get_messages(
            room_id=room_id,
            requester=requester,
            pagin_config=pagination_config,
            as_client_event=as_client_event,
            event_filter=event_filter,
            use_admin_priviledge=True,
        )

        return HTTPStatus.OK, msgs


class RoomTimestampToEventRestServlet(RestServlet):
    """
    API endpoint to fetch the `event_id` of the closest event to the given
    timestamp (`ts` query parameter) in the given direction (`dir` query
    parameter).

    Useful for cases like jump to date so you can start paginating messages from
    a given date in the archive.

    `ts` is a timestamp in milliseconds where we will find the closest event in
    the given direction.

    `dir` can be `f` or `b` to indicate forwards and backwards in time from the
    given timestamp.

    GET /_synapse/admin/v1/rooms/<roomID>/timestamp_to_event?ts=<timestamp>&dir=<direction>
    {
        "event_id": ...
    }
    """

    PATTERNS = admin_patterns("/rooms/(?P<room_id>[^/]*)/timestamp_to_event$")

    def __init__(self, hs: "HomeServer"):
        self._auth = hs.get_auth()
        self._store = hs.get_datastores().main
        self._timestamp_lookup_handler = hs.get_timestamp_lookup_handler()

    async def on_GET(
        self, request: SynapseRequest, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self._auth.get_user_by_req(request)
        await assert_user_is_admin(self._auth, requester)

        timestamp = parse_integer(request, "ts", required=True)
        direction = parse_string(request, "dir", default="f", allowed_values=["f", "b"])

        (
            event_id,
            origin_server_ts,
        ) = await self._timestamp_lookup_handler.get_event_for_timestamp(
            requester, room_id, timestamp, direction
        )

        return HTTPStatus.OK, {
            "event_id": event_id,
            "origin_server_ts": origin_server_ts,
        }
