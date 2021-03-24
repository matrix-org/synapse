# -*- coding: utf-8 -*-
# Copyright 2017 Vector Creations Ltd
# Copyright 2018 New Vector Ltd
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
from functools import wraps
from typing import TYPE_CHECKING, Optional, Tuple

from twisted.web.server import Request

from synapse.api.constants import (
    MAX_GROUP_CATEGORYID_LENGTH,
    MAX_GROUP_ROLEID_LENGTH,
    MAX_GROUPID_LENGTH,
)
from synapse.api.errors import Codes, SynapseError
from synapse.handlers.groups_local import GroupsLocalHandler
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.types import GroupID, JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


def _validate_group_id(f):
    """Wrapper to validate the form of the group ID.

    Can be applied to any on_FOO methods that accepts a group ID as a URL parameter.
    """

    @wraps(f)
    def wrapper(self, request: Request, group_id: str, *args, **kwargs):
        if not GroupID.is_valid(group_id):
            raise SynapseError(400, "%s is not a legal group ID" % (group_id,))

        return f(self, request, group_id, *args, **kwargs)

    return wrapper


class GroupServlet(RestServlet):
    """Get the group profile"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/profile$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        group_description = await self.groups_handler.get_group_profile(
            group_id, requester_user_id
        )

        return 200, group_description

    @_validate_group_id
    async def on_POST(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert_params_in_dict(
            content, ("name", "avatar_url", "short_description", "long_description")
        )
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot create group profiles."
        await self.groups_handler.update_group_profile(
            group_id, requester_user_id, content
        )

        return 200, {}


class GroupSummaryServlet(RestServlet):
    """Get the full group summary"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/summary$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        get_group_summary = await self.groups_handler.get_group_summary(
            group_id, requester_user_id
        )

        return 200, get_group_summary


class GroupSummaryRoomsCatServlet(RestServlet):
    """Update/delete a rooms entry in the summary.

    Matches both:
        - /groups/:group/summary/rooms/:room_id
        - /groups/:group/summary/categories/:category/rooms/:room_id
    """

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/categories/(?P<category_id>[^/]+))?"
        "/rooms/(?P<room_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self,
        request: SynapseRequest,
        group_id: str,
        category_id: Optional[str],
        room_id: str,
    ):
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty", Codes.INVALID_PARAM)

        if category_id and len(category_id) > MAX_GROUP_CATEGORYID_LENGTH:
            raise SynapseError(
                400,
                "category_id may not be longer than %s characters"
                % (MAX_GROUP_CATEGORYID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group summaries."
        resp = await self.groups_handler.update_group_summary_room(
            group_id,
            requester_user_id,
            room_id=room_id,
            category_id=category_id,
            content=content,
        )

        return 200, resp

    @_validate_group_id
    async def on_DELETE(
        self, request: SynapseRequest, group_id: str, category_id: str, room_id: str
    ):
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group profiles."
        resp = await self.groups_handler.delete_group_summary_room(
            group_id, requester_user_id, room_id=room_id, category_id=category_id
        )

        return 200, resp


class GroupCategoryServlet(RestServlet):
    """Get/add/update/delete a group category"""

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/categories/(?P<category_id>[^/]+)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str, category_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        category = await self.groups_handler.get_group_category(
            group_id, requester_user_id, category_id=category_id
        )

        return 200, category

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str, category_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        if not category_id:
            raise SynapseError(400, "category_id cannot be empty", Codes.INVALID_PARAM)

        if len(category_id) > MAX_GROUP_CATEGORYID_LENGTH:
            raise SynapseError(
                400,
                "category_id may not be longer than %s characters"
                % (MAX_GROUP_CATEGORYID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group categories."
        resp = await self.groups_handler.update_group_category(
            group_id, requester_user_id, category_id=category_id, content=content
        )

        return 200, resp

    @_validate_group_id
    async def on_DELETE(
        self, request: SynapseRequest, group_id: str, category_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group categories."
        resp = await self.groups_handler.delete_group_category(
            group_id, requester_user_id, category_id=category_id
        )

        return 200, resp


class GroupCategoriesServlet(RestServlet):
    """Get all group categories"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/categories/$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        category = await self.groups_handler.get_group_categories(
            group_id, requester_user_id
        )

        return 200, category


class GroupRoleServlet(RestServlet):
    """Get/add/update/delete a group role"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/roles/(?P<role_id>[^/]+)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str, role_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        category = await self.groups_handler.get_group_role(
            group_id, requester_user_id, role_id=role_id
        )

        return 200, category

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str, role_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        if not role_id:
            raise SynapseError(400, "role_id cannot be empty", Codes.INVALID_PARAM)

        if len(role_id) > MAX_GROUP_ROLEID_LENGTH:
            raise SynapseError(
                400,
                "role_id may not be longer than %s characters"
                % (MAX_GROUP_ROLEID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group roles."
        resp = await self.groups_handler.update_group_role(
            group_id, requester_user_id, role_id=role_id, content=content
        )

        return 200, resp

    @_validate_group_id
    async def on_DELETE(
        self, request: SynapseRequest, group_id: str, role_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group roles."
        resp = await self.groups_handler.delete_group_role(
            group_id, requester_user_id, role_id=role_id
        )

        return 200, resp


class GroupRolesServlet(RestServlet):
    """Get all group roles"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/roles/$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        category = await self.groups_handler.get_group_roles(
            group_id, requester_user_id
        )

        return 200, category


class GroupSummaryUsersRoleServlet(RestServlet):
    """Update/delete a user's entry in the summary.

    Matches both:
        - /groups/:group/summary/users/:room_id
        - /groups/:group/summary/roles/:role/users/:user_id
    """

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/roles/(?P<role_id>[^/]+))?"
        "/users/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self,
        request: SynapseRequest,
        group_id: str,
        role_id: Optional[str],
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty", Codes.INVALID_PARAM)

        if role_id and len(role_id) > MAX_GROUP_ROLEID_LENGTH:
            raise SynapseError(
                400,
                "role_id may not be longer than %s characters"
                % (MAX_GROUP_ROLEID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group summaries."
        resp = await self.groups_handler.update_group_summary_user(
            group_id,
            requester_user_id,
            user_id=user_id,
            role_id=role_id,
            content=content,
        )

        return 200, resp

    @_validate_group_id
    async def on_DELETE(
        self, request: SynapseRequest, group_id: str, role_id: str, user_id: str
    ):
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group summaries."
        resp = await self.groups_handler.delete_group_summary_user(
            group_id, requester_user_id, user_id=user_id, role_id=role_id
        )

        return 200, resp


class GroupRoomServlet(RestServlet):
    """Get all rooms in a group"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/rooms$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        result = await self.groups_handler.get_rooms_in_group(
            group_id, requester_user_id
        )

        return 200, result


class GroupUsersServlet(RestServlet):
    """Get all users in a group"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/users$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        result = await self.groups_handler.get_users_in_group(
            group_id, requester_user_id
        )

        return 200, result


class GroupInvitedUsersServlet(RestServlet):
    """Get users invited to a group"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/invited_users$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_GET(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        result = await self.groups_handler.get_invited_users_in_group(
            group_id, requester_user_id
        )

        return 200, result


class GroupSettingJoinPolicyServlet(RestServlet):
    """Set group join policy"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/settings/m.join_policy$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group join policy."
        result = await self.groups_handler.set_group_join_policy(
            group_id, requester_user_id, content
        )

        return 200, result


class GroupCreateServlet(RestServlet):
    """Create a group"""

    PATTERNS = client_patterns("/create_group$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()
        self.server_name = hs.hostname

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        # TODO: Create group on remote server
        content = parse_json_object_from_request(request)
        localpart = content.pop("localpart")
        group_id = GroupID(localpart, self.server_name).to_string()

        if not localpart:
            raise SynapseError(400, "Group ID cannot be empty", Codes.INVALID_PARAM)

        if len(group_id) > MAX_GROUPID_LENGTH:
            raise SynapseError(
                400,
                "Group ID may not be longer than %s characters" % (MAX_GROUPID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot create groups."
        result = await self.groups_handler.create_group(
            group_id, requester_user_id, content
        )

        return 200, result


class GroupAdminRoomsServlet(RestServlet):
    """Add a room to the group"""

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/rooms/(?P<room_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify rooms in a group."
        result = await self.groups_handler.add_room_to_group(
            group_id, requester_user_id, room_id, content
        )

        return 200, result

    @_validate_group_id
    async def on_DELETE(
        self, request: SynapseRequest, group_id: str, room_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group categories."
        result = await self.groups_handler.remove_room_from_group(
            group_id, requester_user_id, room_id
        )

        return 200, result


class GroupAdminRoomsConfigServlet(RestServlet):
    """Update the config of a room in a group"""

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/rooms/(?P<room_id>[^/]*)"
        "/config/(?P<config_key>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str, room_id: str, config_key: str
    ):
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot modify group categories."
        result = await self.groups_handler.update_room_in_group(
            group_id, requester_user_id, room_id, config_key, content
        )

        return 200, result


class GroupAdminUsersInviteServlet(RestServlet):
    """Invite a user to the group"""

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/users/invite/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()
        self.store = hs.get_datastore()
        self.is_mine_id = hs.is_mine_id

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id, user_id
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        config = content.get("config", {})
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot invite users to a group."
        result = await self.groups_handler.invite(
            group_id, user_id, requester_user_id, config
        )

        return 200, result


class GroupAdminUsersKickServlet(RestServlet):
    """Kick a user from the group"""

    PATTERNS = client_patterns(
        "/groups/(?P<group_id>[^/]*)/admin/users/remove/(?P<user_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id, user_id
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot kick users from a group."
        result = await self.groups_handler.remove_user_from_group(
            group_id, user_id, requester_user_id, content
        )

        return 200, result


class GroupSelfLeaveServlet(RestServlet):
    """Leave a joined group"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/self/leave$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot leave a group for a users."
        result = await self.groups_handler.remove_user_from_group(
            group_id, requester_user_id, requester_user_id, content
        )

        return 200, result


class GroupSelfJoinServlet(RestServlet):
    """Attempt to join a group, or knock"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/self/join$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot join a user to a group."
        result = await self.groups_handler.join_group(
            group_id, requester_user_id, content
        )

        return 200, result


class GroupSelfAcceptInviteServlet(RestServlet):
    """Accept a group invite"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/self/accept_invite$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        assert isinstance(
            self.groups_handler, GroupsLocalHandler
        ), "Workers cannot accept an invite to a group."
        result = await self.groups_handler.accept_invite(
            group_id, requester_user_id, content
        )

        return 200, result


class GroupSelfUpdatePublicityServlet(RestServlet):
    """Update whether we publicise a users membership of a group"""

    PATTERNS = client_patterns("/groups/(?P<group_id>[^/]*)/self/update_publicity$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()

    @_validate_group_id
    async def on_PUT(
        self, request: SynapseRequest, group_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        requester_user_id = requester.user.to_string()

        content = parse_json_object_from_request(request)
        publicise = content["publicise"]
        await self.store.update_group_publicity(group_id, requester_user_id, publicise)

        return 200, {}


class PublicisedGroupsForUserServlet(RestServlet):
    """Get the list of groups a user is advertising"""

    PATTERNS = client_patterns("/publicised_groups/(?P<user_id>[^/]*)$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.groups_handler = hs.get_groups_local_handler()

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        await self.auth.get_user_by_req(request, allow_guest=True)

        result = await self.groups_handler.get_publicised_groups_for_user(user_id)

        return 200, result


class PublicisedGroupsForUsersServlet(RestServlet):
    """Get the list of groups a user is advertising"""

    PATTERNS = client_patterns("/publicised_groups$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.store = hs.get_datastore()
        self.groups_handler = hs.get_groups_local_handler()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self.auth.get_user_by_req(request, allow_guest=True)

        content = parse_json_object_from_request(request)
        user_ids = content["user_ids"]

        result = await self.groups_handler.bulk_get_publicised_groups(user_ids)

        return 200, result


class GroupsForUserServlet(RestServlet):
    """Get all groups the logged in user is joined to"""

    PATTERNS = client_patterns("/joined_groups$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.groups_handler = hs.get_groups_local_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        requester_user_id = requester.user.to_string()

        result = await self.groups_handler.get_joined_groups(requester_user_id)

        return 200, result


def register_servlets(hs: "HomeServer", http_server):
    GroupServlet(hs).register(http_server)
    GroupSummaryServlet(hs).register(http_server)
    GroupInvitedUsersServlet(hs).register(http_server)
    GroupUsersServlet(hs).register(http_server)
    GroupRoomServlet(hs).register(http_server)
    GroupSettingJoinPolicyServlet(hs).register(http_server)
    GroupCreateServlet(hs).register(http_server)
    GroupAdminRoomsServlet(hs).register(http_server)
    GroupAdminRoomsConfigServlet(hs).register(http_server)
    GroupAdminUsersInviteServlet(hs).register(http_server)
    GroupAdminUsersKickServlet(hs).register(http_server)
    GroupSelfLeaveServlet(hs).register(http_server)
    GroupSelfJoinServlet(hs).register(http_server)
    GroupSelfAcceptInviteServlet(hs).register(http_server)
    GroupsForUserServlet(hs).register(http_server)
    GroupCategoryServlet(hs).register(http_server)
    GroupCategoriesServlet(hs).register(http_server)
    GroupSummaryRoomsCatServlet(hs).register(http_server)
    GroupRoleServlet(hs).register(http_server)
    GroupRolesServlet(hs).register(http_server)
    GroupSelfUpdatePublicityServlet(hs).register(http_server)
    GroupSummaryUsersRoleServlet(hs).register(http_server)
    PublicisedGroupsForUserServlet(hs).register(http_server)
    PublicisedGroupsForUsersServlet(hs).register(http_server)
