#  Copyright 2021 The Matrix.org Foundation C.I.C.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from typing import TYPE_CHECKING, Dict, List, Tuple, Type

from typing_extensions import Literal

from synapse.api.constants import MAX_GROUP_CATEGORYID_LENGTH, MAX_GROUP_ROLEID_LENGTH
from synapse.api.errors import Codes, SynapseError
from synapse.federation.transport.server._base import (
    Authenticator,
    BaseFederationServlet,
)
from synapse.http.servlet import parse_string_from_args
from synapse.types import JsonDict, get_domain_from_id
from synapse.util.ratelimitutils import FederationRateLimiter

if TYPE_CHECKING:
    from synapse.server import HomeServer


class BaseGroupsServerServlet(BaseFederationServlet):
    """Abstract base class for federation servlet classes which provides a groups server handler.

    See BaseFederationServlet for more information.
    """

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_groups_server_handler()


class FederationGroupsProfileServlet(BaseGroupsServerServlet):
    """Get/set the basic profile of a group on behalf of a user"""

    PATH = "/groups/(?P<group_id>[^/]*)/profile"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_group_profile(group_id, requester_user_id)

        return 200, new_content

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.update_group_profile(
            group_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsSummaryServlet(BaseGroupsServerServlet):
    PATH = "/groups/(?P<group_id>[^/]*)/summary"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_group_summary(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsRoomsServlet(BaseGroupsServerServlet):
    """Get the rooms in a group on behalf of a user"""

    PATH = "/groups/(?P<group_id>[^/]*)/rooms"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_rooms_in_group(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsAddRoomsServlet(BaseGroupsServerServlet):
    """Add/remove room from group"""

    PATH = "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.add_room_to_group(
            group_id, requester_user_id, room_id, content
        )

        return 200, new_content

    async def on_DELETE(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.remove_room_from_group(
            group_id, requester_user_id, room_id
        )

        return 200, new_content


class FederationGroupsAddRoomsConfigServlet(BaseGroupsServerServlet):
    """Update room config in group"""

    PATH = (
        "/groups/(?P<group_id>[^/]*)/room/(?P<room_id>[^/]*)"
        "/config/(?P<config_key>[^/]*)"
    )

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        room_id: str,
        config_key: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        result = await self.handler.update_room_in_group(
            group_id, requester_user_id, room_id, config_key, content
        )

        return 200, result


class FederationGroupsUsersServlet(BaseGroupsServerServlet):
    """Get the users in a group on behalf of a user"""

    PATH = "/groups/(?P<group_id>[^/]*)/users"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_users_in_group(group_id, requester_user_id)

        return 200, new_content


class FederationGroupsInvitedUsersServlet(BaseGroupsServerServlet):
    """Get the users that have been invited to a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/invited_users"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.get_invited_users_in_group(
            group_id, requester_user_id
        )

        return 200, new_content


class FederationGroupsInviteServlet(BaseGroupsServerServlet):
    """Ask a group server to invite someone to the group"""

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.invite_to_group(
            group_id, user_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsAcceptInviteServlet(BaseGroupsServerServlet):
    """Accept an invitation from the group server"""

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/accept_invite"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = await self.handler.accept_invite(group_id, user_id, content)

        return 200, new_content


class FederationGroupsJoinServlet(BaseGroupsServerServlet):
    """Attempt to join a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/join"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        if get_domain_from_id(user_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        new_content = await self.handler.join_group(group_id, user_id, content)

        return 200, new_content


class FederationGroupsRemoveUserServlet(BaseGroupsServerServlet):
    """Leave or kick a user from the group"""

    PATH = "/groups/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.remove_user_from_group(
            group_id, user_id, requester_user_id, content
        )

        return 200, new_content


class FederationGroupsSummaryRoomsServlet(BaseGroupsServerServlet):
    """Add/remove a room from the group summary, with optional category.

    Matches both:
        - /groups/:group/summary/rooms/:room_id
        - /groups/:group/summary/categories/:category/rooms/:room_id
    """

    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/categories/(?P<category_id>[^/]+))?"
        "/rooms/(?P<room_id>[^/]*)"
    )

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        category_id: str,
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(
                400, "category_id cannot be empty string", Codes.INVALID_PARAM
            )

        if len(category_id) > MAX_GROUP_CATEGORYID_LENGTH:
            raise SynapseError(
                400,
                "category_id may not be longer than %s characters"
                % (MAX_GROUP_CATEGORYID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        resp = await self.handler.update_group_summary_room(
            group_id,
            requester_user_id,
            room_id=room_id,
            category_id=category_id,
            content=content,
        )

        return 200, resp

    async def on_DELETE(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        category_id: str,
        room_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.delete_group_summary_room(
            group_id, requester_user_id, room_id=room_id, category_id=category_id
        )

        return 200, resp


class FederationGroupsCategoriesServlet(BaseGroupsServerServlet):
    """Get all categories for a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/categories/?"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_categories(group_id, requester_user_id)

        return 200, resp


class FederationGroupsCategoryServlet(BaseGroupsServerServlet):
    """Add/remove/get a category in a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/categories/(?P<category_id>[^/]+)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        category_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_category(
            group_id, requester_user_id, category_id
        )

        return 200, resp

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        category_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        if len(category_id) > MAX_GROUP_CATEGORYID_LENGTH:
            raise SynapseError(
                400,
                "category_id may not be longer than %s characters"
                % (MAX_GROUP_CATEGORYID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        resp = await self.handler.upsert_group_category(
            group_id, requester_user_id, category_id, content
        )

        return 200, resp

    async def on_DELETE(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        category_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if category_id == "":
            raise SynapseError(400, "category_id cannot be empty string")

        resp = await self.handler.delete_group_category(
            group_id, requester_user_id, category_id
        )

        return 200, resp


class FederationGroupsRolesServlet(BaseGroupsServerServlet):
    """Get roles in a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/roles/?"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_roles(group_id, requester_user_id)

        return 200, resp


class FederationGroupsRoleServlet(BaseGroupsServerServlet):
    """Add/remove/get a role in a group"""

    PATH = "/groups/(?P<group_id>[^/]*)/roles/(?P<role_id>[^/]+)"

    async def on_GET(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        role_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        resp = await self.handler.get_group_role(group_id, requester_user_id, role_id)

        return 200, resp

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        role_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(
                400, "role_id cannot be empty string", Codes.INVALID_PARAM
            )

        if len(role_id) > MAX_GROUP_ROLEID_LENGTH:
            raise SynapseError(
                400,
                "role_id may not be longer than %s characters"
                % (MAX_GROUP_ROLEID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        resp = await self.handler.update_group_role(
            group_id, requester_user_id, role_id, content
        )

        return 200, resp

    async def on_DELETE(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        role_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.delete_group_role(
            group_id, requester_user_id, role_id
        )

        return 200, resp


class FederationGroupsSummaryUsersServlet(BaseGroupsServerServlet):
    """Add/remove a user from the group summary, with optional role.

    Matches both:
        - /groups/:group/summary/users/:user_id
        - /groups/:group/summary/roles/:role/users/:user_id
    """

    PATH = (
        "/groups/(?P<group_id>[^/]*)/summary"
        "(/roles/(?P<role_id>[^/]+))?"
        "/users/(?P<user_id>[^/]*)"
    )

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        role_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        if len(role_id) > MAX_GROUP_ROLEID_LENGTH:
            raise SynapseError(
                400,
                "role_id may not be longer than %s characters"
                % (MAX_GROUP_ROLEID_LENGTH,),
                Codes.INVALID_PARAM,
            )

        resp = await self.handler.update_group_summary_user(
            group_id,
            requester_user_id,
            user_id=user_id,
            role_id=role_id,
            content=content,
        )

        return 200, resp

    async def on_DELETE(
        self,
        origin: str,
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
        group_id: str,
        role_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        if role_id == "":
            raise SynapseError(400, "role_id cannot be empty string")

        resp = await self.handler.delete_group_summary_user(
            group_id, requester_user_id, user_id=user_id, role_id=role_id
        )

        return 200, resp


class FederationGroupsSettingJoinPolicyServlet(BaseGroupsServerServlet):
    """Sets whether a group is joinable without an invite or knock"""

    PATH = "/groups/(?P<group_id>[^/]*)/settings/m.join_policy"

    async def on_PUT(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
    ) -> Tuple[int, JsonDict]:
        requester_user_id = parse_string_from_args(
            query, "requester_user_id", required=True
        )
        if get_domain_from_id(requester_user_id) != origin:
            raise SynapseError(403, "requester_user_id doesn't match origin")

        new_content = await self.handler.set_group_join_policy(
            group_id, requester_user_id, content
        )

        return 200, new_content


GROUP_SERVER_SERVLET_CLASSES: Tuple[Type[BaseFederationServlet], ...] = (
    FederationGroupsProfileServlet,
    FederationGroupsSummaryServlet,
    FederationGroupsRoomsServlet,
    FederationGroupsUsersServlet,
    FederationGroupsInvitedUsersServlet,
    FederationGroupsInviteServlet,
    FederationGroupsAcceptInviteServlet,
    FederationGroupsJoinServlet,
    FederationGroupsRemoveUserServlet,
    FederationGroupsSummaryRoomsServlet,
    FederationGroupsCategoriesServlet,
    FederationGroupsCategoryServlet,
    FederationGroupsRolesServlet,
    FederationGroupsRoleServlet,
    FederationGroupsSummaryUsersServlet,
    FederationGroupsAddRoomsServlet,
    FederationGroupsAddRoomsConfigServlet,
    FederationGroupsSettingJoinPolicyServlet,
)
