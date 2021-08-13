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
from typing import Dict, List, Tuple, Type

from synapse.api.errors import SynapseError
from synapse.federation.transport.server._base import (
    Authenticator,
    BaseFederationServlet,
)
from synapse.handlers.groups_local import GroupsLocalHandler
from synapse.server import HomeServer
from synapse.types import JsonDict, get_domain_from_id
from synapse.util.ratelimitutils import FederationRateLimiter


class BaseGroupsLocalServlet(BaseFederationServlet):
    """Abstract base class for federation servlet classes which provides a groups local handler.

    See BaseFederationServlet for more information.
    """

    def __init__(
        self,
        hs: HomeServer,
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_groups_local_handler()


class FederationGroupsLocalInviteServlet(BaseGroupsLocalServlet):
    """A group server has invited a local user"""

    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/invite"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, JsonDict]:
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "group_id doesn't match origin")

        assert isinstance(
            self.handler, GroupsLocalHandler
        ), "Workers cannot handle group invites."

        new_content = await self.handler.on_invite(group_id, user_id, content)

        return 200, new_content


class FederationGroupsRemoveLocalUserServlet(BaseGroupsLocalServlet):
    """A group server has removed a local user"""

    PATH = "/groups/local/(?P<group_id>[^/]*)/users/(?P<user_id>[^/]*)/remove"

    async def on_POST(
        self,
        origin: str,
        content: JsonDict,
        query: Dict[bytes, List[bytes]],
        group_id: str,
        user_id: str,
    ) -> Tuple[int, None]:
        if get_domain_from_id(group_id) != origin:
            raise SynapseError(403, "user_id doesn't match origin")

        assert isinstance(
            self.handler, GroupsLocalHandler
        ), "Workers cannot handle group removals."

        await self.handler.user_removed_from_group(group_id, user_id, content)

        return 200, None


class FederationGroupsBulkPublicisedServlet(BaseGroupsLocalServlet):
    """Get roles in a group"""

    PATH = "/get_groups_publicised"

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        resp = await self.handler.bulk_get_publicised_groups(
            content["user_ids"], proxy=False
        )

        return 200, resp


GROUP_LOCAL_SERVLET_CLASSES: Tuple[Type[BaseFederationServlet], ...] = (
    FederationGroupsLocalInviteServlet,
    FederationGroupsRemoveLocalUserServlet,
    FederationGroupsBulkPublicisedServlet,
)
