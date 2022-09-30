# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
# Copyright 2020 Sorunome
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
from typing import TYPE_CHECKING, Dict, Iterable, List, Optional, Tuple, Type

from typing_extensions import Literal

from synapse.api.errors import FederationDeniedError, SynapseError
from synapse.federation.transport.server._base import (
    Authenticator,
    BaseFederationServlet,
)
from synapse.federation.transport.server.federation import (
    FEDERATION_SERVLET_CLASSES,
    FederationAccountStatusServlet,
    FederationTimestampLookupServlet,
)
from synapse.http.server import HttpServer, JsonResource
from synapse.http.servlet import (
    parse_boolean_from_args,
    parse_integer_from_args,
    parse_string_from_args,
)
from synapse.types import JsonDict, ThirdPartyInstanceID
from synapse.util.ratelimitutils import FederationRateLimiter

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class TransportLayerServer(JsonResource):
    """Handles incoming federation HTTP requests"""

    def __init__(self, hs: "HomeServer", servlet_groups: Optional[List[str]] = None):
        """Initialize the TransportLayerServer

        Will by default register all servlets. For custom behaviour, pass in
        a list of servlet_groups to register.

        Args:
            hs: homeserver
            servlet_groups: List of servlet groups to register.
                Defaults to ``DEFAULT_SERVLET_GROUPS``.
        """
        self.hs = hs
        self.clock = hs.get_clock()
        self.servlet_groups = servlet_groups

        super().__init__(hs, canonical_json=False)

        self.authenticator = Authenticator(hs)
        self.ratelimiter = hs.get_federation_ratelimiter()

        self.register_servlets()

    def register_servlets(self) -> None:
        register_servlets(
            self.hs,
            resource=self,
            ratelimiter=self.ratelimiter,
            authenticator=self.authenticator,
            servlet_groups=self.servlet_groups,
        )


class PublicRoomList(BaseFederationServlet):
    """
    Fetch the public room list for this server.

    This API returns information in the same format as /publicRooms on the
    client API, but will only ever include local public rooms and hence is
    intended for consumption by other homeservers.

    GET /publicRooms HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "chunk": [
            {
                "aliases": [
                    "#test:localhost"
                ],
                "guest_can_join": false,
                "name": "test room",
                "num_joined_members": 3,
                "room_id": "!whkydVegtvatLfXmPN:localhost",
                "world_readable": false
            }
        ],
        "end": "END",
        "start": "START"
    }
    """

    PATH = "/publicRooms"

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_room_list_handler()
        self.allow_access = hs.config.server.allow_public_rooms_over_federation

    async def on_GET(
        self, origin: str, content: Literal[None], query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        if not self.allow_access:
            raise FederationDeniedError(origin)

        limit = parse_integer_from_args(query, "limit", 0)
        since_token = parse_string_from_args(query, "since", None)
        include_all_networks = parse_boolean_from_args(
            query, "include_all_networks", default=False
        )
        third_party_instance_id = parse_string_from_args(
            query, "third_party_instance_id", None
        )

        if include_all_networks:
            network_tuple = None
        elif third_party_instance_id:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)
        else:
            network_tuple = ThirdPartyInstanceID(None, None)

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit, since_token, network_tuple=network_tuple, from_federation=True
        )
        return 200, data

    async def on_POST(
        self, origin: str, content: JsonDict, query: Dict[bytes, List[bytes]]
    ) -> Tuple[int, JsonDict]:
        # This implements MSC2197 (Search Filtering over Federation)
        if not self.allow_access:
            raise FederationDeniedError(origin)

        limit: Optional[int] = int(content.get("limit", 100))
        since_token = content.get("since", None)
        search_filter = content.get("filter", None)

        include_all_networks = content.get("include_all_networks", False)
        third_party_instance_id = content.get("third_party_instance_id", None)

        if include_all_networks:
            network_tuple = None
            if third_party_instance_id is not None:
                raise SynapseError(
                    400, "Can't use include_all_networks with an explicit network"
                )
        elif third_party_instance_id is None:
            network_tuple = ThirdPartyInstanceID(None, None)
        else:
            network_tuple = ThirdPartyInstanceID.from_string(third_party_instance_id)

        if search_filter is None:
            logger.warning("Nonefilter")

        if limit == 0:
            # zero is a special value which corresponds to no limit.
            limit = None

        data = await self.handler.get_local_public_room_list(
            limit=limit,
            since_token=since_token,
            search_filter=search_filter,
            network_tuple=network_tuple,
            from_federation=True,
        )

        return 200, data


class OpenIdUserInfo(BaseFederationServlet):
    """
    Exchange a bearer token for information about a user.

    The response format should be compatible with:
        http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse

    GET /openid/userinfo?access_token=ABDEFGH HTTP/1.1

    HTTP/1.1 200 OK
    Content-Type: application/json

    {
        "sub": "@userpart:example.org",
    }
    """

    PATH = "/openid/userinfo"

    REQUIRE_AUTH = False

    def __init__(
        self,
        hs: "HomeServer",
        authenticator: Authenticator,
        ratelimiter: FederationRateLimiter,
        server_name: str,
    ):
        super().__init__(hs, authenticator, ratelimiter, server_name)
        self.handler = hs.get_federation_server()

    async def on_GET(
        self,
        origin: Optional[str],
        content: Literal[None],
        query: Dict[bytes, List[bytes]],
    ) -> Tuple[int, JsonDict]:
        token = parse_string_from_args(query, "access_token")
        if token is None:
            return (
                401,
                {"errcode": "M_MISSING_TOKEN", "error": "Access Token required"},
            )

        user_id = await self.handler.on_openid_userinfo(token)

        if user_id is None:
            return (
                401,
                {
                    "errcode": "M_UNKNOWN_TOKEN",
                    "error": "Access Token unknown or expired",
                },
            )

        return 200, {"sub": user_id}


SERVLET_GROUPS: Dict[str, Iterable[Type[BaseFederationServlet]]] = {
    "federation": FEDERATION_SERVLET_CLASSES,
    "room_list": (PublicRoomList,),
    "openid": (OpenIdUserInfo,),
}


def register_servlets(
    hs: "HomeServer",
    resource: HttpServer,
    authenticator: Authenticator,
    ratelimiter: FederationRateLimiter,
    servlet_groups: Optional[Iterable[str]] = None,
) -> None:
    """Initialize and register servlet classes.

    Will by default register all servlets. For custom behaviour, pass in
    a list of servlet_groups to register.

    Args:
        hs: homeserver
        resource: resource class to register to
        authenticator: authenticator to use
        ratelimiter: ratelimiter to use
        servlet_groups: List of servlet groups to register.
            Defaults to ``DEFAULT_SERVLET_GROUPS``.
    """
    if not servlet_groups:
        servlet_groups = SERVLET_GROUPS.keys()

    for servlet_group in servlet_groups:
        # Skip unknown servlet groups.
        if servlet_group not in SERVLET_GROUPS:
            raise RuntimeError(
                f"Attempting to register unknown federation servlet: '{servlet_group}'"
            )

        for servletclass in SERVLET_GROUPS[servlet_group]:
            # Only allow the `/timestamp_to_event` servlet if msc3030 is enabled
            if (
                servletclass == FederationTimestampLookupServlet
                and not hs.config.experimental.msc3030_enabled
            ):
                continue

            # Only allow the `/account_status` servlet if msc3720 is enabled
            if (
                servletclass == FederationAccountStatusServlet
                and not hs.config.experimental.msc3720_enabled
            ):
                continue

            servletclass(
                hs=hs,
                authenticator=authenticator,
                ratelimiter=ratelimiter,
                server_name=hs.hostname,
            ).register(resource)
