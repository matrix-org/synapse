# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import Codes, SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.push import PusherConfigException
from synapse.rest.client._base import client_patterns
from synapse.rest.synapse.client.unsubscribe import UnsubscribeResource
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class PushersRestServlet(RestServlet):
    PATTERNS = client_patterns("/pushers$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user = requester.user

        pushers = await self.hs.get_datastores().main.get_pushers_by_user_id(
            user.to_string()
        )

        filtered_pushers = [p.as_dict() for p in pushers]

        return 200, {"pushers": filtered_pushers}


class PushersSetRestServlet(RestServlet):
    PATTERNS = client_patterns("/pushers/set$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.notifier = hs.get_notifier()
        self.pusher_pool = self.hs.get_pusherpool()

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user = requester.user

        content = parse_json_object_from_request(request)

        if (
            "pushkey" in content
            and "app_id" in content
            and "kind" in content
            and content["kind"] is None
        ):
            await self.pusher_pool.remove_pusher(
                content["app_id"], content["pushkey"], user_id=user.to_string()
            )
            return 200, {}

        assert_params_in_dict(
            content,
            [
                "kind",
                "app_id",
                "app_display_name",
                "device_display_name",
                "pushkey",
                "lang",
                "data",
            ],
        )

        logger.debug("set pushkey %s to kind %s", content["pushkey"], content["kind"])
        logger.debug("Got pushers request with body: %r", content)

        append = False
        if "append" in content:
            append = content["append"]

        if not append:
            await self.pusher_pool.remove_pushers_by_app_id_and_pushkey_not_user(
                app_id=content["app_id"],
                pushkey=content["pushkey"],
                not_user_id=user.to_string(),
            )

        try:
            await self.pusher_pool.add_pusher(
                user_id=user.to_string(),
                access_token=requester.access_token_id,
                kind=content["kind"],
                app_id=content["app_id"],
                app_display_name=content["app_display_name"],
                device_display_name=content["device_display_name"],
                pushkey=content["pushkey"],
                lang=content["lang"],
                data=content["data"],
                profile_tag=content.get("profile_tag", ""),
            )
        except PusherConfigException as pce:
            raise SynapseError(
                400, "Config Error: " + str(pce), errcode=Codes.MISSING_PARAM
            )

        self.notifier.on_new_replication_data()

        return 200, {}


class LegacyPushersRemoveRestServlet(UnsubscribeResource, RestServlet):
    """
    A servlet to handle legacy "email unsubscribe" links, forwarding requests to the ``UnsubscribeResource``

    This should be kept for some time, so unsubscribe links in past emails stay valid.
    """

    PATTERNS = client_patterns("/pushers/remove$", releases=[], v1=False, unstable=True)

    async def on_GET(self, request: SynapseRequest) -> None:
        # Forward the request to the UnsubscribeResource
        await self._async_render(request)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    PushersRestServlet(hs).register(http_server)
    PushersSetRestServlet(hs).register(http_server)
    LegacyPushersRemoveRestServlet(hs).register(http_server)
