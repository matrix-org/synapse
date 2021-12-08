# Copyright 2014-2016 OpenMarket Ltd
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

""" This module contains REST servlets to do with presence: /presence/<paths>
"""
import logging
from typing import TYPE_CHECKING, Tuple

from synapse.api.errors import AuthError, SynapseError
from synapse.handlers.presence import format_user_presence_state
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class PresenceStatusRestServlet(RestServlet):
    PATTERNS = client_patterns("/presence/(?P<user_id>[^/]*)/status", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.presence_handler = hs.get_presence_handler()
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()

        self._use_presence = hs.config.server.use_presence

    async def on_GET(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if not self._use_presence:
            return 200, {"presence": "offline"}

        if requester.user != user:
            allowed = await self.presence_handler.is_visible(
                observed_user=user, observer_user=requester.user
            )

            if not allowed:
                raise AuthError(403, "You are not allowed to see their presence.")

        state = await self.presence_handler.get_state(target_user=user)
        result = format_user_presence_state(
            state, self.clock.time_msec(), include_user_id=False
        )

        return 200, result

    async def on_PUT(
        self, request: SynapseRequest, user_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        user = UserID.from_string(user_id)

        if requester.user != user:
            raise AuthError(403, "Can only set your own presence state")

        state = {}

        content = parse_json_object_from_request(request)

        try:
            state["presence"] = content.pop("presence")

            if "status_msg" in content:
                state["status_msg"] = content.pop("status_msg")
                if not isinstance(state["status_msg"], str):
                    raise SynapseError(400, "status_msg must be a string.")

            if content:
                raise KeyError()
        except SynapseError as e:
            raise e
        except Exception:
            raise SynapseError(400, "Unable to parse state")

        if self._use_presence:
            await self.presence_handler.set_state(user, state)

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    PresenceStatusRestServlet(hs).register(http_server)
