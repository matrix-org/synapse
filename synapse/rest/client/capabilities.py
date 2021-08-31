# Copyright 2019 New Vector
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

from synapse.api.room_versions import KNOWN_ROOM_VERSIONS, MSC3244_CAPABILITIES
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class CapabilitiesRestServlet(RestServlet):
    """End point to expose the capabilities of the server."""

    PATTERNS = client_patterns("/capabilities$")

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.config = hs.config
        self.auth = hs.get_auth()
        self.auth_handler = hs.get_auth_handler()

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        await self.auth.get_user_by_req(request, allow_guest=True)
        change_password = self.auth_handler.can_change_password()

        response = {
            "capabilities": {
                "m.room_versions": {
                    "default": self.config.default_room_version.identifier,
                    "available": {
                        v.identifier: v.disposition
                        for v in KNOWN_ROOM_VERSIONS.values()
                    },
                },
                "m.change_password": {"enabled": change_password},
            }
        }

        if self.config.experimental.msc3244_enabled:
            response["capabilities"]["m.room_versions"][
                "org.matrix.msc3244.room_capabilities"
            ] = MSC3244_CAPABILITIES

        if self.config.experimental.msc3283_enabled:
            response["capabilities"]["org.matrix.msc3283.set_displayname"] = {
                "enabled": self.config.enable_set_displayname
            }
            response["capabilities"]["org.matrix.msc3283.set_avatar_url"] = {
                "enabled": self.config.enable_set_avatar_url
            }
            response["capabilities"]["org.matrix.msc3283.3pid_changes"] = {
                "enabled": self.config.enable_3pid_changes
            }

        return 200, response


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    CapabilitiesRestServlet(hs).register(http_server)
