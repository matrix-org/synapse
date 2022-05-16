# Copyright 2019 New Vector Ltd
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
from typing import TYPE_CHECKING, Optional, Tuple, cast

from twisted.web.server import Request

from synapse.http.server import HttpServer
from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RegisterDeviceReplicationServlet(ReplicationEndpoint):
    """Ensure a device is registered, generating a new access token for the
    device.

    Used during registration and login.
    """

    NAME = "device_check_registered"
    PATH_ARGS = ("user_id",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)
        self.registration_handler = hs.get_registration_handler()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        user_id: str,
        device_id: Optional[str],
        initial_display_name: Optional[str],
        is_guest: bool,
        is_appservice_ghost: bool,
        should_issue_refresh_token: bool,
        auth_provider_id: Optional[str],
        auth_provider_session_id: Optional[str],
    ) -> JsonDict:
        """
        Args:
            user_id
            device_id: Device ID to use, if None a new one is generated.
            initial_display_name
            is_guest
            is_appservice_ghost
            should_issue_refresh_token
        """
        return {
            "device_id": device_id,
            "initial_display_name": initial_display_name,
            "is_guest": is_guest,
            "is_appservice_ghost": is_appservice_ghost,
            "should_issue_refresh_token": should_issue_refresh_token,
            "auth_provider_id": auth_provider_id,
            "auth_provider_session_id": auth_provider_session_id,
        }

    async def _handle_request(  # type: ignore[override]
        self, request: Request, user_id: str
    ) -> Tuple[int, JsonDict]:
        content = parse_json_object_from_request(request)

        device_id = content["device_id"]
        initial_display_name = content["initial_display_name"]
        is_guest = content["is_guest"]
        is_appservice_ghost = content["is_appservice_ghost"]
        should_issue_refresh_token = content["should_issue_refresh_token"]
        auth_provider_id = content["auth_provider_id"]
        auth_provider_session_id = content["auth_provider_session_id"]

        res = await self.registration_handler.register_device_inner(
            user_id,
            device_id,
            initial_display_name,
            is_guest,
            is_appservice_ghost=is_appservice_ghost,
            should_issue_refresh_token=should_issue_refresh_token,
            auth_provider_id=auth_provider_id,
            auth_provider_session_id=auth_provider_session_id,
        )

        return 200, cast(JsonDict, res)


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    RegisterDeviceReplicationServlet(hs).register(http_server)
