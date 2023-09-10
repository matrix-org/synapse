# Copyright 2020 The Matrix.org Foundation C.I.C.
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
from typing import TYPE_CHECKING, Optional, Tuple

from twisted.web.server import Request

from synapse.http.server import HttpServer
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict, UserID

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationBumpPresenceActiveTime(ReplicationEndpoint):
    """We've seen the user do something that indicates they're interacting
    with the app.

    The POST looks like:

        POST /_synapse/replication/bump_presence_active_time/<user_id>

        200 OK

        {}
    """

    NAME = "bump_presence_active_time"
    PATH_ARGS = ("user_id",)
    METHOD = "POST"
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._presence_handler = hs.get_presence_handler()

    @staticmethod
    async def _serialize_payload(user_id: str, device_id: Optional[str]) -> JsonDict:  # type: ignore[override]
        return {"device_id": device_id}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, content: JsonDict, user_id: str
    ) -> Tuple[int, JsonDict]:
        await self._presence_handler.bump_presence_active_time(
            UserID.from_string(user_id), content.get("device_id")
        )

        return (200, {})


class ReplicationPresenceSetState(ReplicationEndpoint):
    """Set the presence state for a user.

    The POST looks like:

        POST /_synapse/replication/presence_set_state/<user_id>

        {
            "state": { ... },
            "force_notify": false,
            "is_sync": false
        }

        200 OK

        {}
    """

    NAME = "presence_set_state"
    PATH_ARGS = ("user_id",)
    METHOD = "POST"
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._presence_handler = hs.get_presence_handler()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        user_id: str,
        device_id: Optional[str],
        state: JsonDict,
        force_notify: bool = False,
        is_sync: bool = False,
    ) -> JsonDict:
        return {
            "device_id": device_id,
            "state": state,
            "force_notify": force_notify,
            "is_sync": is_sync,
        }

    async def _handle_request(  # type: ignore[override]
        self, request: Request, content: JsonDict, user_id: str
    ) -> Tuple[int, JsonDict]:
        await self._presence_handler.set_state(
            UserID.from_string(user_id),
            content.get("device_id"),
            content["state"],
            content["force_notify"],
            content.get("is_sync", False),
        )

        return (200, {})


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationBumpPresenceActiveTime(hs).register(http_server)
    ReplicationPresenceSetState(hs).register(http_server)
