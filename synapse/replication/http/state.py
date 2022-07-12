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

from twisted.web.server import Request

from synapse.api.errors import SynapseError
from synapse.http.server import HttpServer
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationUpdateCurrentStateRestServlet(ReplicationEndpoint):
    """Recalculates the current state for a room, and persists it.

    The API looks like:

        POST /_synapse/replication/update_current_state/:room_id

        {}

        200 OK

        {}
    """

    NAME = "update_current_state"
    PATH_ARGS = ("room_id",)

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self._state_handler = hs.get_state_handler()
        self._events_shard_config = hs.config.worker.events_shard_config
        self._instance_name = hs.get_instance_name()

    @staticmethod
    async def _serialize_payload(room_id: str) -> JsonDict:  # type: ignore[override]
        return {}

    async def _handle_request(  # type: ignore[override]
        self, request: Request, room_id: str
    ) -> Tuple[int, JsonDict]:
        writer_instance = self._events_shard_config.get_instance(room_id)
        if writer_instance != self._instance_name:
            raise SynapseError(
                400, "/update_current_state request was routed to the wrong worker"
            )

        await self._state_handler.update_current_state(room_id)

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    if hs.get_instance_name() in hs.config.worker.writers.events:
        ReplicationUpdateCurrentStateRestServlet(hs).register(http_server)
