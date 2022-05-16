# Copyright 2021 The Matrix.org Foundation C.I.C.
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

from synapse.http.server import HttpServer
from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationRemovePusherRestServlet(ReplicationEndpoint):
    """Deletes the given pusher.

    Request format:

        POST /_synapse/replication/remove_pusher/:user_id

        {
            "app_id": "<some_id>",
            "pushkey": "<some_key>"
        }

    """

    NAME = "add_user_account_data"
    PATH_ARGS = ("user_id",)
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.pusher_pool = hs.get_pusherpool()

    @staticmethod
    async def _serialize_payload(app_id: str, pushkey: str, user_id: str) -> JsonDict:  # type: ignore[override]
        payload = {
            "app_id": app_id,
            "pushkey": pushkey,
        }

        return payload

    async def _handle_request(  # type: ignore[override]
        self, request: Request, user_id: str
    ) -> Tuple[int, JsonDict]:
        content = parse_json_object_from_request(request)

        app_id = content["app_id"]
        pushkey = content["pushkey"]

        await self.pusher_pool.remove_pusher(app_id, pushkey, user_id)

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationRemovePusherRestServlet(hs).register(http_server)
