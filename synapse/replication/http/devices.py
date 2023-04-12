# Copyright 2018 New Vector Ltd
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
from typing import TYPE_CHECKING, Dict, List, Optional, Tuple

from twisted.web.server import Request

from synapse.http.server import HttpServer
from synapse.logging.opentracing import active_span
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class ReplicationUploadKeysForUserRestServlet(ReplicationEndpoint):
    """Ask master to upload keys for the user and send them out over federation to
    update other servers.

    For now, only the master is permitted to handle key upload requests;
    any worker can handle key query requests (since they're read-only).

    Calls to e2e_keys_handler.upload_keys_for_user(user_id, device_id, keys) on
    the main process to accomplish this.

    Defined in https://spec.matrix.org/v1.4/client-server-api/#post_matrixclientv3keysupload
    Request format(borrowed and expanded from KeyUploadServlet):

        POST /_synapse/replication/upload_keys_for_user

    {
        "user_id": "<user_id>",
        "device_id": "<device_id>",
        "keys": {
            ....this part can be found in KeyUploadServlet in rest/client/keys.py....
        }
    }

    Response is equivalent to ` /_matrix/client/v3/keys/upload` found in KeyUploadServlet

    """

    NAME = "upload_keys_for_user"
    PATH_ARGS = ()
    CACHE = False

    def __init__(self, hs: "HomeServer"):
        super().__init__(hs)

        self.e2e_keys_handler = hs.get_e2e_keys_handler()
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()

    @staticmethod
    async def _serialize_payload(  # type: ignore[override]
        user_id: str, device_id: str, keys: JsonDict
    ) -> JsonDict:
        return {
            "user_id": user_id,
            "device_id": device_id,
            "keys": keys,
        }

    async def _handle_request(  # type: ignore[override]
        self, request: Request, content: JsonDict
    ) -> Tuple[int, JsonDict]:
        user_id = content["user_id"]
        device_id = content["device_id"]
        keys = content["keys"]

        results = await self.e2e_keys_handler.upload_keys_for_user(
            user_id, device_id, keys
        )

        return 200, results


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    ReplicationMultiUserDevicesResyncRestServlet(hs).register(http_server)
    ReplicationUploadKeysForUserRestServlet(hs).register(http_server)
