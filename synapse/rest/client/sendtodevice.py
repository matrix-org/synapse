# Copyright 2016 OpenMarket Ltd
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
from typing import TYPE_CHECKING, Awaitable, Tuple

from synapse.http import servlet
from synapse.http.server import HttpServer
from synapse.http.servlet import assert_params_in_dict, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.logging.opentracing import set_tag
from synapse.rest.client.transactions import HttpTransactionCache
from synapse.types import JsonDict

from ._base import client_patterns

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class SendToDeviceRestServlet(servlet.RestServlet):
    PATTERNS = client_patterns(
        "/sendToDevice/(?P<message_type>[^/]*)/(?P<txn_id>[^/]*)$"
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.txns = HttpTransactionCache(hs)
        self.device_message_handler = hs.get_device_message_handler()

    def on_PUT(
        self, request: SynapseRequest, message_type: str, txn_id: str
    ) -> Awaitable[Tuple[int, JsonDict]]:
        set_tag("message_type", message_type)
        set_tag("txn_id", txn_id)
        return self.txns.fetch_or_execute_request(
            request, self._put, request, message_type, txn_id
        )

    async def _put(
        self, request: SynapseRequest, message_type: str, txn_id: str
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        content = parse_json_object_from_request(request)
        assert_params_in_dict(content, ("messages",))

        await self.device_message_handler.send_device_message(
            requester, message_type, content["messages"]
        )

        return 200, {}


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    SendToDeviceRestServlet(hs).register(http_server)
