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

from typing import TYPE_CHECKING, Dict, List, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_boolean
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer


# TODO: Needs unit testing
class InitialSyncRestServlet(RestServlet):
    PATTERNS = client_patterns("/initialSync$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.initial_sync_handler = hs.get_initial_sync_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request)
        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        as_client_event = b"raw" not in args
        pagination_config = await PaginationConfig.from_request(
            self.store, request, default_limit=10
        )
        include_archived = parse_boolean(request, "archived", default=False)
        content = await self.initial_sync_handler.snapshot_all_rooms(
            user_id=requester.user.to_string(),
            pagin_config=pagination_config,
            as_client_event=as_client_event,
            include_archived=include_archived,
        )

        return 200, content


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    InitialSyncRestServlet(hs).register(http_server)
