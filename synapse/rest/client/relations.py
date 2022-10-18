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
from typing import TYPE_CHECKING, Optional, Tuple

from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.types import JsonDict, StreamToken

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RelationPaginationServlet(RestServlet):
    """API to paginate relations on an event by topological ordering, optionally
    filtered by relation type and event type.
    """

    PATTERNS = client_patterns(
        "/rooms/(?P<room_id>[^/]*)/relations/(?P<parent_id>[^/]*)"
        "(/(?P<relation_type>[^/]*)(/(?P<event_type>[^/]*))?)?$",
        releases=("v1",),
    )

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main
        self._relations_handler = hs.get_relations_handler()
        self._msc3715_enabled = hs.config.experimental.msc3715_enabled

    async def on_GET(
        self,
        request: SynapseRequest,
        room_id: str,
        parent_id: str,
        relation_type: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)

        limit = parse_integer(request, "limit", default=5)
        # Fetch the direction parameter, if provided.
        #
        # TODO Use PaginationConfig.from_request when the unstable parameter is
        #      no longer needed.
        direction = parse_string(request, "dir", allowed_values=["f", "b"])
        if direction is None:
            if self._msc3715_enabled:
                direction = parse_string(
                    request,
                    "org.matrix.msc3715.dir",
                    default="b",
                    allowed_values=["f", "b"],
                )
            else:
                direction = "b"
        from_token_str = parse_string(request, "from")
        to_token_str = parse_string(request, "to")

        # Return the relations
        from_token = None
        if from_token_str:
            from_token = await StreamToken.from_string(self.store, from_token_str)
        to_token = None
        if to_token_str:
            to_token = await StreamToken.from_string(self.store, to_token_str)

        # The unstable version of this API returns an extra field for client
        # compatibility, see https://github.com/matrix-org/synapse/issues/12930.
        assert request.path is not None
        include_original_event = request.path.startswith(b"/_matrix/client/unstable/")

        result = await self._relations_handler.get_relations(
            requester=requester,
            event_id=parent_id,
            room_id=room_id,
            relation_type=relation_type,
            event_type=event_type,
            limit=limit,
            direction=direction,
            from_token=from_token,
            to_token=to_token,
            include_original_event=include_original_event,
        )

        return 200, result


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    RelationPaginationServlet(hs).register(http_server)
