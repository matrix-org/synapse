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

"""This module contains REST servlets to do with event streaming, /events."""
import logging
from typing import TYPE_CHECKING, Dict, List, Tuple, Union

from synapse.api.errors import SynapseError
from synapse.http.server import HttpServer
from synapse.http.servlet import RestServlet, parse_string
from synapse.http.site import SynapseRequest
from synapse.rest.client._base import client_patterns
from synapse.streams.config import PaginationConfig
from synapse.types import JsonDict

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class EventStreamRestServlet(RestServlet):
    PATTERNS = client_patterns("/events$", v1=True)

    DEFAULT_LONGPOLL_TIME_MS = 30000

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.event_stream_handler = hs.get_event_stream_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastores().main

    async def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        is_guest = requester.is_guest
        args: Dict[bytes, List[bytes]] = request.args  # type: ignore
        if is_guest:
            if b"room_id" not in args:
                raise SynapseError(400, "Guest users must specify room_id param")
        room_id = parse_string(request, "room_id")

        pagin_config = await PaginationConfig.from_request(self.store, request)
        timeout = EventStreamRestServlet.DEFAULT_LONGPOLL_TIME_MS
        if b"timeout" in args:
            try:
                timeout = int(args[b"timeout"][0])
            except ValueError:
                raise SynapseError(400, "timeout must be in milliseconds.")

        as_client_event = b"raw" not in args

        chunk = await self.event_stream_handler.get_stream(
            requester.user.to_string(),
            pagin_config,
            timeout=timeout,
            as_client_event=as_client_event,
            affect_presence=(not is_guest),
            room_id=room_id,
            is_guest=is_guest,
        )

        return 200, chunk


class EventRestServlet(RestServlet):
    PATTERNS = client_patterns("/events/(?P<event_id>[^/]*)$", v1=True)

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.clock = hs.get_clock()
        self.event_handler = hs.get_event_handler()
        self.auth = hs.get_auth()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(
        self, request: SynapseRequest, event_id: str
    ) -> Tuple[int, Union[str, JsonDict]]:
        requester = await self.auth.get_user_by_req(request)
        event = await self.event_handler.get_event(requester.user, None, event_id)

        time_now = self.clock.time_msec()
        if event:
            result = self._event_serializer.serialize_event(event, time_now)
            return 200, result
        else:
            return 404, "Event not found."


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    EventStreamRestServlet(hs).register(http_server)
    EventRestServlet(hs).register(http_server)
