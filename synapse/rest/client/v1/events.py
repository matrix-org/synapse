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

from synapse.api.errors import SynapseError
from synapse.http.servlet import RestServlet
from synapse.rest.client.v2_alpha._base import client_patterns
from synapse.streams.config import PaginationConfig

logger = logging.getLogger(__name__)


class EventStreamRestServlet(RestServlet):
    PATTERNS = client_patterns("/events$", v1=True)

    DEFAULT_LONGPOLL_TIME_MS = 30000

    def __init__(self, hs):
        super().__init__()
        self.event_stream_handler = hs.get_event_stream_handler()
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    async def on_GET(self, request):
        requester = await self.auth.get_user_by_req(request, allow_guest=True)
        is_guest = requester.is_guest
        room_id = None
        if is_guest:
            if b"room_id" not in request.args:
                raise SynapseError(400, "Guest users must specify room_id param")
        if b"room_id" in request.args:
            room_id = request.args[b"room_id"][0].decode("ascii")

        pagin_config = await PaginationConfig.from_request(self.store, request)
        timeout = EventStreamRestServlet.DEFAULT_LONGPOLL_TIME_MS
        if b"timeout" in request.args:
            try:
                timeout = int(request.args[b"timeout"][0])
            except ValueError:
                raise SynapseError(400, "timeout must be in milliseconds.")

        as_client_event = b"raw" not in request.args

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

    def __init__(self, hs):
        super().__init__()
        self.clock = hs.get_clock()
        self.event_handler = hs.get_event_handler()
        self.auth = hs.get_auth()
        self._event_serializer = hs.get_event_client_serializer()

    async def on_GET(self, request, event_id):
        requester = await self.auth.get_user_by_req(request)
        event = await self.event_handler.get_event(requester.user, None, event_id)

        time_now = self.clock.time_msec()
        if event:
            event = await self._event_serializer.serialize_event(event, time_now)
            return 200, event
        else:
            return 404, "Event not found."


def register_servlets(hs, http_server):
    EventStreamRestServlet(hs).register(http_server)
    EventRestServlet(hs).register(http_server)
