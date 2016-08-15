# -*- coding: utf-8 -*-
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
from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.streams.config import PaginationConfig
from .base import ClientV1RestServlet, client_path_patterns
from synapse.events.utils import serialize_event

import logging


logger = logging.getLogger(__name__)


class EventStreamRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/events$")

    DEFAULT_LONGPOLL_TIME_MS = 30000

    def __init__(self, hs):
        super(EventStreamRestServlet, self).__init__(hs)
        self.event_stream_handler = hs.get_event_stream_handler()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(
            request,
            allow_guest=True,
        )
        is_guest = requester.is_guest
        room_id = None
        if is_guest:
            if "room_id" not in request.args:
                raise SynapseError(400, "Guest users must specify room_id param")
        if "room_id" in request.args:
            room_id = request.args["room_id"][0]

        pagin_config = PaginationConfig.from_request(request)
        timeout = EventStreamRestServlet.DEFAULT_LONGPOLL_TIME_MS
        if "timeout" in request.args:
            try:
                timeout = int(request.args["timeout"][0])
            except ValueError:
                raise SynapseError(400, "timeout must be in milliseconds.")

        as_client_event = "raw" not in request.args

        chunk = yield self.event_stream_handler.get_stream(
            requester.user.to_string(),
            pagin_config,
            timeout=timeout,
            as_client_event=as_client_event,
            affect_presence=(not is_guest),
            room_id=room_id,
            is_guest=is_guest,
        )

        defer.returnValue((200, chunk))

    def on_OPTIONS(self, request):
        return (200, {})


# TODO: Unit test gets, with and without auth, with different kinds of events.
class EventRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/events/(?P<event_id>[^/]*)$")

    def __init__(self, hs):
        super(EventRestServlet, self).__init__(hs)
        self.clock = hs.get_clock()
        self.event_handler = hs.get_event_handler()

    @defer.inlineCallbacks
    def on_GET(self, request, event_id):
        requester = yield self.auth.get_user_by_req(request)
        event = yield self.event_handler.get_event(requester.user, event_id)

        time_now = self.clock.time_msec()
        if event:
            defer.returnValue((200, serialize_event(event, time_now)))
        else:
            defer.returnValue((404, "Event not found."))


def register_servlets(hs, http_server):
    EventStreamRestServlet(hs).register(http_server)
    EventRestServlet(hs).register(http_server)
