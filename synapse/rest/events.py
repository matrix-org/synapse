# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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
from synapse.api.streams import PaginationConfig
from synapse.rest.base import RestServlet, client_path_pattern


class EventStreamRestServlet(RestServlet):
    PATTERN = client_path_pattern("/events$")

    DEFAULT_LONGPOLL_TIME_MS = 5000

    @defer.inlineCallbacks
    def on_GET(self, request):
        auth_user = yield self.auth.get_user_by_req(request)

        handler = self.handlers.event_stream_handler
        pagin_config = PaginationConfig.from_request(request)
        timeout = EventStreamRestServlet.DEFAULT_LONGPOLL_TIME_MS
        if "timeout" in request.args:
            try:
                timeout = int(request.args["timeout"][0])
            except ValueError:
                raise SynapseError(400, "timeout must be in milliseconds.")

        chunk = yield handler.get_stream(auth_user.to_string(), pagin_config,
                                         timeout=timeout)
        defer.returnValue((200, chunk))

    def on_OPTIONS(self, request):
        return (200, {})


def register_servlets(hs, http_server):
    EventStreamRestServlet(hs).register(http_server)
