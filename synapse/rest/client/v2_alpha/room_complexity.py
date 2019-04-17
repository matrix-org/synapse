# -*- coding: utf-8 -*-
# Copyright 2019 Matrix.org Foundation
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

from twisted.internet import defer

from synapse.api.errors import Codes, SynapseError
from synapse.http.servlet import RestServlet
from synapse.rest.client.v2_alpha._base import client_v2_patterns


class RoomComplexityRestServlet(RestServlet):
    PATTERNS = client_v2_patterns(
        "/rooms/(?P<room_id>[^/]*)/complexity",
        releases=(),
        v2_alpha=False,
        unstable=True,
    )

    def __init__(self, hs):
        super(RoomComplexityRestServlet, self).__init__()
        self.hs = hs
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request, room_id):

        is_public = yield self.store.is_room_world_readable_or_publicly_joinable(
            room_id
        )

        if not is_public:
            raise SynapseError(404, "Room not found", errcode=Codes.INVALID_PARAM)

        state_events = yield self.store.get_state_event_counts(room_id)

        # Call this one "v1", so we can introduce new ones as we want to develop
        # it.
        complexity_v1 = round(state_events / 500, 2)

        defer.returnValue((200, {"v1": complexity_v1}))


def register_servlets(hs, http_server):
    RoomComplexityRestServlet(hs).register(http_server)
