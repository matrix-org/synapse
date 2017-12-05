# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
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

from twisted.internet import defer

from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet, parse_json_object_from_request, parse_integer
)
from synapse.http.servlet import parse_string
from synapse.types import StreamToken
from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class RoomKeysUploadServlet(RestServlet):
    PATTERNS = client_v2_patterns("/room_keys/keys(/(?P<room_id>[^/]+))?(/(?P<session_id>[^/]+))?$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(RoomKeysUploadServlet, self).__init__()
        self.auth = hs.get_auth()
        self.e2e_room_keys_handler = hs.get_e2e_room_keys_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, room_id, session_id):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        user_id = requester.user.to_string()
        body = parse_json_object_from_request(request)

        result = yield self.e2e_room_keys_handler.upload_room_keys(
            user_id, version, body
        )
        defer.returnValue((200, result))


def register_servlets(hs, http_server):
    RoomKeysUploadServlet(hs).register(http_server)
