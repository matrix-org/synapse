# -*- coding: utf-8 -*-
# Copyright 2019 New Vector
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

from synapse.api.room_versions import DEFAULT_ROOM_VERSION, KNOWN_ROOM_VERSIONS
from synapse.http.servlet import RestServlet

from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class CapabilitiesRestServlet(RestServlet):
    """End point to expose the capabilities of the server."""

    PATTERNS = client_v2_patterns("/capabilities$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(CapabilitiesRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)
        user = yield self.store.get_user_by_id(requester.user.to_string())
        change_password = bool(user["password_hash"])

        response = {
            "capabilities": {
                "m.room_versions": {
                    "default": DEFAULT_ROOM_VERSION.identifier,
                    "available": {
                        v.identifier: v.disposition
                        for v in KNOWN_ROOM_VERSIONS.values()
                    },
                },
                "m.change_password": {"enabled": change_password},
            }
        }
        defer.returnValue((200, response))


def register_servlets(hs, http_server):
    CapabilitiesRestServlet(hs).register(http_server)
