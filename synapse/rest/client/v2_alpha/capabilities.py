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

from synapse.http.servlet import RestServlet

from ._base import client_v2_patterns


class CapabilitiesRestServlet(RestServlet):
    PATTERNS = client_v2_patterns("/capabilities$")

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(CapabilitiesRestServlet, self).__init__()
        self.hs = hs

    def on_GET(self, request):
        return 200, {
            "capabilities": {
                "m.room_versions": {
                    "default": "1",
                    "available": {
                        "1": "stable",
                        "2": "stable",
                        "state-v2-test": "unstable",
                        "3": "unstable"
                    }
                }
            }
        }


def register_servlets(hs, http_server):
    CapabilitiesRestServlet(hs).register(http_server)
