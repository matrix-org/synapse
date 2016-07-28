# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
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

import logging
import re

logger = logging.getLogger(__name__)


class VersionsRestServlet(RestServlet):
    PATTERNS = [re.compile("^/_matrix/client/versions$")]

    def on_GET(self, request):
        return (200, {
            "versions": [
                "r0.0.1",
                "r0.1.0",
                "r0.2.0",
            ]
        })


def register_servlets(http_server):
    VersionsRestServlet().register(http_server)
