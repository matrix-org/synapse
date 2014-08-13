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

from synapse.rest.base import RestServlet

import logging
import re

logger = logging.getLogger(__name__)


class WebClientRestServlet(RestServlet):
    # No PATTERN; we have custom dispatch rules here

    def register(self, http_server):
        http_server.register_path("GET",
                                  re.compile("^/$"),
                                  self.on_GET_redirect)
        http_server.register_path("GET",
                                  re.compile("^/matrix/client$"),
                                  self.on_GET)

    def on_GET(self, request):
        return (200, "not implemented")

    def on_GET_redirect(self, request):
        request.setHeader("Location", request.uri + "matrix/client")
        return (302, None)


def register_servlets(hs, http_server):
    logger.info("Registering web client.")
    WebClientRestServlet(hs).register(http_server)