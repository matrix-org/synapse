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
import synapse.http.servlet

from ._base import parse_media_id, respond_404
from twisted.web.resource import Resource
from synapse.http.server import request_handler, set_cors_headers

from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer

import logging

logger = logging.getLogger(__name__)


class DownloadResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.media_repo = media_repo
        self.server_name = hs.hostname

        # Both of these are expected by @request_handler()
        self.clock = hs.get_clock()
        self.version_string = hs.version_string

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @request_handler()
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        set_cors_headers(request)
        request.setHeader(
            "Content-Security-Policy",
            "default-src 'none';"
            " script-src 'none';"
            " plugin-types application/pdf;"
            " style-src 'unsafe-inline';"
            " object-src 'self';"
        )
        server_name, media_id, name = parse_media_id(request)
        if server_name == self.server_name:
            yield self.media_repo.get_local_media(request, media_id, name)
        else:
            allow_remote = synapse.http.servlet.parse_boolean(
                request, "allow_remote", default=True)
            if not allow_remote:
                logger.info(
                    "Rejecting request for remote media %s/%s due to allow_remote",
                    server_name, media_id,
                )
                respond_404(request)
                return

            yield self.media_repo.get_remote_media(request, server_name, media_id, name)
