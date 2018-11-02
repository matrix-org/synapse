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
import logging

from twisted.internet import defer
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

import synapse.http.servlet
from synapse.http.server import set_cors_headers, wrap_json_request_handler

from ._base import parse_media_id, respond_404

logger = logging.getLogger(__name__)


class DownloadResource(Resource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        Resource.__init__(self)

        self.media_repo = media_repo
        self.server_name = hs.hostname

        # this is expected by @wrap_json_request_handler
        self.clock = hs.get_clock()

    def render_GET(self, request):
        self._async_render_GET(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def _async_render_GET(self, request):
        set_cors_headers(request)
        request.setHeader(
            b"Content-Security-Policy",
            b"default-src 'none';"
            b" script-src 'none';"
            b" plugin-types application/pdf;"
            b" style-src 'unsafe-inline';"
            b" media-src 'self';"
            b" object-src 'self';"
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
