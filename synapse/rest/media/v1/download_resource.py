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

import synapse.http.servlet
from synapse.http.server import DirectServeJsonResource, set_cors_headers

from ._base import parse_media_id, respond_404

logger = logging.getLogger(__name__)


class DownloadResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs, media_repo):
        super().__init__()
        self.media_repo = media_repo
        self.server_name = hs.hostname

    async def _async_render_GET(self, request):
        set_cors_headers(request)
        request.setHeader(
            b"Content-Security-Policy",
            b"sandbox;"
            b" default-src 'none';"
            b" script-src 'none';"
            b" plugin-types application/pdf;"
            b" style-src 'unsafe-inline';"
            b" media-src 'self';"
            b" object-src 'self';",
        )
        request.setHeader(
            b"Referrer-Policy", b"no-referrer",
        )
        server_name, media_id, name = parse_media_id(request)
        if server_name == self.server_name:
            await self.media_repo.get_local_media(request, media_id, name)
        else:
            allow_remote = synapse.http.servlet.parse_boolean(
                request, "allow_remote", default=True
            )
            if not allow_remote:
                logger.info(
                    "Rejecting request for remote media %s/%s due to allow_remote",
                    server_name,
                    media_id,
                )
                respond_404(request)
                return

            await self.media_repo.get_remote_media(request, server_name, media_id, name)
