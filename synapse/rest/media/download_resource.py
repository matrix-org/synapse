# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
import re
from typing import TYPE_CHECKING, Optional

from synapse.http.server import set_corp_headers, set_cors_headers
from synapse.http.servlet import RestServlet, parse_boolean, parse_integer
from synapse.http.site import SynapseRequest
from synapse.media._base import (
    DEFAULT_MAX_TIMEOUT_MS,
    MAXIMUM_ALLOWED_MAX_TIMEOUT_MS,
    respond_404,
)
from synapse.util.stringutils import parse_and_validate_server_name

if TYPE_CHECKING:
    from synapse.media.media_repository import MediaRepository
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class DownloadResource(RestServlet):
    PATTERNS = [
        re.compile(
            "/_matrix/media/(r0|v3|v1)/download/(?P<server_name>[^/]*)/(?P<media_id>[^/]*)(/(?P<file_name>[^/]*))?$"
        )
    ]

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()
        self.media_repo = media_repo
        self._is_mine_server_name = hs.is_mine_server_name

    async def on_GET(
        self,
        request: SynapseRequest,
        server_name: str,
        media_id: str,
        file_name: Optional[str] = None,
    ) -> None:
        # Validate the server name, raising if invalid
        parse_and_validate_server_name(server_name)

        set_cors_headers(request)
        set_corp_headers(request)
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
        # Limited non-standard form of CSP for IE11
        request.setHeader(b"X-Content-Security-Policy", b"sandbox;")
        request.setHeader(b"Referrer-Policy", b"no-referrer")
        max_timeout_ms = parse_integer(
            request, "timeout_ms", default=DEFAULT_MAX_TIMEOUT_MS
        )
        max_timeout_ms = min(max_timeout_ms, MAXIMUM_ALLOWED_MAX_TIMEOUT_MS)

        if self._is_mine_server_name(server_name):
            await self.media_repo.get_local_media(
                request, media_id, file_name, max_timeout_ms
            )
        else:
            allow_remote = parse_boolean(request, "allow_remote", default=True)
            if not allow_remote:
                logger.info(
                    "Rejecting request for remote media %s/%s due to allow_remote",
                    server_name,
                    media_id,
                )
                respond_404(request)
                return

            await self.media_repo.get_remote_media(
                request, server_name, media_id, file_name, max_timeout_ms
            )
