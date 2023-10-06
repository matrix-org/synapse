# Copyright 2016 OpenMarket Ltd
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

import re
from typing import TYPE_CHECKING

from synapse.http.server import respond_with_json_bytes
from synapse.http.servlet import RestServlet, parse_integer, parse_string
from synapse.http.site import SynapseRequest
from synapse.media.media_storage import MediaStorage

if TYPE_CHECKING:
    from synapse.media.media_repository import MediaRepository
    from synapse.server import HomeServer


class PreviewUrlResource(RestServlet):
    """
    The `GET /_matrix/media/r0/preview_url` endpoint provides a generic preview API
    for URLs which outputs Open Graph (https://ogp.me/) responses (with some Matrix
    specific additions).

    This does have trade-offs compared to other designs:

    * Pros:
      * Simple and flexible; can be used by any clients at any point
    * Cons:
      * If each homeserver provides one of these independently, all the homeservers in a
        room may needlessly DoS the target URI
      * The URL metadata must be stored somewhere, rather than just using Matrix
        itself to store the media.
      * Matrix cannot be used to distribute the metadata between homeservers.
    """

    PATTERNS = [re.compile("/_matrix/media/(r0|v3|v1)/preview_url$")]

    def __init__(
        self,
        hs: "HomeServer",
        media_repo: "MediaRepository",
        media_storage: MediaStorage,
    ):
        super().__init__()

        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.media_repo = media_repo
        self.media_storage = media_storage
        assert self.media_repo.url_previewer is not None
        self.url_previewer = self.media_repo.url_previewer

    async def on_GET(self, request: SynapseRequest) -> None:
        # XXX: if get_user_by_req fails, what should we do in an async render?
        requester = await self.auth.get_user_by_req(request)
        url = parse_string(request, "url", required=True)
        ts = parse_integer(request, "ts")
        if ts is None:
            ts = self.clock.time_msec()

        og = await self.url_previewer.preview(url, requester.user, ts)
        respond_with_json_bytes(request, 200, og, send_cors=True)
