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
from typing import TYPE_CHECKING

from synapse.api.errors import LimitExceededError
from synapse.api.ratelimiting import Ratelimiter
from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.rest.media.v1.media_repository import MediaRepository
    from synapse.server import HomeServer


logger = logging.getLogger(__name__)


class CreateResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs: "HomeServer", media_repo: "MediaRepository"):
        super().__init__()

        self.media_repo = media_repo
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()

        # A rate limiter for creating new media IDs.
        self._create_media_rate_limiter = Ratelimiter(
            store=hs.get_datastores().main,
            clock=self.clock,
            rate_hz=hs.config.ratelimiting.rc_media_create.per_second,
            burst_count=hs.config.ratelimiting.rc_media_create.burst_count,
        )

    async def _async_render_OPTIONS(self, request: SynapseRequest) -> None:
        respond_with_json(request, 200, {}, send_cors=True)

    async def _async_render_POST(self, request: SynapseRequest) -> None:
        requester = await self.auth.get_user_by_req(request)

        # If the create media requests for the user are over the limit, drop
        # them.
        allowed, time_allowed = await self._create_media_rate_limiter.can_do_action(
            requester
        )
        if not allowed:
            time_now_s = self.clock.time()
            raise LimitExceededError(
                retry_after_ms=int(1000 * (time_allowed - time_now_s))
            )

        content_uri, unused_expires_at = await self.media_repo.create_media_id(
            requester.user
        )

        logger.info(
            "Created Media URI %r that if unused will expire at %d",
            content_uri,
            unused_expires_at,
        )
        respond_with_json(
            request,
            200,
            {
                "content_uri": content_uri,
                "unused_expires_at": unused_expires_at,
            },
            send_cors=True,
        )
