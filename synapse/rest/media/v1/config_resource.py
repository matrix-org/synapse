# Copyright 2018 Will Hunt <will@half-shot.uk>
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
#

from typing import TYPE_CHECKING

from twisted.web.server import Request

from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer


class MediaConfigResource(DirectServeJsonResource):
    isLeaf = True

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        config = hs.config
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()
        self.limits_dict = {"m.upload.size": config.max_upload_size}

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        await self.auth.get_user_by_req(request)
        respond_with_json(request, 200, self.limits_dict, send_cors=True)

    async def _async_render_OPTIONS(self, request: Request) -> None:
        respond_with_json(request, 200, {}, send_cors=True)
