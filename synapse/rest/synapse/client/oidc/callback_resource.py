# Copyright 2020 Quentin Gliech
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

from synapse.http.server import DirectServeHtmlResource
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class OIDCCallbackResource(DirectServeHtmlResource):
    isLeaf = 1

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._oidc_handler = hs.get_oidc_handler()

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        await self._oidc_handler.handle_oidc_callback(request)

    async def _async_render_POST(self, request: SynapseRequest) -> None:
        # the auth response can be returned via an x-www-form-urlencoded form instead
        # of GET params, as per
        # https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html.
        await self._oidc_handler.handle_oidc_callback(request)
