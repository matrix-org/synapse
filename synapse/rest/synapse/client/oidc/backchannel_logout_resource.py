# Copyright 2022 The Matrix.org Foundation C.I.C.
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

from synapse.http.server import DirectServeJsonResource
from synapse.http.site import SynapseRequest

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class OIDCBackchannelLogoutResource(DirectServeJsonResource):
    isLeaf = 1

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._oidc_handler = hs.get_oidc_handler()

    async def _async_render_POST(self, request: SynapseRequest) -> None:
        await self._oidc_handler.handle_backchannel_logout(request)
