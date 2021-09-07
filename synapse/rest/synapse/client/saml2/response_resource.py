#
# Copyright 2018 New Vector Ltd
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

from typing import TYPE_CHECKING

from synapse.http.server import DirectServeHtmlResource

if TYPE_CHECKING:
    from synapse.server import HomeServer


class SAML2ResponseResource(DirectServeHtmlResource):
    """A Twisted web resource which handles the SAML response"""

    isLeaf = 1

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self._saml_handler = hs.get_saml_handler()
        self._sso_handler = hs.get_sso_handler()

    async def _async_render_GET(self, request):
        # We're not expecting any GET request on that resource if everything goes right,
        # but some IdPs sometimes end up responding with a 302 redirect on this endpoint.
        # In this case, just tell the user that something went wrong and they should
        # try to authenticate again.
        self._sso_handler.render_error(
            request, "unexpected_get", "Unexpected GET request on /saml2/authn_response"
        )

    async def _async_render_POST(self, request):
        await self._saml_handler.handle_saml_response(request)
