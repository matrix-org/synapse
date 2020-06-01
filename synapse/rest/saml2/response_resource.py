# -*- coding: utf-8 -*-
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
from twisted.python import failure

from synapse.api.errors import SynapseError
from synapse.http.server import DirectServeResource, return_html_error


class SAML2ResponseResource(DirectServeResource):
    """A Twisted web resource which handles the SAML response"""

    isLeaf = 1

    def __init__(self, hs):
        super().__init__()
        self._saml_handler = hs.get_saml_handler()
        self._error_html_template = hs.config.saml2.saml2_error_html_template

    async def _async_render_GET(self, request):
        # We're not expecting any GET request on that resource if everything goes right,
        # but some IdPs sometimes end up responding with a 302 redirect on this endpoint.
        # In this case, just tell the user that something went wrong and they should
        # try to authenticate again.
        f = failure.Failure(
            SynapseError(400, "Unexpected GET request on /saml2/authn_response")
        )
        return_html_error(f, request, self._error_html_template)

    async def _async_render_POST(self, request):
        try:
            await self._saml_handler.handle_saml_response(request)
        except Exception:
            f = failure.Failure()
            return_html_error(f, request, self._error_html_template)
