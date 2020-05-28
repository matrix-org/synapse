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

from synapse.http.server import (
    DirectServeResource,
    finish_request,
    wrap_html_request_handler,
)


class SAML2ResponseResource(DirectServeResource):
    """A Twisted web resource which handles the SAML response"""

    isLeaf = 1

    def __init__(self, hs):
        super().__init__()
        self._error_html_content = hs.config.saml2_error_html_content
        self._saml_handler = hs.get_saml_handler()

    async def _async_render_GET(self, request):
        # We're not expecting any GET request on that resource if everything goes right,
        # but some IdPs sometimes end up responding with a 302 redirect on this endpoint.
        # In this case, just tell the user that something went wrong and they should
        # try to authenticate again.
        request.setResponseCode(400)
        request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
        request.setHeader(b"Content-Length", b"%d" % (len(self._error_html_content),))
        request.write(self._error_html_content.encode("utf8"))
        finish_request(request)

    @wrap_html_request_handler
    async def _async_render_POST(self, request):
        return await self._saml_handler.handle_saml_response(request)
