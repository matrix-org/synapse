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

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.http.server import wrap_html_request_handler


class SAML2ResponseResource(Resource):
    """A Twisted web resource which handles the SAML response"""

    isLeaf = 1

    def __init__(self, hs):
        Resource.__init__(self)
        self._saml_handler = hs.get_saml_handler()

    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    @wrap_html_request_handler
    def _async_render_POST(self, request):
        return self._saml_handler.handle_saml_response(request)
