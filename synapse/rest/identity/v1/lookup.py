# -*- coding: utf-8 -*-
# Copyright 2019 New Vector Ltd
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

from twisted.internet import defer
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import SynapseError
from synapse.handlers.identity import IdentityHandler
from synapse.http.server import respond_with_json, wrap_json_request_handler
from synapse.http.servlet import assert_params_in_dict, parse_string

logger = logging.getLogger(__name__)


class IdentityLookup(Resource):
    isLeaf = True

    def __init__(self, hs):
        self.config = hs.config
        self.auth = hs.get_auth()
        self.identity_handler = IdentityHandler(hs)
        Resource.__init__(self)

    def render_GET(self, request):
        self.async_render_GET(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def async_render_GET(self, request):
        """Proxy a /_matrix/identity/api/v1/lookup request to an identity
        server
        """
        yield self.auth.get_user_by_req(request, allow_guest=True)

        if not self.config.enable_3pid_lookup:
            raise SynapseError(
                403,
                "Looking up third-party identifiers is denied from this server"
            )

        # Extract query parameters
        query_params = request.args
        assert_params_in_dict(query_params, [b"medium", b"address", b"is_server"])

        # Retrieve address and medium from the request parameters
        medium = parse_string(request, "medium")
        address = parse_string(request, "address")
        is_server = parse_string(request, "is_server")

        # Proxy the request to the identity server
        ret = yield self.identity_handler.lookup_3pid(is_server, medium, address)

        respond_with_json(request, 200, ret, send_cors=True)
