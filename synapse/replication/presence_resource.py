# Copyright 2016 OpenMarket Ltd
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

from synapse.http.server import respond_with_json_bytes, request_handler
from synapse.http.servlet import parse_json_object_from_request

from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET
from twisted.internet import defer


class PresenceResource(Resource):
    """
    HTTP endpoint for marking users as syncing.

    POST /_synapse/replication/presence HTTP/1.1
    Content-Type: application/json

    {
        "process_id": "<process_id>",
        "syncing_users": ["<user_id>"]
    }
    """

    def __init__(self, hs):
        Resource.__init__(self)  # Resource is old-style, so no super()

        self.version_string = hs.version_string
        self.clock = hs.get_clock()
        self.presence_handler = hs.get_presence_handler()

    def render_POST(self, request):
        self._async_render_POST(request)
        return NOT_DONE_YET

    @request_handler()
    @defer.inlineCallbacks
    def _async_render_POST(self, request):
        content = parse_json_object_from_request(request)

        process_id = content["process_id"]
        syncing_user_ids = content["syncing_users"]

        yield self.presence_handler.update_external_syncs(
            process_id, set(syncing_user_ids)
        )

        respond_with_json_bytes(request, 200, "{}")
