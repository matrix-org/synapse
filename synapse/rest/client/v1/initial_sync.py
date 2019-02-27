# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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

from twisted.internet import defer

from synapse.http.servlet import parse_boolean
from synapse.streams.config import PaginationConfig

from .base import ClientV1RestServlet, client_path_patterns


# TODO: Needs unit testing
class InitialSyncRestServlet(ClientV1RestServlet):
    PATTERNS = client_path_patterns("/initialSync$")

    def __init__(self, hs):
        super(InitialSyncRestServlet, self).__init__(hs)
        self.initial_sync_handler = hs.get_initial_sync_handler()

    @defer.inlineCallbacks
    def on_GET(self, request):
        requester = yield self.auth.get_user_by_req(request)
        as_client_event = b"raw" not in request.args
        pagination_config = PaginationConfig.from_request(request)
        include_archived = parse_boolean(request, "archived", default=False)
        content = yield self.initial_sync_handler.snapshot_all_rooms(
            user_id=requester.user.to_string(),
            pagin_config=pagination_config,
            as_client_event=as_client_event,
            include_archived=include_archived,
        )

        defer.returnValue((200, content))


def register_servlets(hs, http_server):
    InitialSyncRestServlet(hs).register(http_server)
