# -*- coding: utf-8 -*-
# Copyright 2014, 2015 OpenMarket Ltd
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

from synapse.streams.config import PaginationConfig
from base import ClientV1RestServlet, client_path_pattern


# TODO: Needs unit testing
class InitialSyncRestServlet(ClientV1RestServlet):
    PATTERN = client_path_pattern("/initialSync$")

    @defer.inlineCallbacks
    def on_GET(self, request):
        user, client = yield self.auth.get_user_by_req(request)
        with_feedback = "feedback" in request.args
        as_client_event = "raw" not in request.args
        pagination_config = PaginationConfig.from_request(request)
        handler = self.handlers.message_handler
        content = yield handler.snapshot_all_rooms(
            user_id=user.to_string(),
            pagin_config=pagination_config,
            feedback=with_feedback,
            as_client_event=as_client_event
        )

        defer.returnValue((200, content))


def register_servlets(hs, http_server):
    InitialSyncRestServlet(hs).register(http_server)
