# -*- coding: utf-8 -*-
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

import logging

from twisted.internet import defer

from synapse.http.servlet import parse_json_object_from_request
from synapse.replication.http._base import ReplicationEndpoint
from synapse.types import Requester, UserID

logger = logging.getLogger(__name__)


class ReplicationHandleProfileChangeRestServlet(ReplicationEndpoint):
    NAME = "profile_changed"
    PATH_ARGS = ("user_id",)
    POST = True

    def __init__(self, hs):
        super(ReplicationHandleProfileChangeRestServlet, self).__init__(hs)

        self.user_directory_handler = hs.get_user_directory_handler()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()

    @staticmethod
    def _serialize_payload(requester, user_id):
        """
        Args:
            requester (Requester)
            user_id (str)
        """

        return {
            "requester": requester.serialize(),
        }

    @defer.inlineCallbacks
    def _handle_request(self, request, user_id):
        content = parse_json_object_from_request(request)

        requester = Requester.deserialize(self.store, content["requester"])

        if requester.user:
            request.authenticated_entity = requester.user.to_string()

        target_user = UserID.from_string(user_id)

        profile = yield self.store.get_profileinfo(target_user.localpart)
        yield self.user_directory_handler.handle_local_profile_change(
            user_id, profile
        )

        defer.returnValue((200, {}))


def register_servlets(hs, http_server):
    ReplicationHandleProfileChangeRestServlet(hs).register(http_server)
