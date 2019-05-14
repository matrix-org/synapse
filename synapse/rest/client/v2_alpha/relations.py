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

"""This class implements the proposed relation APIs from MSC 1849.

Since the MSC has not been approved all APIs here are unstable and may change at
any time to reflect changes in the MSC.
"""

import logging

from twisted.internet import defer

from synapse.api.constants import EventTypes
from synapse.api.errors import SynapseError
from synapse.http.servlet import (
    RestServlet,
    parse_json_object_from_request,
    parse_string,
)

from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class RelationSendServlet(RestServlet):
    """Helper API for sending events that have relation data.

    Example API shape to send a 👍 reaction to a room:

        POST /rooms/!foo/send_relation/$bar/m.annotation/m.reaction?key=%F0%9F%91%8D
        {}

        {
            "event_id": "$foobar"
        }
    """

    PATTERN = (
        "/rooms/(?P<room_id>[^/]*)/send_relation"
        "/(?P<parent_id>[^/]*)/(?P<relation_type>[^/]*)/(?P<event_type>[^/]*)"
    )

    def __init__(self, hs):
        super(RelationSendServlet, self).__init__()
        self.auth = hs.get_auth()
        self.event_creation_handler = hs.get_event_creation_handler()

    def register(self, http_server):
        http_server.register_paths(
            "POST",
            client_v2_patterns(self.PATTERN + "$", releases=()),
            self.on_PUT_or_POST,
        )
        http_server.register_paths(
            "PUT",
            client_v2_patterns(self.PATTERN + "/(?P<txn_id>[^/]*)$", releases=()),
            self.on_PUT_or_POST,
        )

    @defer.inlineCallbacks
    def on_PUT_or_POST(
        self, request, room_id, parent_id, relation_type, event_type, txn_id=None
    ):
        requester = yield self.auth.get_user_by_req(request, allow_guest=True)

        if event_type == EventTypes.Member:
            # Add relations to a membership is meaningless, so we just deny it
            # at the CS API rather than trying to handle it correctly.
            raise SynapseError(400, "Cannot send member events with relations")

        content = parse_json_object_from_request(request)

        aggregation_key = parse_string(request, "key", encoding="utf-8")

        content["m.relates_to"] = {
            "event_id": parent_id,
            "key": aggregation_key,
            "rel_type": relation_type,
        }

        event_dict = {
            "type": event_type,
            "content": content,
            "room_id": room_id,
            "sender": requester.user.to_string(),
        }

        event = yield self.event_creation_handler.create_and_send_nonmember_event(
            requester, event_dict=event_dict, txn_id=txn_id
        )

        defer.returnValue((200, {"event_id": event.event_id}))


def register_servlets(hs, http_server):
    RelationSendServlet(hs).register(http_server)
