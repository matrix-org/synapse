# -*- coding: utf-8 -*-
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

import logging

from twisted.internet import defer
from synapse.http.servlet import parse_json_object_from_request

from synapse.http import servlet
from synapse.rest.client.v1.transactions import HttpTransactionStore
from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class SendToDeviceRestServlet(servlet.RestServlet):
    PATTERNS = client_v2_patterns(
        "/sendToDevice/(?P<message_type>[^/]*)/(?P<txn_id>[^/]*)$",
        releases=[], v2_alpha=False
    )

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(SendToDeviceRestServlet, self).__init__()
        self.hs = hs
        self.auth = hs.get_auth()
        self.store = hs.get_datastore()
        self.notifier = hs.get_notifier()
        self.is_mine_id = hs.is_mine_id
        self.txns = HttpTransactionStore()

    @defer.inlineCallbacks
    def on_PUT(self, request, message_type, txn_id):
        try:
            defer.returnValue(
                self.txns.get_client_transaction(request, txn_id)
            )
        except KeyError:
            pass

        requester = yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        # TODO: Prod the notifier to wake up sync streams.
        # TODO: Implement replication for the messages.
        # TODO: Send the messages to remote servers if needed.

        local_messages = {}
        for user_id, by_device in content["messages"].items():
            if self.is_mine_id(user_id):
                messages_by_device = {
                    device_id: {
                        "content": message_content,
                        "type": message_type,
                        "sender": requester.user.to_string(),
                    }
                    for device_id, message_content in by_device.items()
                }
                if messages_by_device:
                    local_messages[user_id] = messages_by_device

        stream_id = yield self.store.add_messages_to_device_inbox(local_messages)

        self.notifier.on_new_event(
            "to_device_key", stream_id, users=local_messages.keys()
        )

        response = (200, {})
        self.txns.store_client_transaction(request, txn_id, response)
        defer.returnValue(response)


def register_servlets(hs, http_server):
    SendToDeviceRestServlet(hs).register(http_server)
