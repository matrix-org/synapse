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

from synapse.http import servlet
from synapse.http.servlet import parse_json_object_from_request
from synapse.rest.client.v1.transactions import HttpTransactionCache
from synapse.util.async import ObservableDeferred

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
        self.txns = HttpTransactionCache()
        self.device_message_handler = hs.get_device_message_handler()

    @defer.inlineCallbacks
    def on_PUT(self, request, message_type, txn_id):
        try:
            res_deferred = self.txns.get_client_transaction(request, txn_id)
            res = yield res_deferred.observe()
            defer.returnValue(res)
        except KeyError:
            pass

        res_deferred = ObservableDeferred(self._put(request, message_type, txn_id))
        self.txns.store_client_transaction(request, txn_id, res_deferred)
        res = yield res_deferred.observe()
        defer.returnValue(res)

    @defer.inlineCallbacks
    def _put(self, request, message_type, txn_id):
        requester = yield self.auth.get_user_by_req(request)

        content = parse_json_object_from_request(request)

        sender_user_id = requester.user.to_string()

        yield self.device_message_handler.send_device_message(
            sender_user_id, message_type, content["messages"]
        )

        response = (200, {})
        defer.returnValue(response)


def register_servlets(hs, http_server):
    SendToDeviceRestServlet(hs).register(http_server)
