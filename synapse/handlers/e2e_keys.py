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

import json
import logging

from twisted.internet import defer

import synapse.types
from ._base import BaseHandler

logger = logging.getLogger(__name__)


class E2eKeysHandler(BaseHandler):
    def __init__(self, hs):
        super(E2eKeysHandler, self).__init__(hs)
        self.store = hs.get_datastore()
        self.federation = hs.get_replication_layer()
        self.is_mine = hs.is_mine

    @defer.inlineCallbacks
    def query_devices(self, query_body):
        local_query = []
        remote_queries = {}
        for user_id, device_ids in query_body.get("device_keys", {}).items():
            user = synapse.types.UserID.from_string(user_id)
            if self.is_mine(user):
                if not device_ids:
                    local_query.append((user_id, None))
                else:
                    for device_id in device_ids:
                        local_query.append((user_id, device_id))
            else:
                remote_queries.setdefault(user.domain, {})[user_id] = list(
                    device_ids
                )
        results = yield self.store.get_e2e_device_keys(local_query)

        json_result = {}
        for user_id, device_keys in results.items():
            for device_id, json_bytes in device_keys.items():
                json_result.setdefault(user_id, {})[
                    device_id] = json.loads(
                    json_bytes
                )

        for destination, device_keys in remote_queries.items():
            remote_result = yield self.federation.query_client_keys(
                destination, {"device_keys": device_keys}
            )
            for user_id, keys in remote_result["device_keys"].items():
                if user_id in device_keys:
                    json_result[user_id] = keys
        defer.returnValue((200, {"device_keys": json_result}))
