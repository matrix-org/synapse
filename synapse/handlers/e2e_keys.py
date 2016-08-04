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

import collections
import json
import logging

from twisted.internet import defer

from synapse.api import errors
import synapse.types

logger = logging.getLogger(__name__)


class E2eKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation = hs.get_replication_layer()
        self.is_mine_id = hs.is_mine_id
        self.server_name = hs.hostname

        # doesn't really work as part of the generic query API, because the
        # query request requires an object POST, but we abuse the
        # "query handler" interface.
        self.federation.register_query_handler(
            "client_keys", self.on_federation_query_client_keys
        )

    @defer.inlineCallbacks
    def query_devices(self, query_body):
        """ Handle a device key query from a client

        {
            "device_keys": {
                "<user_id>": ["<device_id>"]
            }
        }
        ->
        {
            "device_keys": {
                "<user_id>": {
                    "<device_id>": {
                        ...
                    }
                }
            }
        }
        """
        device_keys_query = query_body.get("device_keys", {})

        # separate users by domain.
        # make a map from domain to user_id to device_ids
        queries_by_domain = collections.defaultdict(dict)
        for user_id, device_ids in device_keys_query.items():
            user = synapse.types.UserID.from_string(user_id)
            queries_by_domain[user.domain][user_id] = device_ids

        # do the queries
        # TODO: do these in parallel
        results = {}
        for destination, destination_query in queries_by_domain.items():
            if destination == self.server_name:
                res = yield self.query_local_devices(destination_query)
            else:
                res = yield self.federation.query_client_keys(
                    destination, {"device_keys": destination_query}
                )
                res = res["device_keys"]
            for user_id, keys in res.items():
                if user_id in destination_query:
                    results[user_id] = keys

        defer.returnValue((200, {"device_keys": results}))

    @defer.inlineCallbacks
    def query_local_devices(self, query):
        """Get E2E device keys for local users

        Args:
            query (dict[string, list[string]|None): map from user_id to a list
                 of devices to query (None for all devices)

        Returns:
            defer.Deferred: (resolves to dict[string, dict[string, dict]]):
                 map from user_id -> device_id -> device details
        """
        local_query = []

        result_dict = {}
        for user_id, device_ids in query.items():
            if not self.is_mine_id(user_id):
                logger.warning("Request for keys for non-local user %s",
                               user_id)
                raise errors.SynapseError(400, "Not a user here")

            if not device_ids:
                local_query.append((user_id, None))
            else:
                for device_id in device_ids:
                    local_query.append((user_id, device_id))

            # make sure that each queried user appears in the result dict
            result_dict[user_id] = {}

        results = yield self.store.get_e2e_device_keys(local_query)

        # Build the result structure, un-jsonify the results, and add the
        # "unsigned" section
        for user_id, device_keys in results.items():
            for device_id, device_info in device_keys.items():
                r = json.loads(device_info["key_json"])
                r["unsigned"] = {}
                display_name = device_info["device_display_name"]
                if display_name is not None:
                    r["unsigned"]["device_display_name"] = display_name
                result_dict[user_id][device_id] = r

        defer.returnValue(result_dict)

    @defer.inlineCallbacks
    def on_federation_query_client_keys(self, query_body):
        """ Handle a device key query from a federated server
        """
        device_keys_query = query_body.get("device_keys", {})
        res = yield self.query_local_devices(device_keys_query)
        defer.returnValue({"device_keys": res})
