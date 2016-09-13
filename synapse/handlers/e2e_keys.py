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

from synapse.api.errors import SynapseError, CodeMessageException
from synapse.types import get_domain_from_id
from synapse.util.logcontext import preserve_fn, preserve_context_over_deferred

logger = logging.getLogger(__name__)


class E2eKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation = hs.get_replication_layer()
        self.is_mine_id = hs.is_mine_id

        # doesn't really work as part of the generic query API, because the
        # query request requires an object POST, but we abuse the
        # "query handler" interface.
        self.federation.register_query_handler(
            "client_keys", self.on_federation_query_client_keys
        )

    @defer.inlineCallbacks
    def query_devices(self, query_body, timeout):
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
        local_query = {}
        remote_queries = {}

        for user_id, device_ids in device_keys_query.items():
            if self.is_mine_id(user_id):
                local_query[user_id] = device_ids
            else:
                domain = get_domain_from_id(user_id)
                remote_queries.setdefault(domain, {})[user_id] = device_ids

        # do the queries
        failures = {}
        results = {}
        if local_query:
            local_result = yield self.query_local_devices(local_query)
            for user_id, keys in local_result.items():
                if user_id in local_query:
                    results[user_id] = keys

        @defer.inlineCallbacks
        def do_remote_query(destination):
            destination_query = remote_queries[destination]
            try:
                remote_result = yield self.federation.query_client_keys(
                    destination,
                    {"device_keys": destination_query},
                    timeout=timeout
                )
                for user_id, keys in remote_result["device_keys"].items():
                    if user_id in destination_query:
                        results[user_id] = keys
            except CodeMessageException as e:
                failures[destination] = {
                    "status": e.code, "message": e.message
                }

        yield preserve_context_over_deferred(defer.gatherResults([
            preserve_fn(do_remote_query)(destination)
            for destination in remote_queries
        ]))

        defer.returnValue((200, {
            "device_keys": results, "failures": failures,
        }))

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
                raise SynapseError(400, "Not a user here")

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
