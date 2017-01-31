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

import ujson as json
import logging

from canonicaljson import encode_canonical_json
from twisted.internet import defer

from synapse.api.errors import SynapseError, CodeMessageException
from synapse.types import get_domain_from_id
from synapse.util.logcontext import preserve_fn, preserve_context_over_deferred
from synapse.util.retryutils import get_retry_limiter, NotRetryingDestination

logger = logging.getLogger(__name__)


class E2eKeysHandler(object):
    def __init__(self, hs):
        self.store = hs.get_datastore()
        self.federation = hs.get_replication_layer()
        self.device_handler = hs.get_device_handler()
        self.is_mine_id = hs.is_mine_id
        self.clock = hs.get_clock()

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
                remote_queries[user_id] = device_ids

        # Firt get local devices.
        failures = {}
        results = {}
        if local_query:
            local_result = yield self.query_local_devices(local_query)
            for user_id, keys in local_result.items():
                if user_id in local_query:
                    results[user_id] = keys

        # Now attempt to get any remote devices from our local cache.
        remote_queries_not_in_cache = {}
        if remote_queries:
            query_list = []
            for user_id, device_ids in remote_queries.iteritems():
                if device_ids:
                    query_list.extend((user_id, device_id) for device_id in device_ids)
                else:
                    query_list.append((user_id, None))

            user_ids_not_in_cache, remote_results = (
                yield self.store.get_user_devices_from_cache(
                    query_list
                )
            )
            for user_id, devices in remote_results.iteritems():
                user_devices = results.setdefault(user_id, {})
                for device_id, device in devices.iteritems():
                    keys = device.get("keys", None)
                    device_display_name = device.get("device_display_name", None)
                    if keys:
                        result = dict(keys)
                        unsigned = result.setdefault("unsigned", {})
                        if device_display_name:
                            unsigned["device_display_name"] = device_display_name
                        user_devices[device_id] = result

            for user_id in user_ids_not_in_cache:
                domain = get_domain_from_id(user_id)
                r = remote_queries_not_in_cache.setdefault(domain, {})
                r[user_id] = remote_queries[user_id]

        # Now fetch any devices that we don't have in our cache
        @defer.inlineCallbacks
        def do_remote_query(destination):
            destination_query = remote_queries_not_in_cache[destination]
            try:
                limiter = yield get_retry_limiter(
                    destination, self.clock, self.store
                )
                with limiter:
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
            except NotRetryingDestination as e:
                failures[destination] = {
                    "status": 503, "message": "Not ready for retry",
                }
            except Exception as e:
                # include ConnectionRefused and other errors
                failures[destination] = {
                    "status": 503, "message": e.message
                }

        yield preserve_context_over_deferred(defer.gatherResults([
            preserve_fn(do_remote_query)(destination)
            for destination in remote_queries_not_in_cache
        ]))

        defer.returnValue({
            "device_keys": results, "failures": failures,
        })

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
                r = dict(device_info["keys"])
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

    @defer.inlineCallbacks
    def claim_one_time_keys(self, query, timeout):
        local_query = []
        remote_queries = {}

        for user_id, device_keys in query.get("one_time_keys", {}).items():
            if self.is_mine_id(user_id):
                for device_id, algorithm in device_keys.items():
                    local_query.append((user_id, device_id, algorithm))
            else:
                domain = get_domain_from_id(user_id)
                remote_queries.setdefault(domain, {})[user_id] = device_keys

        results = yield self.store.claim_e2e_one_time_keys(local_query)

        json_result = {}
        failures = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_bytes in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json.loads(json_bytes)
                    }

        @defer.inlineCallbacks
        def claim_client_keys(destination):
            device_keys = remote_queries[destination]
            try:
                limiter = yield get_retry_limiter(
                    destination, self.clock, self.store
                )
                with limiter:
                    remote_result = yield self.federation.claim_client_keys(
                        destination,
                        {"one_time_keys": device_keys},
                        timeout=timeout
                    )
                    for user_id, keys in remote_result["one_time_keys"].items():
                        if user_id in device_keys:
                            json_result[user_id] = keys
            except CodeMessageException as e:
                failures[destination] = {
                    "status": e.code, "message": e.message
                }
            except NotRetryingDestination as e:
                failures[destination] = {
                    "status": 503, "message": "Not ready for retry",
                }
            except Exception as e:
                # include ConnectionRefused and other errors
                failures[destination] = {
                    "status": 503, "message": e.message
                }

        yield preserve_context_over_deferred(defer.gatherResults([
            preserve_fn(claim_client_keys)(destination)
            for destination in remote_queries
        ]))

        defer.returnValue({
            "one_time_keys": json_result,
            "failures": failures
        })

    @defer.inlineCallbacks
    def upload_keys_for_user(self, user_id, device_id, keys):
        time_now = self.clock.time_msec()

        # TODO: Validate the JSON to make sure it has the right keys.
        device_keys = keys.get("device_keys", None)
        if device_keys:
            logger.info(
                "Updating device_keys for device %r for user %s at %d",
                device_id, user_id, time_now
            )
            # TODO: Sign the JSON with the server key
            changed = yield self.store.set_e2e_device_keys(
                user_id, device_id, time_now, device_keys,
            )
            if changed:
                # Only notify about device updates *if* the keys actually changed
                yield self.device_handler.notify_device_update(user_id, [device_id])

        one_time_keys = keys.get("one_time_keys", None)
        if one_time_keys:
            logger.info(
                "Adding %d one_time_keys for device %r for user %r at %d",
                len(one_time_keys), device_id, user_id, time_now
            )
            key_list = []
            for key_id, key_json in one_time_keys.items():
                algorithm, key_id = key_id.split(":")
                key_list.append((
                    algorithm, key_id, encode_canonical_json(key_json)
                ))

            yield self.store.add_e2e_one_time_keys(
                user_id, device_id, time_now, key_list
            )

        # the device should have been registered already, but it may have been
        # deleted due to a race with a DELETE request. Or we may be using an
        # old access_token without an associated device_id. Either way, we
        # need to double-check the device is registered to avoid ending up with
        # keys without a corresponding device.
        self.device_handler.check_device_registered(user_id, device_id)

        result = yield self.store.count_e2e_one_time_keys(user_id, device_id)

        defer.returnValue({"one_time_key_counts": result})
