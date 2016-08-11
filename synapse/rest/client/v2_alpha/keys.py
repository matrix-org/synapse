# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

import simplejson as json
from canonicaljson import encode_canonical_json
from twisted.internet import defer

import synapse.api.errors
import synapse.server
import synapse.types
from synapse.http.servlet import RestServlet, parse_json_object_from_request
from synapse.types import UserID
from ._base import client_v2_patterns

logger = logging.getLogger(__name__)


class KeyUploadServlet(RestServlet):
    """
    POST /keys/upload HTTP/1.1
    Content-Type: application/json

    {
      "device_keys": {
        "user_id": "<user_id>",
        "device_id": "<device_id>",
        "valid_until_ts": <millisecond_timestamp>,
        "algorithms": [
          "m.olm.curve25519-aes-sha256",
        ]
        "keys": {
          "<algorithm>:<device_id>": "<key_base64>",
        },
        "signatures:" {
          "<user_id>" {
            "<algorithm>:<device_id>": "<signature_base64>"
      } } },
      "one_time_keys": {
        "<algorithm>:<key_id>": "<key_base64>"
      },
    }
    """
    PATTERNS = client_v2_patterns("/keys/upload(/(?P<device_id>[^/]+))?$",
                                  releases=())

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super(KeyUploadServlet, self).__init__()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.auth = hs.get_auth()
        self.device_handler = hs.get_device_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, device_id):
        requester = yield self.auth.get_user_by_req(request)

        user_id = requester.user.to_string()

        body = parse_json_object_from_request(request)

        if device_id is not None:
            # passing the device_id here is deprecated; however, we allow it
            # for now for compatibility with older clients.
            if (requester.device_id is not None and
                    device_id != requester.device_id):
                logger.warning("Client uploading keys for a different device "
                               "(logged in as %s, uploading for %s)",
                               requester.device_id, device_id)
        else:
            device_id = requester.device_id

        if device_id is None:
            raise synapse.api.errors.SynapseError(
                400,
                "To upload keys, you must pass device_id when authenticating"
            )

        time_now = self.clock.time_msec()

        # TODO: Validate the JSON to make sure it has the right keys.
        device_keys = body.get("device_keys", None)
        if device_keys:
            logger.info(
                "Updating device_keys for device %r for user %s at %d",
                device_id, user_id, time_now
            )
            # TODO: Sign the JSON with the server key
            yield self.store.set_e2e_device_keys(
                user_id, device_id, time_now,
                encode_canonical_json(device_keys)
            )

        one_time_keys = body.get("one_time_keys", None)
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
        defer.returnValue((200, {"one_time_key_counts": result}))


class KeyQueryServlet(RestServlet):
    """
    GET /keys/query/<user_id> HTTP/1.1

    GET /keys/query/<user_id>/<device_id> HTTP/1.1

    POST /keys/query HTTP/1.1
    Content-Type: application/json
    {
      "device_keys": {
        "<user_id>": ["<device_id>"]
    } }

    HTTP/1.1 200 OK
    {
      "device_keys": {
        "<user_id>": {
          "<device_id>": {
            "user_id": "<user_id>", // Duplicated to be signed
            "device_id": "<device_id>", // Duplicated to be signed
            "valid_until_ts": <millisecond_timestamp>,
            "algorithms": [ // List of supported algorithms
              "m.olm.curve25519-aes-sha256",
            ],
            "keys": { // Must include a ed25519 signing key
              "<algorithm>:<key_id>": "<key_base64>",
            },
            "signatures:" {
              // Must be signed with device's ed25519 key
              "<user_id>/<device_id>": {
                "<algorithm>:<key_id>": "<signature_base64>"
              }
              // Must be signed by this server.
              "<server_name>": {
                "<algorithm>:<key_id>": "<signature_base64>"
    } } } } } }
    """

    PATTERNS = client_v2_patterns(
        "/keys/query(?:"
        "/(?P<user_id>[^/]*)(?:"
        "/(?P<device_id>[^/]*)"
        ")?"
        ")?",
        releases=()
    )

    def __init__(self, hs):
        """
        Args:
            hs (synapse.server.HomeServer):
        """
        super(KeyQueryServlet, self).__init__()
        self.auth = hs.get_auth()
        self.e2e_keys_handler = hs.get_e2e_keys_handler()

    @defer.inlineCallbacks
    def on_POST(self, request, user_id, device_id):
        yield self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)
        result = yield self.e2e_keys_handler.query_devices(body)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def on_GET(self, request, user_id, device_id):
        requester = yield self.auth.get_user_by_req(request)
        auth_user_id = requester.user.to_string()
        user_id = user_id if user_id else auth_user_id
        device_ids = [device_id] if device_id else []
        result = yield self.e2e_keys_handler.query_devices(
            {"device_keys": {user_id: device_ids}}
        )
        defer.returnValue(result)


class OneTimeKeyServlet(RestServlet):
    """
    GET /keys/claim/<user-id>/<device-id>/<algorithm> HTTP/1.1

    POST /keys/claim HTTP/1.1
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": "<algorithm>"
    } } }

    HTTP/1.1 200 OK
    {
      "one_time_keys": {
        "<user_id>": {
          "<device_id>": {
            "<algorithm>:<key_id>": "<key_base64>"
    } } } }

    """
    PATTERNS = client_v2_patterns(
        "/keys/claim(?:/?|(?:/"
        "(?P<user_id>[^/]*)/(?P<device_id>[^/]*)/(?P<algorithm>[^/]*)"
        ")?)",
        releases=()
    )

    def __init__(self, hs):
        super(OneTimeKeyServlet, self).__init__()
        self.store = hs.get_datastore()
        self.auth = hs.get_auth()
        self.clock = hs.get_clock()
        self.federation = hs.get_replication_layer()
        self.is_mine = hs.is_mine

    @defer.inlineCallbacks
    def on_GET(self, request, user_id, device_id, algorithm):
        yield self.auth.get_user_by_req(request)
        result = yield self.handle_request(
            {"one_time_keys": {user_id: {device_id: algorithm}}}
        )
        defer.returnValue(result)

    @defer.inlineCallbacks
    def on_POST(self, request, user_id, device_id, algorithm):
        yield self.auth.get_user_by_req(request)
        body = parse_json_object_from_request(request)
        result = yield self.handle_request(body)
        defer.returnValue(result)

    @defer.inlineCallbacks
    def handle_request(self, body):
        local_query = []
        remote_queries = {}
        for user_id, device_keys in body.get("one_time_keys", {}).items():
            user = UserID.from_string(user_id)
            if self.is_mine(user):
                for device_id, algorithm in device_keys.items():
                    local_query.append((user_id, device_id, algorithm))
            else:
                remote_queries.setdefault(user.domain, {})[user_id] = (
                    device_keys
                )
        results = yield self.store.claim_e2e_one_time_keys(local_query)

        json_result = {}
        for user_id, device_keys in results.items():
            for device_id, keys in device_keys.items():
                for key_id, json_bytes in keys.items():
                    json_result.setdefault(user_id, {})[device_id] = {
                        key_id: json.loads(json_bytes)
                    }

        for destination, device_keys in remote_queries.items():
            remote_result = yield self.federation.claim_client_keys(
                destination, {"one_time_keys": device_keys}
            )
            for user_id, keys in remote_result["one_time_keys"].items():
                if user_id in device_keys:
                    json_result[user_id] = keys

        defer.returnValue((200, {"one_time_keys": json_result}))


def register_servlets(hs, http_server):
    KeyUploadServlet(hs).register(http_server)
    KeyQueryServlet(hs).register(http_server)
    OneTimeKeyServlet(hs).register(http_server)
