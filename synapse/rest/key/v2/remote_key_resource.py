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
from io import BytesIO

from twisted.internet import defer
from twisted.web.resource import Resource
from twisted.web.server import NOT_DONE_YET

from synapse.api.errors import Codes, SynapseError
from synapse.crypto.keyring import KeyLookupError
from synapse.http.server import respond_with_json_bytes, wrap_json_request_handler
from synapse.http.servlet import parse_integer, parse_json_object_from_request

logger = logging.getLogger(__name__)


class RemoteKey(Resource):
    """HTTP resource for retreiving the TLS certificate and NACL signature
    verification keys for a collection of servers. Checks that the reported
    X.509 TLS certificate matches the one used in the HTTPS connection. Checks
    that the NACL signature for the remote server is valid. Returns a dict of
    JSON signed by both the remote server and by this server.

    Supports individual GET APIs and a bulk query POST API.

    Requsts:

    GET /_matrix/key/v2/query/remote.server.example.com HTTP/1.1

    GET /_matrix/key/v2/query/remote.server.example.com/a.key.id HTTP/1.1

    POST /_matrix/v2/query HTTP/1.1
    Content-Type: application/json
    {
        "server_keys": {
            "remote.server.example.com": {
                "a.key.id": {
                    "minimum_valid_until_ts": 1234567890123
                }
            }
        }
    }

    Response:

    HTTP/1.1 200 OK
    Content-Type: application/json
    {
        "server_keys": [
            {
                "server_name": "remote.server.example.com"
                "valid_until_ts": # posix timestamp
                "verify_keys": {
                    "a.key.id": { # The identifier for a key.
                        key: "" # base64 encoded verification key.
                    }
                }
                "old_verify_keys": {
                    "an.old.key.id": { # The identifier for an old key.
                        key: "", # base64 encoded key
                        "expired_ts": 0, # when the key stop being used.
                    }
                }
                "tls_fingerprints": [
                    { "sha256": # fingerprint }
                ]
                "signatures": {
                    "remote.server.example.com": {...}
                    "this.server.example.com": {...}
                }
            }
        ]
    }
    """

    isLeaf = True

    def __init__(self, hs):
        self.keyring = hs.get_keyring()
        self.store = hs.get_datastore()
        self.clock = hs.get_clock()
        self.federation_domain_whitelist = hs.config.federation_domain_whitelist

    def render_GET(self, request):
        self.async_render_GET(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def async_render_GET(self, request):
        if len(request.postpath) == 1:
            server, = request.postpath
            query = {server.decode('ascii'): {}}
        elif len(request.postpath) == 2:
            server, key_id = request.postpath
            minimum_valid_until_ts = parse_integer(
                request, "minimum_valid_until_ts"
            )
            arguments = {}
            if minimum_valid_until_ts is not None:
                arguments["minimum_valid_until_ts"] = minimum_valid_until_ts
            query = {server.decode('ascii'): {key_id.decode('ascii'): arguments}}
        else:
            raise SynapseError(
                404, "Not found %r" % request.postpath, Codes.NOT_FOUND
            )

        yield self.query_keys(request, query, query_remote_on_cache_miss=True)

    def render_POST(self, request):
        self.async_render_POST(request)
        return NOT_DONE_YET

    @wrap_json_request_handler
    @defer.inlineCallbacks
    def async_render_POST(self, request):
        content = parse_json_object_from_request(request)

        query = content["server_keys"]

        yield self.query_keys(request, query, query_remote_on_cache_miss=True)

    @defer.inlineCallbacks
    def query_keys(self, request, query, query_remote_on_cache_miss=False):
        logger.info("Handling query for keys %r", query)

        store_queries = []
        for server_name, key_ids in query.items():
            if (
                self.federation_domain_whitelist is not None and
                server_name not in self.federation_domain_whitelist
            ):
                logger.debug("Federation denied with %s", server_name)
                continue

            if not key_ids:
                key_ids = (None,)
            for key_id in key_ids:
                store_queries.append((server_name, key_id, None))

        cached = yield self.store.get_server_keys_json(store_queries)

        json_results = set()

        time_now_ms = self.clock.time_msec()

        cache_misses = dict()
        for (server_name, key_id, from_server), results in cached.items():
            results = [
                (result["ts_added_ms"], result) for result in results
            ]

            if not results and key_id is not None:
                cache_misses.setdefault(server_name, set()).add(key_id)
                continue

            if key_id is not None:
                ts_added_ms, most_recent_result = max(results)
                ts_valid_until_ms = most_recent_result["ts_valid_until_ms"]
                req_key = query.get(server_name, {}).get(key_id, {})
                req_valid_until = req_key.get("minimum_valid_until_ts")
                miss = False
                if req_valid_until is not None:
                    if ts_valid_until_ms < req_valid_until:
                        logger.debug(
                            "Cached response for %r/%r is older than requested"
                            ": valid_until (%r) < minimum_valid_until (%r)",
                            server_name, key_id,
                            ts_valid_until_ms, req_valid_until
                        )
                        miss = True
                    else:
                        logger.debug(
                            "Cached response for %r/%r is newer than requested"
                            ": valid_until (%r) >= minimum_valid_until (%r)",
                            server_name, key_id,
                            ts_valid_until_ms, req_valid_until
                        )
                elif (ts_added_ms + ts_valid_until_ms) / 2 < time_now_ms:
                    logger.debug(
                        "Cached response for %r/%r is too old"
                        ": (added (%r) + valid_until (%r)) / 2 < now (%r)",
                        server_name, key_id,
                        ts_added_ms, ts_valid_until_ms, time_now_ms
                    )
                    # We more than half way through the lifetime of the
                    # response. We should fetch a fresh copy.
                    miss = True
                else:
                    logger.debug(
                        "Cached response for %r/%r is still valid"
                        ": (added (%r) + valid_until (%r)) / 2 < now (%r)",
                        server_name, key_id,
                        ts_added_ms, ts_valid_until_ms, time_now_ms
                    )

                if miss:
                    cache_misses.setdefault(server_name, set()).add(key_id)
                json_results.add(bytes(most_recent_result["key_json"]))
            else:
                for ts_added, result in results:
                    json_results.add(bytes(result["key_json"]))

        if cache_misses and query_remote_on_cache_miss:
            for server_name, key_ids in cache_misses.items():
                try:
                    yield self.keyring.get_server_verify_key_v2_direct(
                        server_name, key_ids
                    )
                except KeyLookupError as e:
                    logger.info("Failed to fetch key: %s", e)
                except Exception:
                    logger.exception("Failed to get key for %r", server_name)
            yield self.query_keys(
                request, query, query_remote_on_cache_miss=False
            )
        else:
            result_io = BytesIO()
            result_io.write(b"{\"server_keys\":")
            sep = b"["
            for json_bytes in json_results:
                result_io.write(sep)
                result_io.write(json_bytes)
                sep = b","
            if sep == b"[":
                result_io.write(sep)
            result_io.write(b"]}")

            respond_with_json_bytes(
                request, 200, result_io.getvalue(),
            )
