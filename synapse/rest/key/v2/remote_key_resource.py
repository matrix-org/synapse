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
from typing import TYPE_CHECKING, Dict, Set

from signedjson.sign import sign_json

from synapse.api.errors import Codes, SynapseError
from synapse.crypto.keyring import ServerKeyFetcher
from synapse.http.server import DirectServeJsonResource, respond_with_json
from synapse.http.servlet import parse_integer, parse_json_object_from_request
from synapse.http.site import SynapseRequest
from synapse.types import JsonDict
from synapse.util import json_decoder
from synapse.util.async_helpers import yieldable_gather_results

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class RemoteKey(DirectServeJsonResource):
    """HTTP resource for retrieving the TLS certificate and NACL signature
    verification keys for a collection of servers. Checks that the reported
    X.509 TLS certificate matches the one used in the HTTPS connection. Checks
    that the NACL signature for the remote server is valid. Returns a dict of
    JSON signed by both the remote server and by this server.

    Supports individual GET APIs and a bulk query POST API.

    Requests:

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
                "signatures": {
                    "remote.server.example.com": {...}
                    "this.server.example.com": {...}
                }
            }
        ]
    }
    """

    isLeaf = True

    def __init__(self, hs: "HomeServer"):
        super().__init__()

        self.fetcher = ServerKeyFetcher(hs)
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.federation_domain_whitelist = (
            hs.config.federation.federation_domain_whitelist
        )
        self.config = hs.config

    async def _async_render_GET(self, request: SynapseRequest) -> None:
        assert request.postpath is not None
        if len(request.postpath) == 1:
            (server,) = request.postpath
            query: dict = {server.decode("ascii"): {}}
        elif len(request.postpath) == 2:
            server, key_id = request.postpath
            minimum_valid_until_ts = parse_integer(request, "minimum_valid_until_ts")
            arguments = {}
            if minimum_valid_until_ts is not None:
                arguments["minimum_valid_until_ts"] = minimum_valid_until_ts
            query = {server.decode("ascii"): {key_id.decode("ascii"): arguments}}
        else:
            raise SynapseError(404, "Not found %r" % request.postpath, Codes.NOT_FOUND)

        await self.query_keys(request, query, query_remote_on_cache_miss=True)

    async def _async_render_POST(self, request: SynapseRequest) -> None:
        content = parse_json_object_from_request(request)

        query = content["server_keys"]

        await self.query_keys(request, query, query_remote_on_cache_miss=True)

    async def query_keys(
        self,
        request: SynapseRequest,
        query: JsonDict,
        query_remote_on_cache_miss: bool = False,
    ) -> None:
        logger.info("Handling query for keys %r", query)

        store_queries = []
        for server_name, key_ids in query.items():
            if not key_ids:
                key_ids = (None,)
            for key_id in key_ids:
                store_queries.append((server_name, key_id, None))

        cached = await self.store.get_server_keys_json(store_queries)

        json_results: Set[bytes] = set()

        time_now_ms = self.clock.time_msec()

        # Map server_name->key_id->int. Note that the value of the init is unused.
        # XXX: why don't we just use a set?
        cache_misses: Dict[str, Dict[str, int]] = {}
        for (server_name, key_id, _), key_results in cached.items():
            results = [(result["ts_added_ms"], result) for result in key_results]

            if key_id is None:
                # all keys were requested. Just return what we have without worrying
                # about validity
                for _, result in results:
                    # Cast to bytes since postgresql returns a memoryview.
                    json_results.add(bytes(result["key_json"]))
                continue

            miss = False
            if not results:
                miss = True
            else:
                ts_added_ms, most_recent_result = max(results)
                ts_valid_until_ms = most_recent_result["ts_valid_until_ms"]
                req_key = query.get(server_name, {}).get(key_id, {})
                req_valid_until = req_key.get("minimum_valid_until_ts")
                if req_valid_until is not None:
                    if ts_valid_until_ms < req_valid_until:
                        logger.debug(
                            "Cached response for %r/%r is older than requested"
                            ": valid_until (%r) < minimum_valid_until (%r)",
                            server_name,
                            key_id,
                            ts_valid_until_ms,
                            req_valid_until,
                        )
                        miss = True
                    else:
                        logger.debug(
                            "Cached response for %r/%r is newer than requested"
                            ": valid_until (%r) >= minimum_valid_until (%r)",
                            server_name,
                            key_id,
                            ts_valid_until_ms,
                            req_valid_until,
                        )
                elif (ts_added_ms + ts_valid_until_ms) / 2 < time_now_ms:
                    logger.debug(
                        "Cached response for %r/%r is too old"
                        ": (added (%r) + valid_until (%r)) / 2 < now (%r)",
                        server_name,
                        key_id,
                        ts_added_ms,
                        ts_valid_until_ms,
                        time_now_ms,
                    )
                    # We more than half way through the lifetime of the
                    # response. We should fetch a fresh copy.
                    miss = True
                else:
                    logger.debug(
                        "Cached response for %r/%r is still valid"
                        ": (added (%r) + valid_until (%r)) / 2 < now (%r)",
                        server_name,
                        key_id,
                        ts_added_ms,
                        ts_valid_until_ms,
                        time_now_ms,
                    )
                # Cast to bytes since postgresql returns a memoryview.
                json_results.add(bytes(most_recent_result["key_json"]))

            if miss and query_remote_on_cache_miss:
                # only bother attempting to fetch keys from servers on our whitelist
                if (
                    self.federation_domain_whitelist is None
                    or server_name in self.federation_domain_whitelist
                ):
                    cache_misses.setdefault(server_name, {})[key_id] = 0

        # If there is a cache miss, request the missing keys, then recurse (and
        # ensure the result is sent).
        if cache_misses:
            await yieldable_gather_results(
                lambda t: self.fetcher.get_keys(*t),
                (
                    (server_name, list(keys), 0)
                    for server_name, keys in cache_misses.items()
                ),
            )
            await self.query_keys(request, query, query_remote_on_cache_miss=False)
        else:
            signed_keys = []
            for key_json_raw in json_results:
                key_json = json_decoder.decode(key_json_raw.decode("utf-8"))
                for signing_key in self.config.key.key_server_signing_keys:
                    key_json = sign_json(
                        key_json, self.config.server.server_name, signing_key
                    )

                signed_keys.append(key_json)

            response = {"server_keys": signed_keys}

            respond_with_json(request, 200, response, canonical_json=True)
