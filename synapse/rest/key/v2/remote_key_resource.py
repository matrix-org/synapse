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
import re
from typing import TYPE_CHECKING, Dict, Mapping, Optional, Set, Tuple

from synapse._pydantic_compat import HAS_PYDANTIC_V2

if TYPE_CHECKING or HAS_PYDANTIC_V2:
    from pydantic.v1 import Extra, StrictInt, StrictStr
else:
    from pydantic import StrictInt, StrictStr, Extra

from signedjson.sign import sign_json

from twisted.web.server import Request

from synapse.crypto.keyring import ServerKeyFetcher
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    parse_and_validate_json_object_from_request,
    parse_integer,
)
from synapse.rest.models import RequestBodyModel
from synapse.storage.keys import FetchKeyResultForRemote
from synapse.types import JsonDict
from synapse.util import json_decoder
from synapse.util.async_helpers import yieldable_gather_results

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class _KeyQueryCriteriaDataModel(RequestBodyModel):
    class Config:
        extra = Extra.allow

    minimum_valid_until_ts: Optional[StrictInt]


class RemoteKey(RestServlet):
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

    CATEGORY = "Federation requests"

    class PostBody(RequestBodyModel):
        server_keys: Dict[StrictStr, Dict[StrictStr, _KeyQueryCriteriaDataModel]]

    def __init__(self, hs: "HomeServer"):
        self.fetcher = ServerKeyFetcher(hs)
        self.store = hs.get_datastores().main
        self.clock = hs.get_clock()
        self.federation_domain_whitelist = (
            hs.config.federation.federation_domain_whitelist
        )
        self.config = hs.config

    def register(self, http_server: HttpServer) -> None:
        http_server.register_paths(
            "GET",
            (
                re.compile(
                    "^/_matrix/key/v2/query/(?P<server>[^/]*)(/(?P<key_id>[^/]*))?$"
                ),
            ),
            self.on_GET,
            self.__class__.__name__,
        )
        http_server.register_paths(
            "POST",
            (re.compile("^/_matrix/key/v2/query$"),),
            self.on_POST,
            self.__class__.__name__,
        )

    async def on_GET(
        self, request: Request, server: str, key_id: Optional[str] = None
    ) -> Tuple[int, JsonDict]:
        if server and key_id:
            # Matrix 1.6 drops support for passing the key_id, this is incompatible
            # with earlier versions and is allowed in order to support both.
            # A warning is issued to help determine when it is safe to drop this.
            logger.warning(
                "Request for remote server key with deprecated key ID (logging to determine usage level for future removal): %s / %s",
                server,
                key_id,
            )

            minimum_valid_until_ts = parse_integer(request, "minimum_valid_until_ts")
            query = {
                server: {
                    key_id: _KeyQueryCriteriaDataModel(
                        minimum_valid_until_ts=minimum_valid_until_ts
                    )
                }
            }
        else:
            query = {server: {}}

        return 200, await self.query_keys(query, query_remote_on_cache_miss=True)

    async def on_POST(self, request: Request) -> Tuple[int, JsonDict]:
        content = parse_and_validate_json_object_from_request(request, self.PostBody)

        query = content.server_keys

        return 200, await self.query_keys(query, query_remote_on_cache_miss=True)

    async def query_keys(
        self,
        query: Dict[str, Dict[str, _KeyQueryCriteriaDataModel]],
        query_remote_on_cache_miss: bool = False,
    ) -> JsonDict:
        logger.info("Handling query for keys %r", query)

        server_keys: Dict[Tuple[str, str], Optional[FetchKeyResultForRemote]] = {}
        for server_name, key_ids in query.items():
            if key_ids:
                results: Mapping[
                    str, Optional[FetchKeyResultForRemote]
                ] = await self.store.get_server_keys_json_for_remote(
                    server_name, key_ids
                )
            else:
                results = await self.store.get_all_server_keys_json_for_remote(
                    server_name
                )

            server_keys.update(
                ((server_name, key_id), res) for key_id, res in results.items()
            )

        json_results: Set[bytes] = set()

        time_now_ms = self.clock.time_msec()

        # Map server_name->key_id->int. Note that the value of the int is unused.
        # XXX: why don't we just use a set?
        cache_misses: Dict[str, Dict[str, int]] = {}
        for (server_name, key_id), key_result in server_keys.items():
            if not query[server_name]:
                # all keys were requested. Just return what we have without worrying
                # about validity
                if key_result:
                    json_results.add(key_result.key_json)
                continue

            miss = False
            if key_result is None:
                miss = True
            else:
                ts_added_ms = key_result.added_ts
                ts_valid_until_ms = key_result.valid_until_ts
                req_key = query.get(server_name, {}).get(
                    key_id, _KeyQueryCriteriaDataModel(minimum_valid_until_ts=None)
                )
                req_valid_until = req_key.minimum_valid_until_ts
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

                json_results.add(key_result.key_json)

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
            return await self.query_keys(query, query_remote_on_cache_miss=False)
        else:
            signed_keys = []
            for key_json_raw in json_results:
                key_json = json_decoder.decode(key_json_raw.decode("utf-8"))
                for signing_key in self.config.key.key_server_signing_keys:
                    key_json = sign_json(
                        key_json, self.config.server.server_name, signing_key
                    )

                signed_keys.append(key_json)

            return {"server_keys": signed_keys}
