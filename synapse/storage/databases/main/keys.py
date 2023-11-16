# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd.
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

import itertools
import json
import logging
from typing import Dict, Iterable, List, Mapping, Optional, Tuple, Union, cast

from canonicaljson import encode_canonical_json
from signedjson.key import decode_verify_key_bytes
from unpaddedbase64 import decode_base64

from synapse.storage.database import LoggingTransaction
from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.keys import FetchKeyResult, FetchKeyResultForRemote
from synapse.storage.types import Cursor
from synapse.types import JsonDict
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.iterutils import batch_iter

logger = logging.getLogger(__name__)


db_binary_type = memoryview


class KeyStore(CacheInvalidationWorkerStore):
    """Persistence for signature verification keys"""

    async def store_server_keys_response(
        self,
        server_name: str,
        from_server: str,
        ts_added_ms: int,
        verify_keys: Dict[str, FetchKeyResult],
        response_json: JsonDict,
    ) -> None:
        """Stores the keys for the given server that we got from `from_server`.

        Args:
            server_name: The owner of the keys
            from_server: Which server we got the keys from
            ts_added_ms: When we're adding the keys
            verify_keys: The decoded keys
            response_json: The full *signed* response JSON that contains the keys.
        """

        key_json_bytes = encode_canonical_json(response_json)

        def store_server_keys_response_txn(txn: LoggingTransaction) -> None:
            self.db_pool.simple_upsert_many_txn(
                txn,
                table="server_signature_keys",
                key_names=("server_name", "key_id"),
                key_values=[(server_name, key_id) for key_id in verify_keys],
                value_names=(
                    "from_server",
                    "ts_added_ms",
                    "ts_valid_until_ms",
                    "verify_key",
                ),
                value_values=[
                    (
                        from_server,
                        ts_added_ms,
                        fetch_result.valid_until_ts,
                        db_binary_type(fetch_result.verify_key.encode()),
                    )
                    for fetch_result in verify_keys.values()
                ],
            )

            self.db_pool.simple_upsert_many_txn(
                txn,
                table="server_keys_json",
                key_names=("server_name", "key_id", "from_server"),
                key_values=[
                    (server_name, key_id, from_server) for key_id in verify_keys
                ],
                value_names=(
                    "ts_added_ms",
                    "ts_valid_until_ms",
                    "key_json",
                ),
                value_values=[
                    (
                        ts_added_ms,
                        fetch_result.valid_until_ts,
                        db_binary_type(key_json_bytes),
                    )
                    for fetch_result in verify_keys.values()
                ],
            )

            # invalidate takes a tuple corresponding to the params of
            # _get_server_keys_json. _get_server_keys_json only takes one
            # param, which is itself the 2-tuple (server_name, key_id).
            self._invalidate_cache_and_stream_bulk(
                txn,
                self._get_server_keys_json,
                [((server_name, key_id),) for key_id in verify_keys],
            )
            self._invalidate_cache_and_stream_bulk(
                txn,
                self.get_server_key_json_for_remote,
                [(server_name, key_id) for key_id in verify_keys],
            )

        await self.db_pool.runInteraction(
            "store_server_keys_response", store_server_keys_response_txn
        )

    @cached()
    def _get_server_keys_json(
        self, server_name_and_key_id: Tuple[str, str]
    ) -> FetchKeyResult:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_server_keys_json", list_name="server_name_and_key_ids"
    )
    async def get_server_keys_json(
        self, server_name_and_key_ids: Iterable[Tuple[str, str]]
    ) -> Mapping[Tuple[str, str], FetchKeyResult]:
        """
        Args:
            server_name_and_key_ids:
                iterable of (server_name, key-id) tuples to fetch keys for

        Returns:
            A map from (server_name, key_id) -> FetchKeyResult, or None if the
            key is unknown
        """
        keys = {}

        def _get_keys(txn: Cursor, batch: Tuple[Tuple[str, str], ...]) -> None:
            """Processes a batch of keys to fetch, and adds the result to `keys`."""

            # batch_iter always returns tuples so it's safe to do len(batch)
            where_clause = " OR (server_name=? AND key_id=?)" * len(batch)

            # `server_keys_json` can have multiple entries per server (one per
            # remote server we fetched from, if using perspectives). Order by
            # `ts_added_ms` so the most recently fetched one always wins.
            sql = f"""
                SELECT server_name, key_id, key_json, ts_valid_until_ms
                FROM server_keys_json WHERE 1=0
                {where_clause}
                ORDER BY ts_added_ms
            """

            txn.execute(sql, tuple(itertools.chain.from_iterable(batch)))

            for server_name, key_id, key_json_bytes, ts_valid_until_ms in txn:
                if ts_valid_until_ms is None:
                    # Old keys may be stored with a ts_valid_until_ms of null,
                    # in which case we treat this as if it was set to `0`, i.e.
                    # it won't match key requests that define a minimum
                    # `ts_valid_until_ms`.
                    ts_valid_until_ms = 0

                # The entire signed JSON response is stored in server_keys_json,
                # fetch out the bits needed.
                key_json = json.loads(bytes(key_json_bytes))
                key_base64 = key_json["verify_keys"][key_id]["key"]

                keys[(server_name, key_id)] = FetchKeyResult(
                    verify_key=decode_verify_key_bytes(
                        key_id, decode_base64(key_base64)
                    ),
                    valid_until_ts=ts_valid_until_ms,
                )

        def _txn(txn: Cursor) -> Dict[Tuple[str, str], FetchKeyResult]:
            for batch in batch_iter(server_name_and_key_ids, 50):
                _get_keys(txn, batch)
            return keys

        return await self.db_pool.runInteraction("get_server_keys_json", _txn)

    @cached()
    def get_server_key_json_for_remote(
        self,
        server_name: str,
        key_id: str,
    ) -> Optional[FetchKeyResultForRemote]:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="get_server_key_json_for_remote", list_name="key_ids"
    )
    async def get_server_keys_json_for_remote(
        self, server_name: str, key_ids: Iterable[str]
    ) -> Mapping[str, Optional[FetchKeyResultForRemote]]:
        """Fetch the cached keys for the given server/key IDs.

        If we have multiple entries for a given key ID, returns the most recent.
        """
        rows = cast(
            List[Tuple[str, str, int, int, Union[bytes, memoryview]]],
            await self.db_pool.simple_select_many_batch(
                table="server_keys_json",
                column="key_id",
                iterable=key_ids,
                keyvalues={"server_name": server_name},
                retcols=(
                    "key_id",
                    "from_server",
                    "ts_added_ms",
                    "ts_valid_until_ms",
                    "key_json",
                ),
                desc="get_server_keys_json_for_remote",
            ),
        )

        if not rows:
            return {}

        # We sort the rows by ts_added_ms so that the most recently added entry
        # will stomp over older entries in the dictionary.
        rows.sort(key=lambda r: r[2])

        return {
            key_id: FetchKeyResultForRemote(
                # Cast to bytes since postgresql returns a memoryview.
                key_json=bytes(key_json),
                valid_until_ts=ts_valid_until_ms,
                added_ts=ts_added_ms,
            )
            for key_id, from_server, ts_added_ms, ts_valid_until_ms, key_json in rows
        }

    async def get_all_server_keys_json_for_remote(
        self,
        server_name: str,
    ) -> Dict[str, FetchKeyResultForRemote]:
        """Fetch the cached keys for the given server.

        If we have multiple entries for a given key ID, returns the most recent.
        """
        rows = cast(
            List[Tuple[str, str, int, int, Union[bytes, memoryview]]],
            await self.db_pool.simple_select_list(
                table="server_keys_json",
                keyvalues={"server_name": server_name},
                retcols=(
                    "key_id",
                    "from_server",
                    "ts_added_ms",
                    "ts_valid_until_ms",
                    "key_json",
                ),
                desc="get_server_keys_json_for_remote",
            ),
        )

        if not rows:
            return {}

        # We sort the rows by ts_added_ms so that the most recently added entry
        # will stomp over older entries in the dictionary.
        rows.sort(key=lambda r: r[2])

        return {
            key_id: FetchKeyResultForRemote(
                # Cast to bytes since postgresql returns a memoryview.
                key_json=bytes(key_json),
                valid_until_ts=ts_valid_until_ms,
                added_ts=ts_added_ms,
            )
            for key_id, from_server, ts_added_ms, ts_valid_until_ms, key_json in rows
        }
