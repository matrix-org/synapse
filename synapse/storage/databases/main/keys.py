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
from typing import Dict, Iterable, Mapping, Optional, Tuple

from signedjson.key import decode_verify_key_bytes
from unpaddedbase64 import decode_base64

from synapse.storage.databases.main.cache import CacheInvalidationWorkerStore
from synapse.storage.keys import FetchKeyResult, FetchKeyResultForRemote
from synapse.storage.types import Cursor
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.iterutils import batch_iter

logger = logging.getLogger(__name__)


db_binary_type = memoryview


class KeyStore(CacheInvalidationWorkerStore):
    """Persistence for signature verification keys"""

    @cached()
    def _get_server_signature_key(
        self, server_name_and_key_id: Tuple[str, str]
    ) -> FetchKeyResult:
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_server_signature_key",
        list_name="server_name_and_key_ids",
    )
    async def get_server_signature_keys(
        self, server_name_and_key_ids: Iterable[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], FetchKeyResult]:
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
            sql = """
            SELECT server_name, key_id, verify_key, ts_valid_until_ms
            FROM server_signature_keys WHERE 1=0
            """ + " OR (server_name=? AND key_id=?)" * len(
                batch
            )

            txn.execute(sql, tuple(itertools.chain.from_iterable(batch)))

            for row in txn:
                server_name, key_id, key_bytes, ts_valid_until_ms = row

                if ts_valid_until_ms is None:
                    # Old keys may be stored with a ts_valid_until_ms of null,
                    # in which case we treat this as if it was set to `0`, i.e.
                    # it won't match key requests that define a minimum
                    # `ts_valid_until_ms`.
                    ts_valid_until_ms = 0

                keys[(server_name, key_id)] = FetchKeyResult(
                    verify_key=decode_verify_key_bytes(key_id, bytes(key_bytes)),
                    valid_until_ts=ts_valid_until_ms,
                )

        def _txn(txn: Cursor) -> Dict[Tuple[str, str], FetchKeyResult]:
            for batch in batch_iter(server_name_and_key_ids, 50):
                _get_keys(txn, batch)
            return keys

        return await self.db_pool.runInteraction("get_server_signature_keys", _txn)

    async def store_server_signature_keys(
        self,
        from_server: str,
        ts_added_ms: int,
        verify_keys: Mapping[Tuple[str, str], FetchKeyResult],
    ) -> None:
        """Stores NACL verification keys for remote servers.
        Args:
            from_server: Where the verification keys were looked up
            ts_added_ms: The time to record that the key was added
            verify_keys:
                keys to be stored. Each entry is a triplet of
                (server_name, key_id, key).
        """
        key_values = []
        value_values = []
        invalidations = []
        for (server_name, key_id), fetch_result in verify_keys.items():
            key_values.append((server_name, key_id))
            value_values.append(
                (
                    from_server,
                    ts_added_ms,
                    fetch_result.valid_until_ts,
                    db_binary_type(fetch_result.verify_key.encode()),
                )
            )
            # invalidate takes a tuple corresponding to the params of
            # _get_server_signature_key. _get_server_signature_key only takes one
            # param, which is itself the 2-tuple (server_name, key_id).
            invalidations.append((server_name, key_id))

        await self.db_pool.simple_upsert_many(
            table="server_signature_keys",
            key_names=("server_name", "key_id"),
            key_values=key_values,
            value_names=(
                "from_server",
                "ts_added_ms",
                "ts_valid_until_ms",
                "verify_key",
            ),
            value_values=value_values,
            desc="store_server_signature_keys",
        )

        invalidate = self._get_server_signature_key.invalidate
        for i in invalidations:
            invalidate((i,))

    async def store_server_keys_json(
        self,
        server_name: str,
        key_id: str,
        from_server: str,
        ts_now_ms: int,
        ts_expires_ms: int,
        key_json_bytes: bytes,
    ) -> None:
        """Stores the JSON bytes for a set of keys from a server
        The JSON should be signed by the originating server, the intermediate
        server, and by this server. Updates the value for the
        (server_name, key_id, from_server) triplet if one already existed.
        Args:
            server_name: The name of the server.
            key_id: The identifier of the key this JSON is for.
            from_server: The server this JSON was fetched from.
            ts_now_ms: The time now in milliseconds.
            ts_valid_until_ms: The time when this json stops being valid.
            key_json_bytes: The encoded JSON.
        """
        await self.db_pool.simple_upsert(
            table="server_keys_json",
            keyvalues={
                "server_name": server_name,
                "key_id": key_id,
                "from_server": from_server,
            },
            values={
                "server_name": server_name,
                "key_id": key_id,
                "from_server": from_server,
                "ts_added_ms": ts_now_ms,
                "ts_valid_until_ms": ts_expires_ms,
                "key_json": db_binary_type(key_json_bytes),
            },
            desc="store_server_keys_json",
        )

        # invalidate takes a tuple corresponding to the params of
        # _get_server_keys_json. _get_server_keys_json only takes one
        # param, which is itself the 2-tuple (server_name, key_id).
        await self.invalidate_cache_and_stream(
            "_get_server_keys_json", ((server_name, key_id),)
        )
        await self.invalidate_cache_and_stream(
            "get_server_key_json_for_remote", (server_name, key_id)
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
    ) -> Dict[Tuple[str, str], FetchKeyResult]:
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
            sql = """
            SELECT server_name, key_id, key_json, ts_valid_until_ms
            FROM server_keys_json WHERE 1=0
            """ + " OR (server_name=? AND key_id=?)" * len(
                batch
            )

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
    ) -> Dict[str, Optional[FetchKeyResultForRemote]]:
        """Fetch the cached keys for the given server/key IDs.

        If we have multiple entries for a given key ID, returns the most recent.
        """
        rows = await self.db_pool.simple_select_many_batch(
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
        )

        if not rows:
            return {}

        # We sort the rows so that the most recently added entry is picked up.
        rows.sort(key=lambda r: r["ts_added_ms"])

        return {
            row["key_id"]: FetchKeyResultForRemote(
                # Cast to bytes since postgresql returns a memoryview.
                key_json=bytes(row["key_json"]),
                valid_until_ts=row["ts_valid_until_ms"],
                added_ts=row["ts_added_ms"],
            )
            for row in rows
        }

    async def get_all_server_keys_json_for_remote(
        self,
        server_name: str,
    ) -> Dict[str, FetchKeyResultForRemote]:
        """Fetch the cached keys for the given server.

        If we have multiple entries for a given key ID, returns the most recent.
        """
        rows = await self.db_pool.simple_select_list(
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
        )

        if not rows:
            return {}

        rows.sort(key=lambda r: r["ts_added_ms"])

        return {
            row["key_id"]: FetchKeyResultForRemote(
                # Cast to bytes since postgresql returns a memoryview.
                key_json=bytes(row["key_json"]),
                valid_until_ts=row["ts_valid_until_ms"],
                added_ts=row["ts_added_ms"],
            )
            for row in rows
        }
