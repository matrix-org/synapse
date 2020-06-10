# -*- coding: utf-8 -*-
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
import logging

from signedjson.key import decode_verify_key_bytes

from synapse.storage._base import SQLBaseStore
from synapse.storage.keys import FetchKeyResult
from synapse.util.caches.descriptors import cached, cachedList
from synapse.util.iterutils import batch_iter

logger = logging.getLogger(__name__)


db_binary_type = memoryview


class KeyStore(SQLBaseStore):
    """Persistence for signature verification keys
    """

    @cached()
    def _get_server_verify_key(self, server_name_and_key_id):
        raise NotImplementedError()

    @cachedList(
        cached_method_name="_get_server_verify_key", list_name="server_name_and_key_ids"
    )
    def get_server_verify_keys(self, server_name_and_key_ids):
        """
        Args:
            server_name_and_key_ids (iterable[Tuple[str, str]]):
                iterable of (server_name, key-id) tuples to fetch keys for

        Returns:
            Deferred: resolves to dict[Tuple[str, str], FetchKeyResult|None]:
                map from (server_name, key_id) -> FetchKeyResult, or None if the key is
                unknown
        """
        keys = {}

        def _get_keys(txn, batch):
            """Processes a batch of keys to fetch, and adds the result to `keys`."""

            # batch_iter always returns tuples so it's safe to do len(batch)
            sql = (
                "SELECT server_name, key_id, verify_key, ts_valid_until_ms "
                "FROM server_signature_keys WHERE 1=0"
            ) + " OR (server_name=? AND key_id=?)" * len(batch)

            txn.execute(sql, tuple(itertools.chain.from_iterable(batch)))

            for row in txn:
                server_name, key_id, key_bytes, ts_valid_until_ms = row

                if ts_valid_until_ms is None:
                    # Old keys may be stored with a ts_valid_until_ms of null,
                    # in which case we treat this as if it was set to `0`, i.e.
                    # it won't match key requests that define a minimum
                    # `ts_valid_until_ms`.
                    ts_valid_until_ms = 0

                res = FetchKeyResult(
                    verify_key=decode_verify_key_bytes(key_id, bytes(key_bytes)),
                    valid_until_ts=ts_valid_until_ms,
                )
                keys[(server_name, key_id)] = res

        def _txn(txn):
            for batch in batch_iter(server_name_and_key_ids, 50):
                _get_keys(txn, batch)
            return keys

        return self.db.runInteraction("get_server_verify_keys", _txn)

    def store_server_verify_keys(self, from_server, ts_added_ms, verify_keys):
        """Stores NACL verification keys for remote servers.
        Args:
            from_server (str): Where the verification keys were looked up
            ts_added_ms (int): The time to record that the key was added
            verify_keys (iterable[tuple[str, str, FetchKeyResult]]):
                keys to be stored. Each entry is a triplet of
                (server_name, key_id, key).
        """
        key_values = []
        value_values = []
        invalidations = []
        for server_name, key_id, fetch_result in verify_keys:
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
            # _get_server_verify_key. _get_server_verify_key only takes one
            # param, which is itself the 2-tuple (server_name, key_id).
            invalidations.append((server_name, key_id))

        def _invalidate(res):
            f = self._get_server_verify_key.invalidate
            for i in invalidations:
                f((i,))
            return res

        return self.db.runInteraction(
            "store_server_verify_keys",
            self.db.simple_upsert_many_txn,
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
        ).addCallback(_invalidate)

    def store_server_keys_json(
        self, server_name, key_id, from_server, ts_now_ms, ts_expires_ms, key_json_bytes
    ):
        """Stores the JSON bytes for a set of keys from a server
        The JSON should be signed by the originating server, the intermediate
        server, and by this server. Updates the value for the
        (server_name, key_id, from_server) triplet if one already existed.
        Args:
            server_name (str): The name of the server.
            key_id (str): The identifer of the key this JSON is for.
            from_server (str): The server this JSON was fetched from.
            ts_now_ms (int): The time now in milliseconds.
            ts_valid_until_ms (int): The time when this json stops being valid.
            key_json (bytes): The encoded JSON.
        """
        return self.db.simple_upsert(
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

    def get_server_keys_json(self, server_keys):
        """Retrive the key json for a list of server_keys and key ids.
        If no keys are found for a given server, key_id and source then
        that server, key_id, and source triplet entry will be an empty list.
        The JSON is returned as a byte array so that it can be efficiently
        used in an HTTP response.
        Args:
            server_keys (list): List of (server_name, key_id, source) triplets.
        Returns:
            Deferred[dict[Tuple[str, str, str|None], list[dict]]]:
                Dict mapping (server_name, key_id, source) triplets to lists of dicts
        """

        def _get_server_keys_json_txn(txn):
            results = {}
            for server_name, key_id, from_server in server_keys:
                keyvalues = {"server_name": server_name}
                if key_id is not None:
                    keyvalues["key_id"] = key_id
                if from_server is not None:
                    keyvalues["from_server"] = from_server
                rows = self.db.simple_select_list_txn(
                    txn,
                    "server_keys_json",
                    keyvalues=keyvalues,
                    retcols=(
                        "key_id",
                        "from_server",
                        "ts_added_ms",
                        "ts_valid_until_ms",
                        "key_json",
                    ),
                )
                results[(server_name, key_id, from_server)] = rows
            return results

        return self.db.runInteraction("get_server_keys_json", _get_server_keys_json_txn)
