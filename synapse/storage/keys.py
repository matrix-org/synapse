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

import six

from signedjson.key import decode_verify_key_bytes

from synapse.util import batch_iter
from synapse.util.caches.descriptors import cached, cachedList

from ._base import SQLBaseStore

logger = logging.getLogger(__name__)

# py2 sqlite has buffer hardcoded as only binary type, so we must use it,
# despite being deprecated and removed in favor of memoryview
if six.PY2:
    db_binary_type = six.moves.builtins.buffer
else:
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
            Deferred: resolves to dict[Tuple[str, str], VerifyKey|None]:
                map from (server_name, key_id) -> VerifyKey, or None if the key is
                unknown
        """
        keys = {}

        def _get_keys(txn, batch):
            """Processes a batch of keys to fetch, and adds the result to `keys`."""

            # batch_iter always returns tuples so it's safe to do len(batch)
            sql = (
                "SELECT server_name, key_id, verify_key FROM server_signature_keys "
                "WHERE 1=0"
            ) + " OR (server_name=? AND key_id=?)" * len(batch)

            txn.execute(sql, tuple(itertools.chain.from_iterable(batch)))

            for row in txn:
                server_name, key_id, key_bytes = row
                keys[(server_name, key_id)] = decode_verify_key_bytes(
                    key_id, bytes(key_bytes)
                )

        def _txn(txn):
            for batch in batch_iter(server_name_and_key_ids, 50):
                _get_keys(txn, batch)
            return keys

        return self.runInteraction("get_server_verify_keys", _txn)

    def store_server_verify_key(
        self, server_name, from_server, time_now_ms, verify_key
    ):
        """Stores a NACL verification key for the given server.
        Args:
            server_name (str): The name of the server.
            from_server (str): Where the verification key was looked up
            time_now_ms (int): The time now in milliseconds
            verify_key (nacl.signing.VerifyKey): The NACL verify key.
        """
        key_id = "%s:%s" % (verify_key.alg, verify_key.version)

        # XXX fix this to not need a lock (#3819)
        def _txn(txn):
            self._simple_upsert_txn(
                txn,
                table="server_signature_keys",
                keyvalues={"server_name": server_name, "key_id": key_id},
                values={
                    "from_server": from_server,
                    "ts_added_ms": time_now_ms,
                    "verify_key": db_binary_type(verify_key.encode()),
                },
            )
            # invalidate takes a tuple corresponding to the params of
            # _get_server_verify_key. _get_server_verify_key only takes one
            # param, which is itself the 2-tuple (server_name, key_id).
            txn.call_after(
                self._get_server_verify_key.invalidate, ((server_name, key_id),)
            )

        return self.runInteraction("store_server_verify_key", _txn)

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
        return self._simple_upsert(
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
                rows = self._simple_select_list_txn(
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

        return self.runInteraction("get_server_keys_json", _get_server_keys_json_txn)
