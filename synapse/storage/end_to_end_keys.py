# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
# Copyright 2019 The Matrix.org Foundation C.I.C.
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
from six import iteritems

from canonicaljson import encode_canonical_json, json

from twisted.internet import defer

from synapse.logging.opentracing import log_kv, set_tag, trace
from synapse.util.caches.descriptors import cached

from ._base import SQLBaseStore, db_to_json


class EndToEndKeyWorkerStore(SQLBaseStore):
    @trace
    @defer.inlineCallbacks
    def get_e2e_device_keys(
        self, query_list, include_all_devices=False, include_deleted_devices=False
    ):
        """Fetch a list of device keys.
        Args:
            query_list(list): List of pairs of user_ids and device_ids.
            include_all_devices (bool): whether to include entries for devices
                that don't have device keys
            include_deleted_devices (bool): whether to include null entries for
                devices which no longer exist (but were in the query_list).
                This option only takes effect if include_all_devices is true.
        Returns:
            Dict mapping from user-id to dict mapping from device_id to
            dict containing "key_json", "device_display_name".
        """
        set_tag("query_list", query_list)
        if not query_list:
            return {}

        results = yield self.runInteraction(
            "get_e2e_device_keys",
            self._get_e2e_device_keys_txn,
            query_list,
            include_all_devices,
            include_deleted_devices,
        )

        for user_id, device_keys in iteritems(results):
            for device_id, device_info in iteritems(device_keys):
                device_info["keys"] = db_to_json(device_info.pop("key_json"))
                # add cross-signing signatures to the keys
                if "signatures" in device_info:
                    for sig_user_id, sigs in device_info["signatures"].items():
                        device_info["keys"].setdefault("signatures", {}).setdefault(
                            sig_user_id, {}
                        ).update(sigs)

        return results

    @trace
    def _get_e2e_device_keys_txn(
        self, txn, query_list, include_all_devices=False, include_deleted_devices=False
    ):
        set_tag("include_all_devices", include_all_devices)
        set_tag("include_deleted_devices", include_deleted_devices)

        query_clauses = []
        query_params = []
        signature_query_clauses = []
        signature_query_params = []

        if include_all_devices is False:
            include_deleted_devices = False

        if include_deleted_devices:
            deleted_devices = set(query_list)

        for (user_id, device_id) in query_list:
            query_clause = "user_id = ?"
            query_params.append(user_id)
            signature_query_clause = "target_user_id = ?"
            signature_query_params.append(user_id)

            if device_id is not None:
                query_clause += " AND device_id = ?"
                query_params.append(device_id)
                signature_query_clause += " AND target_device_id = ?"
                signature_query_params.append(device_id)

            signature_query_clause += " AND user_id = ?"
            signature_query_params.append(user_id)

            query_clauses.append(query_clause)
            signature_query_clauses.append(signature_query_clause)

        sql = (
            "SELECT user_id, device_id, "
            "    d.display_name AS device_display_name, "
            "    k.key_json"
            " FROM devices d"
            "    %s JOIN e2e_device_keys_json k USING (user_id, device_id)"
            " WHERE %s AND NOT d.hidden"
        ) % (
            "LEFT" if include_all_devices else "INNER",
            " OR ".join("(" + q + ")" for q in query_clauses),
        )

        txn.execute(sql, query_params)
        rows = self.cursor_to_dict(txn)

        result = {}
        for row in rows:
            if include_deleted_devices:
                deleted_devices.remove((row["user_id"], row["device_id"]))
            result.setdefault(row["user_id"], {})[row["device_id"]] = row

        if include_deleted_devices:
            for user_id, device_id in deleted_devices:
                result.setdefault(user_id, {})[device_id] = None

        # get signatures on the device
        signature_sql = (
            "SELECT * " "  FROM e2e_cross_signing_signatures " " WHERE %s"
        ) % (" OR ".join("(" + q + ")" for q in signature_query_clauses))

        txn.execute(signature_sql, signature_query_params)
        rows = self.cursor_to_dict(txn)

        for row in rows:
            target_user_id = row["target_user_id"]
            target_device_id = row["target_device_id"]
            if target_user_id in result and target_device_id in result[target_user_id]:
                result[target_user_id][target_device_id].setdefault(
                    "signatures", {}
                ).setdefault(row["user_id"], {})[row["key_id"]] = row["signature"]

        log_kv(result)
        return result

    @defer.inlineCallbacks
    def get_e2e_one_time_keys(self, user_id, device_id, key_ids):
        """Retrieve a number of one-time keys for a user

        Args:
            user_id(str): id of user to get keys for
            device_id(str): id of device to get keys for
            key_ids(list[str]): list of key ids (excluding algorithm) to
                retrieve

        Returns:
            deferred resolving to Dict[(str, str), str]: map from (algorithm,
            key_id) to json string for key
        """

        rows = yield self._simple_select_many_batch(
            table="e2e_one_time_keys_json",
            column="key_id",
            iterable=key_ids,
            retcols=("algorithm", "key_id", "key_json"),
            keyvalues={"user_id": user_id, "device_id": device_id},
            desc="add_e2e_one_time_keys_check",
        )
        result = {(row["algorithm"], row["key_id"]): row["key_json"] for row in rows}
        log_kv({"message": "Fetched one time keys for user", "one_time_keys": result})
        return result

    @defer.inlineCallbacks
    def add_e2e_one_time_keys(self, user_id, device_id, time_now, new_keys):
        """Insert some new one time keys for a device. Errors if any of the
        keys already exist.

        Args:
            user_id(str): id of user to get keys for
            device_id(str): id of device to get keys for
            time_now(long): insertion time to record (ms since epoch)
            new_keys(iterable[(str, str, str)]: keys to add - each a tuple of
                (algorithm, key_id, key json)
        """

        def _add_e2e_one_time_keys(txn):
            set_tag("user_id", user_id)
            set_tag("device_id", device_id)
            set_tag("new_keys", new_keys)
            # We are protected from race between lookup and insertion due to
            # a unique constraint. If there is a race of two calls to
            # `add_e2e_one_time_keys` then they'll conflict and we will only
            # insert one set.
            self._simple_insert_many_txn(
                txn,
                table="e2e_one_time_keys_json",
                values=[
                    {
                        "user_id": user_id,
                        "device_id": device_id,
                        "algorithm": algorithm,
                        "key_id": key_id,
                        "ts_added_ms": time_now,
                        "key_json": json_bytes,
                    }
                    for algorithm, key_id, json_bytes in new_keys
                ],
            )
            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )

        yield self.runInteraction(
            "add_e2e_one_time_keys_insert", _add_e2e_one_time_keys
        )

    @cached(max_entries=10000)
    def count_e2e_one_time_keys(self, user_id, device_id):
        """ Count the number of one time keys the server has for a device
        Returns:
            Dict mapping from algorithm to number of keys for that algorithm.
        """

        def _count_e2e_one_time_keys(txn):
            sql = (
                "SELECT algorithm, COUNT(key_id) FROM e2e_one_time_keys_json"
                " WHERE user_id = ? AND device_id = ?"
                " GROUP BY algorithm"
            )
            txn.execute(sql, (user_id, device_id))
            result = {}
            for algorithm, key_count in txn:
                result[algorithm] = key_count
            return result

        return self.runInteraction("count_e2e_one_time_keys", _count_e2e_one_time_keys)


class EndToEndKeyStore(EndToEndKeyWorkerStore, SQLBaseStore):
    def set_e2e_device_keys(self, user_id, device_id, time_now, device_keys):
        """Stores device keys for a device. Returns whether there was a change
        or the keys were already in the database.
        """

        def _set_e2e_device_keys_txn(txn):
            set_tag("user_id", user_id)
            set_tag("device_id", device_id)
            set_tag("time_now", time_now)
            set_tag("device_keys", device_keys)

            old_key_json = self._simple_select_one_onecol_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
                retcol="key_json",
                allow_none=True,
            )

            # In py3 we need old_key_json to match new_key_json type. The DB
            # returns unicode while encode_canonical_json returns bytes.
            new_key_json = encode_canonical_json(device_keys).decode("utf-8")

            if old_key_json == new_key_json:
                log_kv({"Message": "Device key already stored."})
                return False

            self._simple_upsert_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
                values={"ts_added_ms": time_now, "key_json": new_key_json},
            )
            log_kv({"message": "Device keys stored."})
            return True

        return self.runInteraction("set_e2e_device_keys", _set_e2e_device_keys_txn)

    def claim_e2e_one_time_keys(self, query_list):
        """Take a list of one time keys out of the database"""

        @trace
        def _claim_e2e_one_time_keys(txn):
            sql = (
                "SELECT key_id, key_json FROM e2e_one_time_keys_json"
                " WHERE user_id = ? AND device_id = ? AND algorithm = ?"
                " LIMIT 1"
            )
            result = {}
            delete = []
            for user_id, device_id, algorithm in query_list:
                user_result = result.setdefault(user_id, {})
                device_result = user_result.setdefault(device_id, {})
                txn.execute(sql, (user_id, device_id, algorithm))
                for key_id, key_json in txn:
                    device_result[algorithm + ":" + key_id] = key_json
                    delete.append((user_id, device_id, algorithm, key_id))
            sql = (
                "DELETE FROM e2e_one_time_keys_json"
                " WHERE user_id = ? AND device_id = ? AND algorithm = ?"
                " AND key_id = ?"
            )
            for user_id, device_id, algorithm, key_id in delete:
                log_kv(
                    {
                        "message": "Executing claim e2e_one_time_keys transaction on database."
                    }
                )
                txn.execute(sql, (user_id, device_id, algorithm, key_id))
                log_kv({"message": "finished executing and invalidating cache"})
                self._invalidate_cache_and_stream(
                    txn, self.count_e2e_one_time_keys, (user_id, device_id)
                )
            return result

        return self.runInteraction("claim_e2e_one_time_keys", _claim_e2e_one_time_keys)

    def delete_e2e_keys_by_device(self, user_id, device_id):
        def delete_e2e_keys_by_device_txn(txn):
            log_kv(
                {
                    "message": "Deleting keys for device",
                    "device_id": device_id,
                    "user_id": user_id,
                }
            )
            self._simple_delete_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self._simple_delete_txn(
                txn,
                table="e2e_one_time_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
            )
            self._invalidate_cache_and_stream(
                txn, self.count_e2e_one_time_keys, (user_id, device_id)
            )

        return self.runInteraction(
            "delete_e2e_keys_by_device", delete_e2e_keys_by_device_txn
        )

    def _set_e2e_cross_signing_key_txn(self, txn, user_id, key_type, key):
        """Set a user's cross-signing key.

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            user_id (str): the user to set the signing key for
            key_type (str): the type of key that is being set: either 'master'
                for a master key, 'self_signing' for a self-signing key, or
                'user_signing' for a user-signing key
            key (dict): the key data
        """
        # the cross-signing keys need to occupy the same namespace as devices,
        # since signatures are identified by device ID.  So add an entry to the
        # device table to make sure that we don't have a collision with device
        # IDs

        # the 'key' dict will look something like:
        # {
        #   "user_id": "@alice:example.com",
        #   "usage": ["self_signing"],
        #   "keys": {
        #     "ed25519:base64+self+signing+public+key": "base64+self+signing+public+key",
        #   },
        #   "signatures": {
        #     "@alice:example.com": {
        #       "ed25519:base64+master+public+key": "base64+signature"
        #     }
        #   }
        # }
        # The "keys" property must only have one entry, which will be the public
        # key, so we just grab the first value in there
        pubkey = next(iter(key["keys"].values()))
        self._simple_insert(
            "devices",
            values={
                "user_id": user_id,
                "device_id": pubkey,
                "display_name": key_type + " signing key",
                "hidden": True,
            },
            desc="store_master_key_device",
        )

        # and finally, store the key itself
        with self._cross_signing_id_gen.get_next() as stream_id:
            self._simple_insert(
                "e2e_cross_signing_keys",
                values={
                    "user_id": user_id,
                    "keytype": key_type,
                    "keydata": json.dumps(key),
                    "stream_id": stream_id,
                },
                desc="store_master_key",
            )

    def set_e2e_cross_signing_key(self, user_id, key_type, key):
        """Set a user's cross-signing key.

        Args:
            user_id (str): the user to set the user-signing key for
            key_type (str): the type of cross-signing key to set
            key (dict): the key data
        """
        return self.runInteraction(
            "add_e2e_cross_signing_key",
            self._set_e2e_cross_signing_key_txn,
            user_id,
            key_type,
            key,
        )

    def _get_e2e_cross_signing_key_txn(self, txn, user_id, key_type, from_user_id=None):
        """Returns a user's cross-signing key.

        Args:
            txn (twisted.enterprise.adbapi.Connection): db connection
            user_id (str): the user whose key is being requested
            key_type (str): the type of key that is being set: either 'master'
                for a master key, 'self_signing' for a self-signing key, or
                'user_signing' for a user-signing key
            from_user_id (str): if specified, signatures made by this user on
                the key will be included in the result

        Returns:
            dict of the key data or None if not found
        """
        sql = (
            "SELECT keydata "
            "  FROM e2e_cross_signing_keys "
            " WHERE user_id = ? AND keytype = ? ORDER BY stream_id DESC LIMIT 1"
        )
        txn.execute(sql, (user_id, key_type))
        row = txn.fetchone()
        if not row:
            return None
        key = json.loads(row[0])

        device_id = None
        for k in key["keys"].values():
            device_id = k

        if from_user_id is not None:
            sql = (
                "SELECT key_id, signature "
                "  FROM e2e_cross_signing_signatures "
                " WHERE user_id = ? "
                "   AND target_user_id = ? "
                "   AND target_device_id = ? "
            )
            txn.execute(sql, (from_user_id, user_id, device_id))
            row = txn.fetchone()
            if row:
                key.setdefault("signatures", {}).setdefault(from_user_id, {})[
                    row[0]
                ] = row[1]

        return key

    def get_e2e_cross_signing_key(self, user_id, key_type, from_user_id=None):
        """Returns a user's cross-signing key.

        Args:
            user_id (str): the user whose self-signing key is being requested
            key_type (str): the type of cross-signing key to get
            from_user_id (str): if specified, signatures made by this user on
                the self-signing key will be included in the result

        Returns:
            dict of the key data or None if not found
        """
        return self.runInteraction(
            "get_e2e_cross_signing_key",
            self._get_e2e_cross_signing_key_txn,
            user_id,
            key_type,
            from_user_id,
        )

    def store_e2e_cross_signing_signatures(self, user_id, signatures):
        """Stores cross-signing signatures.

        Args:
            user_id (str): the user who made the signatures
            signatures (iterable[(str, str, str, str)]): signatures to add - each
                a tuple of (key_id, target_user_id, target_device_id, signature),
                where key_id is the ID of the key (including the signature
                algorithm) that made the signature, target_user_id and
                target_device_id indicate the device being signed, and signature
                is the signature of the device
        """
        return self._simple_insert_many(
            "e2e_cross_signing_signatures",
            [
                {
                    "user_id": user_id,
                    "key_id": key_id,
                    "target_user_id": target_user_id,
                    "target_device_id": target_device_id,
                    "signature": signature,
                }
                for (key_id, target_user_id, target_device_id, signature) in signatures
            ],
            "add_e2e_signing_key",
        )
