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
from six import iteritems

from canonicaljson import encode_canonical_json

from twisted.internet import defer

from synapse.util.caches.descriptors import cached

from ._base import SQLBaseStore, db_to_json


class EndToEndKeyWorkerStore(SQLBaseStore):
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
        if not query_list:
            defer.returnValue({})

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

        defer.returnValue(results)

    def _get_e2e_device_keys_txn(
        self, txn, query_list, include_all_devices=False, include_deleted_devices=False
    ):
        query_clauses = []
        query_params = []

        if include_all_devices is False:
            include_deleted_devices = False

        if include_deleted_devices:
            deleted_devices = set(query_list)

        for (user_id, device_id) in query_list:
            query_clause = "user_id = ?"
            query_params.append(user_id)

            if device_id is not None:
                query_clause += " AND device_id = ?"
                query_params.append(device_id)

            query_clauses.append(query_clause)

        sql = (
            "SELECT user_id, device_id, "
            "    d.display_name AS device_display_name, "
            "    k.key_json"
            " FROM devices d"
            "    %s JOIN e2e_device_keys_json k USING (user_id, device_id)"
            " WHERE %s"
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

        defer.returnValue(
            {(row["algorithm"], row["key_id"]): row["key_json"] for row in rows}
        )

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
                return False

            self._simple_upsert_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={"user_id": user_id, "device_id": device_id},
                values={"ts_added_ms": time_now, "key_json": new_key_json},
            )

            return True

        return self.runInteraction("set_e2e_device_keys", _set_e2e_device_keys_txn)

    def claim_e2e_one_time_keys(self, query_list):
        """Take a list of one time keys out of the database"""

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
                txn.execute(sql, (user_id, device_id, algorithm, key_id))
                self._invalidate_cache_and_stream(
                    txn, self.count_e2e_one_time_keys, (user_id, device_id)
                )
            return result

        return self.runInteraction("claim_e2e_one_time_keys", _claim_e2e_one_time_keys)

    def delete_e2e_keys_by_device(self, user_id, device_id):
        def delete_e2e_keys_by_device_txn(txn):
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
