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
from twisted.internet import defer

from canonicaljson import encode_canonical_json
import ujson as json

from ._base import SQLBaseStore


class EndToEndKeyStore(SQLBaseStore):
    def set_e2e_device_keys(self, user_id, device_id, time_now, device_keys):
        """Stores device keys for a device. Returns whether there was a change
        or the keys were already in the database.
        """
        def _set_e2e_device_keys_txn(txn):
            old_key_json = self._simple_select_one_onecol_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                },
                retcol="key_json",
                allow_none=True,
            )

            new_key_json = encode_canonical_json(device_keys)
            if old_key_json == new_key_json:
                return False

            self._simple_upsert_txn(
                txn,
                table="e2e_device_keys_json",
                keyvalues={
                    "user_id": user_id,
                    "device_id": device_id,
                },
                values={
                    "ts_added_ms": time_now,
                    "key_json": new_key_json,
                }
            )

            return True

        return self.runInteraction(
            "set_e2e_device_keys", _set_e2e_device_keys_txn
        )

    @defer.inlineCallbacks
    def get_e2e_device_keys(self, query_list, include_all_devices=False):
        """Fetch a list of device keys.
        Args:
            query_list(list): List of pairs of user_ids and device_ids.
            include_all_devices (bool): whether to include entries for devices
                that don't have device keys
        Returns:
            Dict mapping from user-id to dict mapping from device_id to
            dict containing "key_json", "device_display_name".
        """
        if not query_list:
            defer.returnValue({})

        results = yield self.runInteraction(
            "get_e2e_device_keys", self._get_e2e_device_keys_txn,
            query_list, include_all_devices,
        )

        for user_id, device_keys in results.iteritems():
            for device_id, device_info in device_keys.iteritems():
                device_info["keys"] = json.loads(device_info.pop("key_json"))

        defer.returnValue(results)

    def _get_e2e_device_keys_txn(self, txn, query_list, include_all_devices):
        query_clauses = []
        query_params = []

        for (user_id, device_id) in query_list:
            query_clause = "user_id = ?"
            query_params.append(user_id)

            if device_id:
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
            " OR ".join("(" + q + ")" for q in query_clauses)
        )

        txn.execute(sql, query_params)
        rows = self.cursor_to_dict(txn)

        result = {}
        for row in rows:
            result.setdefault(row["user_id"], {})[row["device_id"]] = row

        return result

    def add_e2e_one_time_keys(self, user_id, device_id, time_now, key_list):
        def _add_e2e_one_time_keys(txn):
            for (algorithm, key_id, json_bytes) in key_list:
                self._simple_upsert_txn(
                    txn, table="e2e_one_time_keys_json",
                    keyvalues={
                        "user_id": user_id,
                        "device_id": device_id,
                        "algorithm": algorithm,
                        "key_id": key_id,
                    },
                    values={
                        "ts_added_ms": time_now,
                        "key_json": json_bytes,
                    }
                )
        return self.runInteraction(
            "add_e2e_one_time_keys", _add_e2e_one_time_keys
        )

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
            for algorithm, key_count in txn.fetchall():
                result[algorithm] = key_count
            return result
        return self.runInteraction(
            "count_e2e_one_time_keys", _count_e2e_one_time_keys
        )

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
                for key_id, key_json in txn.fetchall():
                    device_result[algorithm + ":" + key_id] = key_json
                    delete.append((user_id, device_id, algorithm, key_id))
            sql = (
                "DELETE FROM e2e_one_time_keys_json"
                " WHERE user_id = ? AND device_id = ? AND algorithm = ?"
                " AND key_id = ?"
            )
            for user_id, device_id, algorithm, key_id in delete:
                txn.execute(sql, (user_id, device_id, algorithm, key_id))
            return result
        return self.runInteraction(
            "claim_e2e_one_time_keys", _claim_e2e_one_time_keys
        )

    @defer.inlineCallbacks
    def delete_e2e_keys_by_device(self, user_id, device_id):
        yield self._simple_delete(
            table="e2e_device_keys_json",
            keyvalues={"user_id": user_id, "device_id": device_id},
            desc="delete_e2e_device_keys_by_device"
        )
        yield self._simple_delete(
            table="e2e_one_time_keys_json",
            keyvalues={"user_id": user_id, "device_id": device_id},
            desc="delete_e2e_one_time_keys_by_device"
        )
