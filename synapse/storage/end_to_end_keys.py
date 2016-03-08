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

from ._base import SQLBaseStore


class EndToEndKeyStore(SQLBaseStore):
    def set_e2e_device_keys(self, user_id, device_id, time_now, json_bytes):
        return self._simple_upsert(
            table="e2e_device_keys_json",
            keyvalues={
                "user_id": user_id,
                "device_id": device_id,
            },
            values={
                "ts_added_ms": time_now,
                "key_json": json_bytes,
            }
        )

    def get_e2e_device_keys(self, query_list):
        """Fetch a list of device keys.
        Args:
            query_list(list): List of pairs of user_ids and device_ids.
        Returns:
            Dict mapping from user-id to dict mapping from device_id to
            key json byte strings.
        """
        def _get_e2e_device_keys(txn):
            result = {}
            for user_id, device_id in query_list:
                user_result = result.setdefault(user_id, {})
                keyvalues = {"user_id": user_id}
                if device_id:
                    keyvalues["device_id"] = device_id
                rows = self._simple_select_list_txn(
                    txn, table="e2e_device_keys_json",
                    keyvalues=keyvalues,
                    retcols=["device_id", "key_json"]
                )
                for row in rows:
                    user_result[row["device_id"]] = row["key_json"]
            return result
        return self.runInteraction("get_e2e_device_keys", _get_e2e_device_keys)

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
