# Copyright 2015, 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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

import secrets

from tests import unittest


class UpsertManyTests(unittest.HomeserverTestCase):
    def prepare(self, reactor, clock, hs):
        self.storage = hs.get_datastore()

        self.table_name = "table_" + secrets.token_hex(6)
        self.get_success(
            self.storage.db_pool.runInteraction(
                "create",
                lambda x, *a: x.execute(*a),
                "CREATE TABLE %s (id INTEGER, username TEXT, value TEXT)"
                % (self.table_name,),
            )
        )
        self.get_success(
            self.storage.db_pool.runInteraction(
                "index",
                lambda x, *a: x.execute(*a),
                "CREATE UNIQUE INDEX %sindex ON %s(id, username)"
                % (self.table_name, self.table_name),
            )
        )

    def _dump_to_tuple(self, res):
        for i in res:
            yield (i["id"], i["username"], i["value"])

    def test_upsert_many(self):
        """
        Upsert_many will perform the upsert operation across a batch of data.
        """
        # Add some data to an empty table
        key_names = ["id", "username"]
        value_names = ["value"]
        key_values = [[1, "user1"], [2, "user2"]]
        value_values = [["hello"], ["there"]]

        self.get_success(
            self.storage.db_pool.runInteraction(
                "test",
                self.storage.db_pool.simple_upsert_many_txn,
                self.table_name,
                key_names,
                key_values,
                value_names,
                value_values,
            )
        )

        # Check results are what we expect
        res = self.get_success(
            self.storage.db_pool.simple_select_list(
                self.table_name, None, ["id, username, value"]
            )
        )
        self.assertEqual(
            set(self._dump_to_tuple(res)),
            {(1, "user1", "hello"), (2, "user2", "there")},
        )

        # Update only user2
        key_values = [[2, "user2"]]
        value_values = [["bleb"]]

        self.get_success(
            self.storage.db_pool.runInteraction(
                "test",
                self.storage.db_pool.simple_upsert_many_txn,
                self.table_name,
                key_names,
                key_values,
                value_names,
                value_values,
            )
        )

        # Check results are what we expect
        res = self.get_success(
            self.storage.db_pool.simple_select_list(
                self.table_name, None, ["id, username, value"]
            )
        )
        self.assertEqual(
            set(self._dump_to_tuple(res)),
            {(1, "user1", "hello"), (2, "user2", "bleb")},
        )
