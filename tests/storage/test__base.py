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
from typing import Generator, Tuple

from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.util import Clock

from tests import unittest


class UpdateUpsertManyTests(unittest.HomeserverTestCase):
    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.storage = hs.get_datastores().main

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

    def _dump_table_to_tuple(self) -> Generator[Tuple[int, str, str], None, None]:
        res = self.get_success(
            self.storage.db_pool.simple_select_list(
                self.table_name, None, ["id, username, value"]
            )
        )

        for i in res:
            yield (i["id"], i["username"], i["value"])

    def test_upsert_many(self) -> None:
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
        self.assertEqual(
            set(self._dump_table_to_tuple()),
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
        self.assertEqual(
            set(self._dump_table_to_tuple()),
            {(1, "user1", "hello"), (2, "user2", "bleb")},
        )

    def test_simple_update_many(self):
        """
        simple_update_many performs many updates at once.
        """
        # First add some data.
        self.get_success(
            self.storage.db_pool.simple_insert_many(
                table=self.table_name,
                keys=("id", "username", "value"),
                values=[(1, "alice", "A"), (2, "bob", "B"), (3, "charlie", "C")],
                desc="insert",
            )
        )

        # Check the data made it to the table
        self.assertEqual(
            set(self._dump_table_to_tuple()),
            {(1, "alice", "A"), (2, "bob", "B"), (3, "charlie", "C")},
        )

        # Now use simple_update_many
        self.get_success(
            self.storage.db_pool.simple_update_many(
                table=self.table_name,
                key_names=("username",),
                key_values=(
                    ("alice",),
                    ("bob",),
                    ("stranger",),
                ),
                value_names=("value",),
                value_values=(
                    ("aaa!",),
                    ("bbb!",),
                    ("???",),
                ),
                desc="update_many1",
            )
        )

        # Check the table is how we expect:
        # charlie has been left alone
        self.assertEqual(
            set(self._dump_table_to_tuple()),
            {(1, "alice", "aaa!"), (2, "bob", "bbb!"), (3, "charlie", "C")},
        )
