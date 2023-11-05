# Copyright 2023 The Matrix.org Foundation C.I.C
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


from twisted.test.proto_helpers import MemoryReactor

from synapse.server import HomeServer
from synapse.storage.database import LoggingTransaction
from synapse.storage.engines import PostgresEngine
from synapse.util import Clock

from tests import unittest


class UserFiltersStoreTestCase(unittest.HomeserverTestCase):
    """
    Test background migration that copies entries from column user_id to full_user_id, adding
    the hostname in the process.
    """

    def prepare(self, reactor: MemoryReactor, clock: Clock, hs: HomeServer) -> None:
        self.store = hs.get_datastores().main

    def test_bg_migration(self) -> None:
        updater = self.hs.get_datastores().main.db_pool.updates

        # drop the constraint so we can insert nulls in full_user_id to populate the test
        if isinstance(self.store.database_engine, PostgresEngine):

            def f(txn: LoggingTransaction) -> None:
                txn.execute(
                    "ALTER TABLE user_filters DROP CONSTRAINT full_user_id_not_null"
                )

            self.get_success(self.store.db_pool.runInteraction("", f))

        for i in range(70):
            self.get_success(
                self.store.db_pool.simple_insert(
                    "user_filters",
                    {
                        "user_id": f"hello{i:02}",
                        "filter_id": i,
                        "filter_json": bytearray(i),
                    },
                )
            )

        # re-add the constraint so that when it's validated it actually exists
        if isinstance(self.store.database_engine, PostgresEngine):

            def f(txn: LoggingTransaction) -> None:
                txn.execute(
                    "ALTER TABLE user_filters ADD CONSTRAINT full_user_id_not_null CHECK (full_user_id IS NOT NULL) NOT VALID"
                )

            self.get_success(self.store.db_pool.runInteraction("", f))

        self.get_success(
            self.store.db_pool.simple_insert(
                "background_updates",
                values={
                    "update_name": "populate_full_user_id_user_filters",
                    "progress_json": "{}",
                },
            )
        )

        self.get_success(
            updater.run_background_updates(False),
        )

        expected_values = []
        for i in range(70):
            expected_values.append((f"@hello{i:02}:{self.hs.hostname}",))

        res = self.get_success(
            self.store.db_pool.execute(
                "", "SELECT full_user_id from user_filters ORDER BY full_user_id"
            )
        )
        self.assertEqual(len(res), len(expected_values))
        self.assertEqual(res, expected_values)
