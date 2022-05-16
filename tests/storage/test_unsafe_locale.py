# Copyright 2022 The Matrix.org Foundation C.I.C.
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
from unittest.mock import MagicMock, patch

from synapse.storage.database import make_conn
from synapse.storage.engines._base import IncorrectDatabaseSetup

from tests.unittest import HomeserverTestCase
from tests.utils import USE_POSTGRES_FOR_TESTS


class UnsafeLocaleTest(HomeserverTestCase):
    if not USE_POSTGRES_FOR_TESTS:
        skip = "Requires Postgres"

    @patch("synapse.storage.engines.postgres.PostgresEngine.get_db_locale")
    def test_unsafe_locale(self, mock_db_locale: MagicMock) -> None:
        mock_db_locale.return_value = ("B", "B")
        database = self.hs.get_datastores().databases[0]

        db_conn = make_conn(database._database_config, database.engine, "test_unsafe")
        with self.assertRaises(IncorrectDatabaseSetup):
            database.engine.check_database(db_conn)
        with self.assertRaises(IncorrectDatabaseSetup):
            database.engine.check_new_database(db_conn)
        db_conn.close()

    def test_safe_locale(self) -> None:
        database = self.hs.get_datastores().databases[0]

        db_conn = make_conn(database._database_config, database.engine, "test_unsafe")
        with db_conn.cursor() as txn:
            res = database.engine.get_db_locale(txn)
        self.assertEqual(res, ("C", "C"))
        db_conn.close()
