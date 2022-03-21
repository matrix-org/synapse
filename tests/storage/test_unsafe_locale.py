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
from unittest.mock import patch

from synapse.storage.database import make_conn
from synapse.storage.engines._base import IncorrectDatabaseSetup
from synapse.storage.engines.postgres import PostgresEngine

from tests.unittest import HomeserverTestCase


class UnsafeLocaleTest(HomeserverTestCase):
    @patch("synapse.storage.engines.postgres.PostgresEngine.get_db_locale")
    def test_unsafe_locale(self, mock_db_locale):
        mock_db_locale.return_value = ("B", "B")
        database = self.hs.get_datastores().databases[0]

        # Only run this on postgres databases
        if isinstance(database.engine, PostgresEngine):
            db_conn = make_conn(
                database._database_config, database.engine, "test_unsafe"
            )
            with self.assertRaises(IncorrectDatabaseSetup):
                database.engine.check_database(db_conn)
            with self.assertRaises(IncorrectDatabaseSetup):
                database.engine.check_new_database(db_conn)
            db_conn.close()
