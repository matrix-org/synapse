# Copyright 2021 The Matrix.org Foundation C.I.C.
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
from synapse.app.generic_worker import GenericWorkerServer
from synapse.storage.database import LoggingDatabaseConnection
from synapse.storage.prepare_database import PrepareDatabaseException, prepare_database
from synapse.storage.schema import SCHEMA_VERSION

from tests.unittest import HomeserverTestCase


class WorkerSchemaTests(HomeserverTestCase):
    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver(
            federation_http_client=None, homeserver_to_use=GenericWorkerServer
        )
        return hs

    def default_config(self):
        conf = super().default_config()

        # Mark this as a worker app.
        conf["worker_app"] = "yes"

        return conf

    def test_rolling_back(self):
        """Test that workers can start if the DB is a newer schema version"""

        db_pool = self.hs.get_datastore().db_pool
        db_conn = LoggingDatabaseConnection(
            db_pool._db_pool.connect(),
            db_pool.engine,
            "tests",
        )

        cur = db_conn.cursor()
        cur.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))

        db_conn.commit()

        prepare_database(db_conn, db_pool.engine, self.hs.config)

    def test_not_upgraded(self):
        """Test that workers don't start if the DB has an older schema version"""
        db_pool = self.hs.get_datastore().db_pool
        db_conn = LoggingDatabaseConnection(
            db_pool._db_pool.connect(),
            db_pool.engine,
            "tests",
        )

        cur = db_conn.cursor()
        cur.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION - 1,))

        db_conn.commit()

        with self.assertRaises(PrepareDatabaseException):
            prepare_database(db_conn, db_pool.engine, self.hs.config)
