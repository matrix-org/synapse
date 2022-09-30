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
from typing import List
from unittest import mock

from synapse.app.generic_worker import GenericWorkerServer
from synapse.storage.database import LoggingDatabaseConnection
from synapse.storage.prepare_database import PrepareDatabaseException, prepare_database
from synapse.storage.schema import SCHEMA_VERSION

from tests.unittest import HomeserverTestCase


def fake_listdir(filepath: str) -> List[str]:
    """
    A fake implementation of os.listdir which we can use to mock out the filesystem.

    Args:
        filepath: The directory to list files for.

    Returns:
        A list of files and folders in the directory.
    """
    if filepath.endswith("full_schemas"):
        return [str(SCHEMA_VERSION)]

    return ["99_add_unicorn_to_database.sql"]


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

        db_pool = self.hs.get_datastores().main.db_pool
        db_conn = LoggingDatabaseConnection(
            db_pool._db_pool.connect(),
            db_pool.engine,
            "tests",
        )

        cur = db_conn.cursor()
        cur.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 1,))

        db_conn.commit()

        prepare_database(db_conn, db_pool.engine, self.hs.config)

    def test_not_upgraded_old_schema_version(self):
        """Test that workers don't start if the DB has an older schema version"""
        db_pool = self.hs.get_datastores().main.db_pool
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

    def test_not_upgraded_current_schema_version_with_outstanding_deltas(self):
        """
        Test that workers don't start if the DB is on the current schema version,
        but there are still outstanding delta migrations to run.
        """
        db_pool = self.hs.get_datastores().main.db_pool
        db_conn = LoggingDatabaseConnection(
            db_pool._db_pool.connect(),
            db_pool.engine,
            "tests",
        )

        # Set the schema version of the database to the current version
        cur = db_conn.cursor()
        cur.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))

        db_conn.commit()

        # Path `os.listdir` here to make synapse think that there is a migration
        # file ready to be run.
        # Note that we can't patch this function for the whole method, else Synapse
        # will try to find the file when building the database initially.
        with mock.patch("os.listdir", mock.Mock(side_effect=fake_listdir)):
            with self.assertRaises(PrepareDatabaseException):
                # Synapse should think that there is an outstanding migration file due to
                # patching 'os.listdir' in the function decorator.
                #
                # We expect Synapse to raise an exception to indicate the master process
                # needs to apply this migration file.
                prepare_database(db_conn, db_pool.engine, self.hs.config)
