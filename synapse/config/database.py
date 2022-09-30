# Copyright 2014-2016 OpenMarket Ltd
# Copyright 2020-2021 The Matrix.org Foundation C.I.C.
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
import argparse
import logging
import os
from typing import Any, List

from synapse.config._base import Config, ConfigError
from synapse.types import JsonDict

logger = logging.getLogger(__name__)

NON_SQLITE_DATABASE_PATH_WARNING = """\
Ignoring 'database_path' setting: not using a sqlite3 database.
--------------------------------------------------------------------------------
"""

DEFAULT_CONFIG = """\
database:
  name: sqlite3
  args:
    database: %(database_path)s
"""


class DatabaseConnectionConfig:
    """Contains the connection config for a particular database.

    Args:
        name: A label for the database, used for logging.
        db_config: The config for a particular database, as per `database`
            section of main config. Has three fields: `name` for database
            module name, `args` for the args to give to the database
            connector, and optional `data_stores` that is a list of stores to
            provision on this database (defaulting to all).
    """

    def __init__(self, name: str, db_config: dict):
        db_engine = db_config.get("name", "sqlite3")

        if db_engine not in ("sqlite3", "psycopg2"):
            raise ConfigError("Unsupported database type %r" % (db_engine,))

        if db_engine == "sqlite3":
            db_config.setdefault("args", {}).update(
                {"cp_min": 1, "cp_max": 1, "check_same_thread": False}
            )

        data_stores = db_config.get("data_stores")
        if data_stores is None:
            data_stores = ["main", "state"]

        self.name = name
        self.config = db_config

        # The `data_stores` config is actually talking about `databases` (we
        # changed the name).
        self.databases = data_stores


class DatabaseConfig(Config):
    section = "database"

    def __init__(self, *args: Any):
        super().__init__(*args)

        self.databases: List[DatabaseConnectionConfig] = []

    def read_config(self, config: JsonDict, **kwargs: Any) -> None:
        # We *experimentally* support specifying multiple databases via the
        # `databases` key. This is a map from a label to database config in the
        # same format as the `database` config option, plus an extra
        # `data_stores` key to specify which data store goes where. For example:
        #
        #   databases:
        #       master:
        #           name: psycopg2
        #           data_stores: ["main"]
        #           args: {}
        #       state:
        #           name: psycopg2
        #           data_stores: ["state"]
        #           args: {}

        multi_database_config = config.get("databases")
        database_config = config.get("database")
        database_path = config.get("database_path")

        if multi_database_config and database_config:
            raise ConfigError("Can't specify both 'database' and 'databases' in config")

        if multi_database_config:
            if database_path:
                raise ConfigError("Can't specify 'database_path' with 'databases'")

            self.databases = [
                DatabaseConnectionConfig(name, db_conf)
                for name, db_conf in multi_database_config.items()
            ]

        if database_config:
            self.databases = [DatabaseConnectionConfig("master", database_config)]

        if database_path:
            if self.databases and self.databases[0].name != "sqlite3":
                logger.warning(NON_SQLITE_DATABASE_PATH_WARNING)
                return

            database_config = {"name": "sqlite3", "args": {}}
            self.databases = [DatabaseConnectionConfig("master", database_config)]
            self.set_databasepath(database_path)

    def generate_config_section(self, data_dir_path: str, **kwargs: Any) -> str:
        return DEFAULT_CONFIG % {
            "database_path": os.path.join(data_dir_path, "homeserver.db")
        }

    def read_arguments(self, args: argparse.Namespace) -> None:
        """
        Cases for the cli input:
          - If no databases are configured and no database_path is set, raise.
          - No databases and only database_path available ==> sqlite3 db.
          - If there are multiple databases and a database_path raise an error.
          - If the database set in the config file is sqlite then
            overwrite with the command line argument.
        """

        if args.database_path is None:
            if not self.databases:
                raise ConfigError("No database config provided")
            return

        if len(self.databases) == 0:
            database_config = {"name": "sqlite3", "args": {}}
            self.databases = [DatabaseConnectionConfig("master", database_config)]
            self.set_databasepath(args.database_path)
            return

        if self.get_single_database().name == "sqlite3":
            self.set_databasepath(args.database_path)
        else:
            logger.warning(NON_SQLITE_DATABASE_PATH_WARNING)

    def set_databasepath(self, database_path: str) -> None:

        if database_path != ":memory:":
            database_path = self.abspath(database_path)

        self.databases[0].config["args"]["database"] = database_path

    @staticmethod
    def add_arguments(parser: argparse.ArgumentParser) -> None:
        db_group = parser.add_argument_group("database")
        db_group.add_argument(
            "-d",
            "--database-path",
            metavar="SQLITE_DATABASE_PATH",
            help="The path to a sqlite database to use.",
        )

    def get_single_database(self) -> DatabaseConnectionConfig:
        """Returns the database if there is only one, useful for e.g. tests"""
        if not self.databases:
            raise Exception("More than one database exists")

        return self.databases[0]
