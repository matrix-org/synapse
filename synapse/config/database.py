# -*- coding: utf-8 -*-
# Copyright 2014-2016 OpenMarket Ltd
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
import logging
import os
from textwrap import indent

import yaml

from twisted.enterprise import adbapi

from synapse.config._base import Config, ConfigError
from synapse.storage.engines import create_engine

logger = logging.getLogger(__name__)


class DatabaseConfig(Config):
    section = "database"

    def read_config(self, config, **kwargs):
        self.event_cache_size = self.parse_size(config.get("event_cache_size", "10K"))

        database_config = config.get("database")

        if database_config is None:
            database_config = {"name": "sqlite3", "args": {}}

        name = database_config.get("name", None)
        if name == "psycopg2":
            pass
        elif name == "sqlite3":
            database_config.setdefault("args", {}).update(
                {"cp_min": 1, "cp_max": 1, "check_same_thread": False}
            )
        else:
            raise RuntimeError("Unsupported database type '%s'" % (name,))

        # A map from database name to database config.
        self.databases = {"master": DatabaseConnectionConfig(database_config)}

        # A map from data store name to database the data store should use.
        self.data_stores = {"main": "master", "state": "master"}

        self.set_databasepath(config.get("database_path"))

    def generate_config_section(self, data_dir_path, database_conf, **kwargs):
        if not database_conf:
            database_path = os.path.join(data_dir_path, "homeserver.db")
            database_conf = (
                """# The database engine name
          name: "sqlite3"
          # Arguments to pass to the engine
          args:
            # Path to the database
            database: "%(database_path)s"
            """
                % locals()
            )
        else:
            database_conf = indent(yaml.dump(database_conf), " " * 10).lstrip()

        return (
            """\
        ## Database ##

        database:
          %(database_conf)s
        # Number of events to cache in memory.
        #
        #event_cache_size: 10K
        """
            % locals()
        )

    def read_arguments(self, args):
        self.set_databasepath(args.database_path)

    def set_databasepath(self, database_path):
        if database_path is None:
            return

        if database_path != ":memory:":
            database_path = self.abspath(database_path)

        # We only support setting a database path if we have a single sqlite3
        # database.
        if len(self.databases) != 1:
            raise ConfigError("Cannot specify 'database_path' with multiple databases")

        database = self.get_single_database()
        if database.config["name"] != "sqlite3":
            # We don't raise here as we haven't done so before for this case.
            logger.warn("Ignoring 'database_path' for non-sqlite3 database")
            return

        database.config["args"]["database"] = database_path

    @staticmethod
    def add_arguments(parser):
        db_group = parser.add_argument_group("database")
        db_group.add_argument(
            "-d",
            "--database-path",
            metavar="SQLITE_DATABASE_PATH",
            help="The path to a sqlite database to use.",
        )

    def get_single_database(self):
        """Returns the database if there is only one, useful for e.g. tests
        """
        if len(self.databases) != 1:
            raise Exception("More than one database exists")

        return self.databases[list(self.databases)[0]]


class DatabaseConnectionConfig(object):
    """Contains the connection config for a particular database.
    """

    def __init__(self, db_config):
        if db_config["name"] not in ("sqlite3", "psycopg2"):
            raise ConfigError("Unsupported database type %r" % (db_config["name"],))

        if db_config["name"] == "sqlite3":
            db_config.setdefault("args", {}).update(
                {"cp_min": 1, "cp_max": 1, "check_same_thread": False}
            )

        self.config = db_config
        self.engine = create_engine(db_config)
        self.config["args"]["cp_openfun"] = self.engine.on_new_connection

        self._pool = None

    def get_pool(self, reactor) -> adbapi.ConnectionPool:
        """Get the connection pool for the database.
        """

        if self._pool is None:
            self._pool = adbapi.ConnectionPool(
                self.config["name"], cp_reactor=reactor, **self.config.get("args", {})
            )

        return self._pool

    def make_conn(self):
        """Make a new connection to the database and return it.

        Returns:
            Connection
        """

        db_params = {
            k: v
            for k, v in self.config.get("args", {}).items()
            if not k.startswith("cp_")
        }
        db_conn = self.engine.module.connect(**db_params)
        return db_conn

    def is_running(self):
        """Is the database pool currently running
        """
        return self._pool is not None and self._pool.running
