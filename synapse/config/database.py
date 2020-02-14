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
import os

from ._base import Config


class DatabaseConfig(Config):
    def read_config(self, config, **kwargs):
        self.event_cache_size = self.parse_size(config.get("event_cache_size", "10K"))

        self.database_config = config.get("database")

        if self.database_config is None:
            self.database_config = {"name": "sqlite3", "args": {}}

        name = self.database_config.get("name", None)
        if name == "psycopg2":
            pass
        elif name == "sqlite3":
            self.database_config.setdefault("args", {}).update(
                {"cp_min": 1, "cp_max": 1, "check_same_thread": False}
            )
        else:
            raise RuntimeError("Unsupported database type '%s'" % (name,))

        self.set_databasepath(config.get("database_path"))

    def generate_config_section(self, data_dir_path, **kwargs):
        database_path = os.path.join(data_dir_path, "homeserver.db")
        return (
            """\
        ## Database ##

        database:
          # The database engine name
          name: "sqlite3"
          # Arguments to pass to the engine
          args:
            # Path to the database
            database: "%(database_path)s"

        # Number of events to cache in memory.
        #
        #event_cache_size: 10K
        """
            % locals()
        )

    def read_arguments(self, args):
        self.set_databasepath(args.database_path)

    def set_databasepath(self, database_path):
        if database_path != ":memory:":
            database_path = self.abspath(database_path)
        if self.database_config.get("name", None) == "sqlite3":
            if database_path is not None:
                self.database_config["args"]["database"] = database_path

    def add_arguments(self, parser):
        db_group = parser.add_argument_group("database")
        db_group.add_argument(
            "-d",
            "--database-path",
            metavar="SQLITE_DATABASE_PATH",
            help="The path to a sqlite database to use.",
        )
