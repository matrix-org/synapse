# -*- coding: utf-8 -*-
# Copyright 2014 matrix.org
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

from ._base import Config
import os

class DatabaseConfig(Config):
    def __init__(self, args):
        self.db_path = os.path.abspath(args.database_path)

    @classmethod
    def add_arguments(cls, parser):
        super(DatabaseConfig, cls).add_arguments(parser)
        db_group = parser.add_argument_group("database")
        db_group.add_argument(
            "-d", "--database", dest="database_path", default="homeserver.db",
            help="The database name."
        )

    @classmethod
    def generate_config(cls, args, config_dir_path):
        super(DatabaseConfig, cls).generate_config(args, config_dir_path)
        args.database_path = os.path.abspath(args.database_path)

