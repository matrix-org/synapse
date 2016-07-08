# -*- coding: utf-8 -*-
# Copyright 2015, 2016 OpenMarket Ltd
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

from ._base import IncorrectDatabaseSetup
from .postgres import PostgresEngine
from .sqlite3 import Sqlite3Engine

import importlib


SUPPORTED_MODULE = {
    "sqlite3": Sqlite3Engine,
    "psycopg2": PostgresEngine,
}


def create_engine(database_config):
    name = database_config["name"]
    engine_class = SUPPORTED_MODULE.get(name, None)

    if engine_class:
        module = importlib.import_module(name)
        return engine_class(module, database_config)

    raise RuntimeError(
        "Unsupported database engine '%s'" % (name,)
    )


__all__ = ["create_engine", "IncorrectDatabaseSetup"]
