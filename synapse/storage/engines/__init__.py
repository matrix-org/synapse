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
from typing import Any, Mapping, NoReturn

from ._base import BaseDatabaseEngine, IncorrectDatabaseSetup

# The classes `PostgresEngine` and `Sqlite3Engine` must always be importable, because
# we use `isinstance(engine, PostgresEngine)` to write different queries for postgres
# and sqlite. But the database driver modules are both optional: they may not be
# installed. To account for this, create dummy classes on import failure so we can
# still run `isinstance()` checks.
try:
    from .postgres import PostgresEngine
except ImportError:

    class PostgresEngine(BaseDatabaseEngine):  # type: ignore[no-redef]
        def __new__(cls, *args: object, **kwargs: object) -> NoReturn:  # type: ignore[misc]
            raise RuntimeError(
                f"Cannot create {cls.__name__} -- psycopg2 module is not installed"
            )


try:
    from .sqlite import Sqlite3Engine
except ImportError:

    class Sqlite3Engine(BaseDatabaseEngine):  # type: ignore[no-redef]
        def __new__(cls, *args: object, **kwargs: object) -> NoReturn:  # type: ignore[misc]
            raise RuntimeError(
                f"Cannot create {cls.__name__} -- sqlite3 module is not installed"
            )


def create_engine(database_config: Mapping[str, Any]) -> BaseDatabaseEngine:
    name = database_config["name"]

    if name == "sqlite3":
        return Sqlite3Engine(database_config)

    if name == "psycopg2":
        return PostgresEngine(database_config)

    raise RuntimeError("Unsupported database engine '%s'" % (name,))


__all__ = [
    "create_engine",
    "BaseDatabaseEngine",
    "PostgresEngine",
    "Sqlite3Engine",
    "IncorrectDatabaseSetup",
]
